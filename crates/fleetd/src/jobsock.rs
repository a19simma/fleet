//! The per-job unix socket of ADR-0036.
//!
//! fleetd binds one socket per Job. A client sends one handshake line that selects a
//! [`ServiceName`]. The service gets a [`JobContext`] and the stream, and never reads the
//! job id from the client. Before it reads a byte, the listener checks the cgroup of the
//! peer: its whole path must equal `<agent slice>/fleet-agent@<job id>.service` for the
//! listener's own id. A mismatch or an unreadable cgroup closes the connection with no
//! reply and bumps [`JobSocket::rejected`]. After the handshake line the listener reads the
//! peer pid and cgroup again and requires both to equal the first reading.
//!
//! The peer pid comes from `SO_PEERCRED`. `SO_PEERPIDFD` is not reachable here: neither tokio
//! nor rustix exposes it and the workspace forbids `unsafe`, so a pid recycled between accept
//! and a cgroup read is not detected. The second reading only shrinks that window. The
//! per-Job mount namespace of ADR-0036 would cover the residual gap, but its mount shape
//! (`BindPaths` after `TemporaryFileSystem`) is UNVERIFIED on a Box, so no claim rests on it.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

/// Most bytes in one frame, newline excluded. Server and client code share this constant.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Most bytes in the handshake line, newline excluded.
pub const MAX_HANDSHAKE_BYTES: usize = 32;
/// Most concurrent connections per Job.
pub const MAX_CONNECTIONS: usize = 8;
/// How long a client may take to send the handshake line.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// File name of the socket inside the Run dir.
pub const SOCKET_NAME: &str = "job.sock";
/// The cgroup path, below the root, of the slice that holds the Agent units.
///
/// `fleet-agent@.service` sets no `Slice=`, so systemd places an instance in
/// `system-fleet\x2dagent.slice` under `system.slice`.
pub const AGENT_SLICE: &str = "system.slice/system-fleet\\x2dagent.slice";
/// Longest accepted Job id, as in the polkit rule.
pub const MAX_JOB_ID_BYTES: usize = 64;
const SOCKET_MODE: u32 = 0o660;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(1);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Whether `job_id` is one safe path component: `[A-Za-z0-9_-]` and at most
/// [`MAX_JOB_ID_BYTES`] bytes.
#[must_use]
pub fn valid_job_id(job_id: &str) -> bool {
    !job_id.is_empty()
        && job_id.len() <= MAX_JOB_ID_BYTES
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// The path of the Job socket inside `<run_dir>/<job id>/`, or `None` when `job_id` is not a
/// valid id (see [`valid_job_id`]).
#[must_use]
pub fn socket_path(run_dir: &Path, job_id: &str) -> Option<PathBuf> {
    valid_job_id(job_id).then(|| run_dir.join(job_id).join(SOCKET_NAME))
}

/// A service a handshake line can select.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceName {
    /// The credential broker (ADR-0037).
    Broker,
    /// The fetch tool.
    Fetch,
    /// The egress proxy (ADR-0031 P2).
    EgressProxy,
}

impl ServiceName {
    /// The handshake word of the service.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Broker => "broker",
            Self::Fetch => "fetch",
            Self::EgressProxy => "egress proxy",
        }
    }

    /// Parses a handshake line. An unknown name yields `None`.
    #[must_use]
    pub fn parse(line: &[u8]) -> Option<Self> {
        [Self::Broker, Self::Fetch, Self::EgressProxy]
            .into_iter()
            .find(|name| name.as_str().as_bytes() == line)
    }
}

/// A cancel signal a service watches. It fires on Job cancel, lease loss and socket shutdown.
#[derive(Clone, Debug)]
pub struct CancelToken(watch::Receiver<bool>);

impl CancelToken {
    /// Whether the signal has fired.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow() || self.0.has_changed().is_err()
    }

    /// Resolves once the signal fires.
    pub async fn cancelled(&self) {
        let mut rx = self.0.clone();
        let _ = rx.wait_for(|fired| *fired).await;
    }
}

/// What a service knows about the Job. The id comes from the listener, never from the client.
#[derive(Clone, Debug)]
pub struct JobContext {
    /// The Job id the socket belongs to.
    pub job_id: String,
    /// The cancel signal of the Job.
    pub cancel: CancelToken,
}

/// A future that serves one connection.
pub type ServeFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// A service behind the Job socket.
pub trait Service: Send + Sync {
    /// Serves one connection. The future is dropped when the Job is cancelled.
    fn serve(&self, ctx: JobContext, stream: UnixStream) -> ServeFuture<'_>;
}

/// The services a socket offers, by handshake name.
pub type Services = HashMap<ServiceName, Arc<dyn Service>>;

/// Why [`PerJob::register`] refused a Job id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// The id is not a valid Job id (see [`valid_job_id`]).
    InvalidId,
    /// A service is already registered under the id.
    Duplicate,
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "invalid job id",
            Self::Duplicate => "job id already registered",
        })
    }
}

impl std::error::Error for RegisterError {}

/// A registry of one service instance per Job, keyed by [`JobContext::job_id`].
///
/// The listener of a Job socket sets `job_id`, so a connection reaches only the service
/// registered for its own Job. Clones share one map: the runner keeps a clone to
/// [`register`](Self::register) before it launches the Agent unit and to
/// [`unregister`](Self::unregister) on every end path.
///
/// An id with no service closes the connection with no reply, the same as an unknown
/// handshake name. Unregistering takes effect on the next connection. A connection already
/// served keeps its service until it finishes or the socket cancels it through
/// [`JobContext::cancel`].
///
/// The lock guards single map operations and is never held across an await. A panic that
/// poisons it leaves the map whole, so every method recovers the guard.
#[derive(Debug)]
pub struct PerJob<S> {
    jobs: Arc<std::sync::Mutex<HashMap<String, Arc<S>>>>,
}

impl<S> Clone for PerJob<S> {
    fn clone(&self) -> Self {
        Self {
            jobs: Arc::clone(&self.jobs),
        }
    }
}

impl<S> Default for PerJob<S> {
    fn default() -> Self {
        Self {
            jobs: Arc::default(),
        }
    }
}

impl<S> PerJob<S> {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<S>>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers `service` for `job_id`.
    ///
    /// A second registration of a live id is an error and leaves the first service in place,
    /// so a double registration surfaces instead of swapping a service under a Job.
    ///
    /// # Errors
    ///
    /// Fails with [`RegisterError::InvalidId`] when `job_id` is not a valid Job id, and with
    /// [`RegisterError::Duplicate`] when a service is registered for it.
    pub fn register(&self, job_id: &str, service: Arc<S>) -> Result<(), RegisterError> {
        if !valid_job_id(job_id) {
            return Err(RegisterError::InvalidId);
        }
        match self.map().entry(job_id.to_owned()) {
            std::collections::hash_map::Entry::Occupied(_) => Err(RegisterError::Duplicate),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(service);
                Ok(())
            }
        }
    }

    /// Removes the service of `job_id` and reports whether one was registered.
    ///
    /// Safe to call on every end path of a Job, more than once.
    pub fn unregister(&self, job_id: &str) -> bool {
        self.map().remove(job_id).is_some()
    }

    /// Whether a service is registered for `job_id`.
    #[must_use]
    pub fn contains(&self, job_id: &str) -> bool {
        self.map().contains_key(job_id)
    }

    /// How many Jobs are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map().len()
    }

    /// Whether no Job is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map().is_empty()
    }
}

impl<S: Service + 'static> Service for PerJob<S> {
    fn serve(&self, ctx: JobContext, stream: UnixStream) -> ServeFuture<'_> {
        let service = self.map().get(&ctx.job_id).cloned();
        Box::pin(async move {
            match service {
                Some(service) => service.serve(ctx, stream).await,
                None => drop(stream),
            }
        })
    }
}

/// What a reading of a connected peer yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerId {
    /// The pid of the peer.
    pub pid: i32,
    /// The contents of the peer's `/proc/<pid>/cgroup`.
    pub cgroup: String,
}

/// How the identity of a connected peer is read. A test substitutes a fake.
pub trait Peer: Send + Sync {
    /// Reads the peer pid and its cgroup file.
    ///
    /// # Errors
    ///
    /// Fails when the peer pid or its cgroup cannot be read.
    fn identity(&self, stream: &UnixStream) -> io::Result<PeerId>;
}

/// The production [`Peer`]: the `SO_PEERCRED` pid and `/proc/<pid>/cgroup`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcPeer;

impl Peer for ProcPeer {
    fn identity(&self, stream: &UnixStream) -> io::Result<PeerId> {
        let pid = stream
            .peer_cred()?
            .pid()
            .ok_or_else(|| io::Error::other("peer pid unavailable"))?;
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        Ok(PeerId { pid, cgroup })
    }
}

/// Whether `cgroup` is the cgroup file of the Agent unit of `job_id` under `slice`.
///
/// The one line must be `0::/<slice>/fleet-agent@<job id>.service` in full, bar one trailing
/// newline. Another id, another parent, a nested cgroup below the unit, a v1 listing and
/// extra lines all fail.
#[must_use]
pub fn cgroup_unit(cgroup: &str, slice: &str, job_id: &str) -> bool {
    valid_job_id(job_id)
        && cgroup.strip_suffix('\n').unwrap_or(cgroup)
            == format!("0::/{slice}/fleet-agent@{job_id}.service")
}

/// Tunable limits of a [`JobSocket`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Most concurrent connections.
    pub max_connections: usize,
    /// How long a client may take to send the handshake line.
    pub handshake_timeout: Duration,
    /// The cgroup path of the slice the Agent unit must sit in.
    pub agent_slice: &'static str,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            agent_slice: AGENT_SLICE,
        }
    }
}

struct Shared {
    job_id: String,
    services: Services,
    peer: Arc<dyn Peer>,
    permits: Arc<Semaphore>,
    rejected: Arc<AtomicU64>,
    cancel: CancelToken,
    handshake_timeout: Duration,
    agent_slice: &'static str,
}

/// A bound Job socket and its accept loop.
///
/// Dropping it stops the loop, cancels every service and unlinks the socket.
#[derive(Debug)]
pub struct JobSocket {
    path: PathBuf,
    identity: (u64, u64),
    cancel: watch::Sender<bool>,
    rejected: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl JobSocket {
    /// Binds `path` with mode 0660 and starts serving.
    ///
    /// The socket is bound inside a private 0700 staging dir beside `path`, set to 0660 and
    /// renamed onto `path`, so it is never reachable under a wider mode. A stale socket at
    /// `path` is replaced. Anything else there, a symlink included, is refused untouched.
    ///
    /// # Errors
    ///
    /// Fails with `AlreadyExists` when `path` holds something other than a socket, and when
    /// the staging dir, the bind, the mode change or the rename fails.
    pub fn bind(
        path: &Path,
        job_id: &str,
        services: Services,
        peer: Arc<dyn Peer>,
        limits: Limits,
    ) -> io::Result<Self> {
        let (listener, identity) = publish(path)?;
        let (cancel, rx) = watch::channel(false);
        let rejected = Arc::new(AtomicU64::new(0));
        let shared = Arc::new(Shared {
            job_id: job_id.to_owned(),
            services,
            peer,
            permits: Arc::new(Semaphore::new(limits.max_connections)),
            rejected: Arc::clone(&rejected),
            cancel: CancelToken(rx),
            handshake_timeout: limits.handshake_timeout,
            agent_slice: limits.agent_slice,
        });
        let task = tokio::spawn(accept_loop(listener, shared));
        Ok(Self {
            path: path.to_path_buf(),
            identity,
            cancel,
            rejected,
            task,
        })
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many connections failed the identity check.
    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Fires the cancel signal, so every service stops mid-request.
    pub fn cancel(&self) {
        self.cancel.send_replace(true);
    }
}

impl Drop for JobSocket {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        self.task.abort();
        let ours = std::fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.identity
        });
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn publish(path: &Path) -> io::Result<(UnixListener, (u64, u64))> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path holds something other than a socket",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let stage = parent.join(format!(
        ".js{}-{}",
        std::process::id(),
        STAGE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&stage)?;
    let staged = stage.join(SOCKET_NAME);
    let result = bind_staged(&staged, path);
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_dir(&stage);
    result
}

fn bind_staged(staged: &Path, path: &Path) -> io::Result<(UnixListener, (u64, u64))> {
    let listener = UnixListener::bind(staged)?;
    std::fs::set_permissions(staged, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    let meta = std::fs::symlink_metadata(staged)?;
    std::fs::rename(staged, path)?;
    Ok((listener, (meta.dev(), meta.ino())))
}

async fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&shared.permits).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            handle(&shared, stream).await;
            drop(permit);
        });
    }
}

async fn handle(shared: &Shared, stream: UnixStream) {
    tokio::select! {
        () = serve_peer(shared, stream) => {}
        () = shared.cancel.cancelled() => {}
    }
}

fn reject(shared: &Shared) {
    if shared.rejected.fetch_add(1, Ordering::Relaxed) == 0 {
        tracing::warn!("job socket peer rejected; later rejections log at debug");
    } else {
        tracing::debug!("job socket peer rejected");
    }
}

fn verified(shared: &Shared, stream: &UnixStream) -> Option<PeerId> {
    let id = shared
        .peer
        .identity(stream)
        .ok()
        .filter(|id| cgroup_unit(&id.cgroup, shared.agent_slice, &shared.job_id));
    if id.is_none() {
        reject(shared);
    }
    id
}

async fn serve_peer(shared: &Shared, mut stream: UnixStream) {
    let Some(first) = verified(shared, &stream) else {
        return;
    };
    let Ok(Ok(line)) =
        tokio::time::timeout(shared.handshake_timeout, read_handshake(&mut stream)).await
    else {
        return;
    };
    match verified(shared, &stream) {
        Some(second) if second == first => {}
        Some(_) => {
            reject(shared);
            return;
        }
        None => return,
    }
    let Some(service) = ServiceName::parse(&line).and_then(|name| shared.services.get(&name))
    else {
        return;
    };
    let ctx = JobContext {
        job_id: shared.job_id.clone(),
        cancel: shared.cancel.clone(),
    };
    service.serve(ctx, stream).await;
}

async fn read_handshake(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        match stream.read_u8().await? {
            b'\n' => return Ok(line),
            byte if line.len() < MAX_HANDSHAKE_BYTES => line.push(byte),
            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
}

/// Reads one newline-terminated frame of at most [`MAX_FRAME_BYTES`], newline stripped.
///
/// # Errors
///
/// Fails with `InvalidData` when the frame is longer than the cap, with `UnexpectedEof` when
/// the stream ends before a newline, or with the read error.
pub async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    (&mut *reader)
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_until(b'\n', &mut frame)
        .await?;
    if frame.pop_if(|byte| *byte == b'\n').is_some() {
        Ok(frame)
    } else if frame.len() > MAX_FRAME_BYTES {
        Err(io::Error::from(io::ErrorKind::InvalidData))
    } else {
        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
    }
}

/// Writes one frame and its newline.
///
/// # Errors
///
/// Fails with `InvalidData` when `frame` is over the cap or holds a newline, else with the
/// write error.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    if frame.len() > MAX_FRAME_BYTES || frame.contains(&b'\n') {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut line = Vec::with_capacity(frame.len() + 1);
    line.extend_from_slice(frame);
    line.push(b'\n');
    writer.write_all(&line).await
}

struct SocketFacts {
    owner: u32,
    parent_owner: u32,
    parent_mode: u32,
}

fn socket_acceptable(path: &Path, facts: &SocketFacts, uid: u32) -> bool {
    path.is_absolute()
        && facts.owner == uid
        && (facts.parent_owner == 0 || facts.parent_owner == uid)
        && facts.parent_mode & 0o022 == 0
}

fn socket_usable(path: &Path, uid: u32) -> bool {
    let facts = std::fs::metadata(path).ok().and_then(|socket| {
        let parent = std::fs::metadata(path.parent()?).ok()?;
        Some(SocketFacts {
            owner: socket.uid(),
            parent_owner: parent.uid(),
            parent_mode: parent.mode(),
        })
    });
    facts.is_some_and(|facts| socket_acceptable(path, &facts, uid))
}

/// Connects to a Job socket and selects `service`.
///
/// Applies the hook client's trust checks: the path is absolute, the socket belongs to
/// `trusted_uid`, its parent belongs to root or `trusted_uid` and has no group or other write
/// bit, and the listening peer runs as `trusted_uid`. Nothing is sent before they pass.
///
/// # Errors
///
/// Fails with `PermissionDenied` when a check fails, with `TimedOut` after one second, or
/// with the connect or write error.
pub async fn connect(
    path: &Path,
    service: ServiceName,
    trusted_uid: u32,
) -> io::Result<UnixStream> {
    connect_with(path, service, trusted_uid, |stream| {
        stream.peer_cred().map(|cred| cred.uid())
    })
    .await
}

async fn connect_with(
    path: &Path,
    service: ServiceName,
    trusted_uid: u32,
    peer_uid: fn(&UnixStream) -> io::Result<u32>,
) -> io::Result<UnixStream> {
    let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
    if !socket_usable(path, trusted_uid) {
        return Err(denied());
    }
    let attempt = async {
        let mut stream = UnixStream::connect(path).await?;
        if !peer_uid(&stream).is_ok_and(|uid| uid == trusted_uid) {
            return Err(denied());
        }
        write_frame(&mut stream, service.as_str().as_bytes()).await?;
        Ok(stream)
    };
    tokio::time::timeout(CLIENT_TIMEOUT, attempt)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::sync::mpsc;

    use super::{
        AGENT_SLICE, JobContext, JobSocket, Limits, MAX_FRAME_BYTES, Peer, PeerId, PerJob,
        RegisterError, ServeFuture, Service, ServiceName, Services, SocketFacts, cgroup_unit,
        connect, connect_with, read_frame, socket_acceptable, socket_path, write_frame,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const WAIT: Duration = Duration::from_secs(5);

    fn cgroup_of(id: &str) -> String {
        format!("0::/{AGENT_SLICE}/fleet-agent@{id}.service\n")
    }

    struct FakePeer {
        readings: Vec<(i32, Result<String, std::io::ErrorKind>)>,
        next: std::sync::atomic::AtomicUsize,
    }

    impl FakePeer {
        fn steady(reading: std::io::Result<String>) -> Self {
            Self::seq(vec![(7, reading.map_err(|err| err.kind()))])
        }

        fn seq(readings: Vec<(i32, Result<String, std::io::ErrorKind>)>) -> Self {
            Self {
                readings,
                next: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl Peer for FakePeer {
        fn identity(&self, _: &UnixStream) -> std::io::Result<PeerId> {
            let at = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (pid, cgroup) = &self.readings[at.min(self.readings.len() - 1)];
            match cgroup {
                Ok(text) => Ok(PeerId {
                    pid: *pid,
                    cgroup: text.clone(),
                }),
                Err(kind) => Err(std::io::Error::new(*kind, "fake")),
            }
        }
    }

    struct Echo(mpsc::UnboundedSender<(String, bool)>);

    impl Service for Echo {
        fn serve(&self, ctx: JobContext, mut stream: UnixStream) -> ServeFuture<'_> {
            Box::pin(async move {
                let _ = self.0.send((ctx.job_id.clone(), ctx.cancel.is_cancelled()));
                let mut buf = [0u8; 4];
                if stream.read_exact(&mut buf).await.is_ok() {
                    let _ = stream.write_all(&buf).await;
                }
            })
        }
    }

    struct Hang(mpsc::UnboundedSender<()>);

    impl Service for Hang {
        fn serve(&self, _: JobContext, _stream: UnixStream) -> ServeFuture<'_> {
            Box::pin(async move {
                let _ = self.0.send(());
                std::future::pending::<()>().await;
            })
        }
    }

    fn services(name: ServiceName, service: impl Service + 'static) -> Services {
        let mut map = Services::new();
        map.insert(name, Arc::new(service));
        map
    }

    fn start(
        dir: &TempDir,
        peer: std::io::Result<String>,
        services: Services,
        limits: Limits,
    ) -> Result<JobSocket, Box<dyn std::error::Error>> {
        Ok(JobSocket::bind(
            &dir.path().join("s"),
            "job1",
            services,
            Arc::new(FakePeer::steady(peer)),
            limits,
        )?)
    }

    fn closed_without_reply(read: std::io::Result<usize>) -> std::io::Result<()> {
        match read {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn assert_closed_silently(stream: &mut UnixStream) -> TestResult {
        let mut seen = Vec::new();
        let read = tokio::time::timeout(WAIT, stream.read_to_end(&mut seen)).await?;
        closed_without_reply(read)?;
        assert_eq!(seen, [0u8; 0]);
        Ok(())
    }

    #[test]
    fn a_reset_or_an_eof_both_count_as_closed_without_a_reply() {
        let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        assert!(closed_without_reply(Err(reset)).is_ok());
        assert!(closed_without_reply(Ok(0)).is_ok());
        let other = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        assert!(closed_without_reply(Err(other)).is_err());
    }

    #[test]
    fn cgroup_unit_accepts_only_the_listeners_own_unit_at_the_exact_path() {
        let ok = |cgroup: &str, id: &str| cgroup_unit(cgroup, AGENT_SLICE, id);
        assert!(ok(&cgroup_of("job1"), "job1"));
        assert!(ok(cgroup_of("job1").trim_end(), "job1"));
        assert!(ok(&cgroup_of("job_1-x"), "job_1-x"));
        assert!(!ok(&cgroup_of("job2"), "job1"));
        assert!(!ok(&cgroup_of("job10"), "job1"));
        assert!(!ok(&cgroup_of("xjob1"), "job1"));
        assert!(!ok(&cgroup_of("job1"), ""));
        assert!(!ok(&cgroup_of("a/../job1"), "a/../job1"));
    }

    #[test]
    fn cgroup_unit_requires_the_whole_path() {
        let ok = |cgroup: &str| cgroup_unit(cgroup, AGENT_SLICE, "job1");
        assert!(!ok(
            "0::/user.slice/user-1000.slice/fleet-agent@job1.service\n"
        ));
        assert!(!ok("0::/fleet-agent@job1.service\n"));
        assert!(!ok(&format!(
            "0::/extra/{AGENT_SLICE}/fleet-agent@job1.service\n"
        )));
        assert!(!ok(&format!(
            "0::/{AGENT_SLICE}/sub/fleet-agent@job1.service\n"
        )));
        assert!(!ok(&format!(
            "0::/{AGENT_SLICE}/fleet-agent@job1.service/sub\n"
        )));
        assert!(cgroup_unit(
            "0::/other.slice/fleet-agent@job1.service",
            "other.slice",
            "job1"
        ));
    }

    #[test]
    fn cgroup_unit_refuses_other_shapes() {
        let ok = |cgroup: &str| cgroup_unit(cgroup, AGENT_SLICE, "job1");
        let exact = cgroup_of("job1");
        assert!(!ok(""));
        assert!(!ok(&exact[3..]));
        assert!(!ok(&format!(
            "1:name=systemd:/{AGENT_SLICE}/fleet-agent@job1.service"
        )));
        assert!(!ok(&format!("{}.scope", exact.trim_end())));
        assert!(!ok(&format!("{exact}{exact}")));
        assert!(!ok(&format!("{}\nx", exact.trim_end())));
        assert!(!ok(&format!("{exact}\n")));
    }

    #[test]
    fn handshake_names_parse_exactly() {
        for name in [
            ServiceName::Broker,
            ServiceName::Fetch,
            ServiceName::EgressProxy,
        ] {
            assert_eq!(ServiceName::parse(name.as_str().as_bytes()), Some(name));
        }
        assert_eq!(ServiceName::parse(b"egress proxy "), None);
        assert_eq!(ServiceName::parse(b"Broker"), None);
        assert_eq!(ServiceName::parse(b""), None);
    }

    #[test]
    fn socket_path_sits_in_the_job_run_dir() {
        assert_eq!(
            socket_path(Path::new("/run/fleet"), "j"),
            Some(Path::new("/run/fleet/j/job.sock").to_path_buf())
        );
        assert!(socket_path(Path::new("/run/fleet"), "a-b_C9").is_some());
        assert!(socket_path(Path::new("/run/fleet"), &"a".repeat(64)).is_some());
    }

    #[test]
    fn socket_path_rejects_ids_that_are_not_one_safe_component() {
        let run = Path::new("/run/fleet");
        for id in [
            "", "..", ".", "../x", "/abs", "a/b", "a.b", "a b", "a\n", "é",
        ] {
            assert_eq!(socket_path(run, id), None, "{id:?}");
        }
        assert_eq!(socket_path(run, &"a".repeat(65)), None);
    }

    #[tokio::test]
    async fn the_socket_is_group_writable_and_a_handshake_reaches_the_service() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Fetch, Echo(tx)),
            Limits::default(),
        )?;
        assert_eq!(
            std::fs::metadata(sock.path())?.permissions().mode() & 0o777,
            0o660
        );
        let mut client = UnixStream::connect(sock.path()).await?;
        write_frame(&mut client, b"fetch").await?;
        client.write_all(b"ping").await?;
        let mut back = [0u8; 4];
        tokio::time::timeout(WAIT, client.read_exact(&mut back)).await??;
        assert_eq!(&back, b"ping");
        assert_eq!(rx.recv().await, Some(("job1".to_owned(), false)));
        assert_eq!(sock.rejected(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_or_unregistered_service_closes_with_no_reply() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Fetch, Echo(tx)),
            Limits::default(),
        )?;
        for word in [&b"nonsense"[..], b"broker"] {
            let mut client = UnixStream::connect(sock.path()).await?;
            write_frame(&mut client, word).await?;
            assert_closed_silently(&mut client).await?;
        }
        assert!(rx.try_recv().is_err());
        assert_eq!(sock.rejected(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_foreign_or_unreadable_cgroup_closes_with_no_reply_and_counts() -> TestResult {
        for peer in [
            Ok(cgroup_of("job2")),
            Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        ] {
            let dir = TempDir::new()?;
            let (tx, mut rx) = mpsc::unbounded_channel();
            let sock = start(
                &dir,
                peer,
                services(ServiceName::Fetch, Echo(tx)),
                Limits::default(),
            )?;
            let mut client = UnixStream::connect(sock.path()).await?;
            let _ = write_frame(&mut client, b"fetch").await;
            assert_closed_silently(&mut client).await?;
            assert_eq!(sock.rejected(), 1);
            assert!(rx.try_recv().is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_overlong_handshake_closes_with_no_reply() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Fetch, Echo(tx)),
            Limits::default(),
        )?;
        let mut client = UnixStream::connect(sock.path()).await?;
        client.write_all(&[b'a'; 64]).await?;
        assert_closed_silently(&mut client).await?;
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn a_silent_client_is_closed_after_the_handshake_timeout() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let limits = Limits {
            handshake_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Fetch, Echo(tx)),
            limits,
        )?;
        let mut client = UnixStream::connect(sock.path()).await?;
        assert_closed_silently(&mut client).await
    }

    #[tokio::test]
    async fn connections_over_the_cap_are_closed_and_a_freed_slot_is_reused() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let limits = Limits {
            max_connections: 1,
            ..Limits::default()
        };
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Fetch, Hang(tx)),
            limits,
        )?;
        let mut first = UnixStream::connect(sock.path()).await?;
        write_frame(&mut first, b"fetch").await?;
        tokio::time::timeout(WAIT, rx.recv()).await?;
        let mut second = UnixStream::connect(sock.path()).await?;
        assert_closed_silently(&mut second).await?;
        drop(first);
        sock.cancel();
        Ok(())
    }

    #[tokio::test]
    async fn a_freed_slot_serves_the_next_client() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let limits = Limits {
            max_connections: 1,
            ..Limits::default()
        };
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Fetch, Echo(tx)),
            limits,
        )?;
        for _ in 0..2 {
            let mut client = UnixStream::connect(sock.path()).await?;
            write_frame(&mut client, b"fetch").await?;
            client.write_all(b"ping").await?;
            let mut back = [0u8; 4];
            tokio::time::timeout(WAIT, client.read_exact(&mut back)).await??;
            assert!(tokio::time::timeout(WAIT, rx.recv()).await?.is_some());
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancel_stops_a_service_mid_request() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Broker, Hang(tx)),
            Limits::default(),
        )?;
        let mut client = UnixStream::connect(sock.path()).await?;
        write_frame(&mut client, b"broker").await?;
        tokio::time::timeout(WAIT, rx.recv()).await?;
        sock.cancel();
        assert_closed_silently(&mut client).await
    }

    #[tokio::test]
    async fn dropping_the_socket_unlinks_it() -> TestResult {
        let dir = TempDir::new()?;
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            Services::new(),
            Limits::default(),
        )?;
        let path = sock.path().to_path_buf();
        assert!(path.exists());
        drop(sock);
        assert!(!path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn frames_round_trip_and_the_cap_holds() -> TestResult {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").await?;
        assert_eq!(read_frame(&mut BufReader::new(&buf[..])).await?, b"hello");

        let max = vec![b'a'; MAX_FRAME_BYTES];
        let mut ok = max.clone();
        ok.push(b'\n');
        assert_eq!(read_frame(&mut BufReader::new(&ok[..])).await?, max);

        let mut over = max.clone();
        over.extend_from_slice(b"a\n");
        let err = read_frame(&mut BufReader::new(&over[..])).await.err();
        assert_eq!(err.map(|e| e.kind()), Some(std::io::ErrorKind::InvalidData));

        let err = read_frame(&mut BufReader::new(&b"abc"[..])).await.err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );

        assert!(write_frame(&mut Vec::new(), &over).await.is_err());
        assert!(write_frame(&mut Vec::new(), b"a\nb").await.is_err());
        Ok(())
    }

    fn facts(owner: u32, parent_owner: u32, parent_mode: u32) -> SocketFacts {
        SocketFacts {
            owner,
            parent_owner,
            parent_mode,
        }
    }

    #[test]
    fn socket_trust_matches_the_hook_client() {
        let ok = |facts: &SocketFacts| socket_acceptable(Path::new("/run/fleet/j/s"), facts, 1000);
        assert!(ok(&facts(1000, 1000, 0o40750)));
        assert!(ok(&facts(1000, 0, 0o40755)));
        assert!(!socket_acceptable(
            Path::new("s"),
            &facts(1000, 1000, 0o40700),
            1000
        ));
        assert!(!ok(&facts(1001, 1000, 0o40700)));
        assert!(!ok(&facts(1000, 1001, 0o40700)));
        assert!(!ok(&facts(1000, 1000, 0o40770)));
        assert!(!ok(&facts(1000, 1000, 0o40702)));
    }

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[tokio::test]
    async fn connect_sends_the_handshake_to_a_trusted_peer() -> TestResult {
        let dir = TempDir::new()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Broker, Echo(tx)),
            Limits::default(),
        )?;
        let mut client = connect(sock.path(), ServiceName::Broker, me()).await?;
        client.write_all(b"ping").await?;
        let mut back = [0u8; 4];
        tokio::time::timeout(WAIT, client.read_exact(&mut back)).await??;
        assert_eq!(&back, b"ping");
        assert_eq!(rx.recv().await, Some(("job1".to_owned(), false)));
        Ok(())
    }

    #[tokio::test]
    async fn connect_refuses_an_untrusted_socket_or_peer_and_sends_nothing() -> TestResult {
        let dir = TempDir::new()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Broker, Echo(tx)),
            Limits::default(),
        )?;
        let wrong = me().wrapping_add(1);
        let err = connect(sock.path(), ServiceName::Broker, wrong).await.err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(std::io::ErrorKind::PermissionDenied)
        );

        let err = connect_with(sock.path(), ServiceName::Broker, me(), |_| Ok(u32::MAX))
            .await
            .err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(std::io::ErrorKind::PermissionDenied)
        );

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770))?;
        let err = connect(sock.path(), ServiceName::Broker, me()).await.err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn cancel_closes_a_connection_still_in_the_handshake() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let limits = Limits {
            handshake_timeout: Duration::from_secs(60),
            ..Limits::default()
        };
        let sock = start(
            &dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Fetch, Echo(tx)),
            limits,
        )?;
        let mut client = UnixStream::connect(sock.path()).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        sock.cancel();
        assert_closed_silently(&mut client).await
    }

    #[derive(Default)]
    struct CountingWriter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl tokio::io::AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_frame_issues_one_write() -> TestResult {
        let mut writer = CountingWriter::default();
        write_frame(&mut writer, b"hello").await?;
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.bytes, b"hello\n");
        Ok(())
    }

    fn bind_at(path: &Path) -> std::io::Result<JobSocket> {
        JobSocket::bind(
            path,
            "job1",
            Services::new(),
            Arc::new(FakePeer::steady(Ok(cgroup_of("job1")))),
            Limits::default(),
        )
    }

    #[tokio::test]
    async fn bind_replaces_a_stale_socket_left_by_a_crash() -> TestResult {
        let dir = TempDir::new()?;
        let path = dir.path().join("s");
        drop(std::os::unix::net::UnixListener::bind(&path)?);
        assert!(path.exists());
        let sock = bind_at(&path)?;
        assert_eq!(
            std::fs::metadata(sock.path())?.permissions().mode() & 0o777,
            0o660
        );
        UnixStream::connect(sock.path()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_a_regular_file_and_leaves_it() -> TestResult {
        let dir = TempDir::new()?;
        let path = dir.path().join("s");
        std::fs::write(&path, b"keep")?;
        assert!(bind_at(&path).is_err());
        assert_eq!(std::fs::read(&path)?, b"keep");
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_a_symlink_and_leaves_it_and_its_target() -> TestResult {
        let dir = TempDir::new()?;
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep")?;
        let path = dir.path().join("s");
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(bind_at(&path).is_err());
        assert!(std::fs::symlink_metadata(&path)?.file_type().is_symlink());
        assert_eq!(std::fs::read(&target)?, b"keep");
        Ok(())
    }

    #[tokio::test]
    async fn a_user_slice_cgroup_with_the_right_leaf_is_rejected() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sock = start(
            &dir,
            Ok("0::/user.slice/user-1000.slice/fleet-agent@job1.service\n".to_owned()),
            services(ServiceName::Fetch, Echo(tx)),
            Limits::default(),
        )?;
        let mut client = UnixStream::connect(sock.path()).await?;
        let _ = write_frame(&mut client, b"fetch").await;
        assert_closed_silently(&mut client).await?;
        assert_eq!(sock.rejected(), 1);
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn a_cgroup_or_pid_that_changes_after_the_handshake_is_rejected() -> TestResult {
        let moved = vec![(7, Ok(cgroup_of("job1"))), (7, Ok(cgroup_of("job2")))];
        let recycled = vec![(7, Ok(cgroup_of("job1"))), (8, Ok(cgroup_of("job1")))];
        let gone = vec![
            (7, Ok(cgroup_of("job1"))),
            (7, Err(std::io::ErrorKind::NotFound)),
        ];
        for readings in [moved, recycled, gone] {
            let dir = TempDir::new()?;
            let (tx, mut rx) = mpsc::unbounded_channel();
            let sock = JobSocket::bind(
                &dir.path().join("s"),
                "job1",
                services(ServiceName::Fetch, Echo(tx)),
                Arc::new(FakePeer::seq(readings)),
                Limits::default(),
            )?;
            let mut client = UnixStream::connect(sock.path()).await?;
            write_frame(&mut client, b"fetch").await?;
            assert_closed_silently(&mut client).await?;
            assert_eq!(sock.rejected(), 1);
            assert!(rx.try_recv().is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn every_rejection_is_counted_not_only_the_first() -> TestResult {
        let dir = TempDir::new()?;
        let sock = start(
            &dir,
            Ok(cgroup_of("job2")),
            Services::new(),
            Limits::default(),
        )?;
        for _ in 0..3 {
            let mut client = UnixStream::connect(sock.path()).await?;
            assert_closed_silently(&mut client).await?;
        }
        assert_eq!(sock.rejected(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn bind_leaves_no_staging_dir_and_drop_keeps_a_replaced_path() -> TestResult {
        let dir = TempDir::new()?;
        let path = dir.path().join("s");
        let sock = bind_at(&path)?;
        let names: Vec<_> = std::fs::read_dir(dir.path())?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        assert_eq!(names, [std::ffi::OsString::from("s")]);
        std::fs::remove_file(&path)?;
        std::fs::write(&path, b"other")?;
        drop(sock);
        assert_eq!(std::fs::read(&path)?, b"other");
        Ok(())
    }

    fn per_job_socket(
        dir: &TempDir,
        registry: &PerJob<impl Service + 'static>,
    ) -> Result<JobSocket, Box<dyn std::error::Error>> {
        start(
            dir,
            Ok(cgroup_of("job1")),
            services(ServiceName::Broker, registry.clone()),
            Limits::default(),
        )
    }

    async fn dial(sock: &JobSocket) -> std::io::Result<UnixStream> {
        let mut stream = UnixStream::connect(sock.path()).await?;
        write_frame(&mut stream, b"broker").await?;
        Ok(stream)
    }

    async fn echoes(stream: &mut UnixStream) -> TestResult {
        stream.write_all(b"ping").await?;
        let mut back = [0u8; 4];
        tokio::time::timeout(WAIT, stream.read_exact(&mut back)).await??;
        assert_eq!(&back, b"ping");
        Ok(())
    }

    #[tokio::test]
    async fn per_job_delegates_to_the_service_of_the_listeners_job() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut seen) = mpsc::unbounded_channel();
        let (other_tx, mut other_seen) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        registry.register("job1", Arc::new(Echo(tx)))?;
        registry.register("job2", Arc::new(Echo(other_tx)))?;
        let sock = per_job_socket(&dir, &registry)?;
        let mut stream = dial(&sock).await?;
        echoes(&mut stream).await?;
        assert_eq!(seen.recv().await, Some(("job1".to_owned(), false)));
        assert!(other_seen.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_job_id_closes_with_no_reply() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut seen) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        registry.register("job2", Arc::new(Echo(tx)))?;
        let sock = per_job_socket(&dir, &registry)?;
        let mut stream = dial(&sock).await?;
        assert_closed_silently(&mut stream).await?;
        assert!(seen.try_recv().is_err());
        assert_eq!(sock.rejected(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn unregister_takes_effect_on_the_next_connection_and_spares_the_open_one() -> TestResult
    {
        let dir = TempDir::new()?;
        let (tx, mut seen) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        registry.register("job1", Arc::new(Echo(tx)))?;
        let sock = per_job_socket(&dir, &registry)?;
        let mut open = dial(&sock).await?;
        assert!(tokio::time::timeout(WAIT, seen.recv()).await?.is_some());
        assert!(registry.unregister("job1"));
        echoes(&mut open).await?;
        let mut next = dial(&sock).await?;
        assert_closed_silently(&mut next).await?;
        Ok(())
    }

    #[tokio::test]
    async fn cancel_stops_an_in_flight_per_job_service() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, mut entered) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        registry.register("job1", Arc::new(Hang(tx)))?;
        let sock = per_job_socket(&dir, &registry)?;
        let mut stream = dial(&sock).await?;
        assert!(tokio::time::timeout(WAIT, entered.recv()).await?.is_some());
        registry.unregister("job1");
        sock.cancel();
        assert_closed_silently(&mut stream).await?;
        Ok(())
    }

    #[test]
    fn a_duplicate_or_invalid_id_is_refused_and_the_first_service_stays() -> TestResult {
        let (tx, _rx) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        let first = Arc::new(Echo(tx.clone()));
        registry.register("a", Arc::clone(&first))?;
        assert_eq!(
            registry.register("a", Arc::new(Echo(tx.clone()))),
            Err(RegisterError::Duplicate)
        );
        assert_eq!(Arc::strong_count(&first), 2);
        for id in ["", "a/b", "..", "a b", &"x".repeat(65)] {
            assert_eq!(
                registry.register(id, Arc::new(Echo(tx.clone()))),
                Err(RegisterError::InvalidId)
            );
        }
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        Ok(())
    }

    #[test]
    fn unregister_is_idempotent_and_frees_the_id() -> TestResult {
        let (tx, _rx) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        assert!(!registry.unregister("a"));
        registry.register("a", Arc::new(Echo(tx.clone())))?;
        assert!(registry.unregister("a"));
        assert!(!registry.unregister("a"));
        assert!(!registry.contains("a"));
        registry.register("a", Arc::new(Echo(tx)))?;
        assert!(registry.contains("a"));
        Ok(())
    }

    #[test]
    fn concurrent_register_unregister_and_lookup_stay_consistent() {
        let (tx, _rx) = mpsc::unbounded_channel::<(String, bool)>();
        let registry = PerJob::new();
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let registry = registry.clone();
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for round in 0..200 {
                        let id = format!("w{worker}-{}", round % 5);
                        let _ = registry.register(&id, Arc::new(Echo(tx.clone())));
                        let _ = registry.contains(&id);
                        if round % 2 == 0 {
                            registry.unregister(&id);
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            assert!(worker.join().is_ok());
        }
        for worker in 0..8 {
            for slot in 0..5 {
                registry.unregister(&format!("w{worker}-{slot}"));
            }
        }
        assert!(registry.is_empty());
    }

    #[test]
    fn many_ids_register_and_unregister() -> TestResult {
        let (tx, _rx) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        for n in 0..20_000 {
            registry.register(&format!("j{n}"), Arc::new(Echo(tx.clone())))?;
        }
        assert_eq!(registry.len(), 20_000);
        assert!(registry.contains("j19999"));
        assert!(registry.unregister("j0"));
        assert_eq!(registry.len(), 19_999);
        Ok(())
    }

    #[tokio::test]
    async fn a_poisoned_lock_does_not_stop_the_registry() -> TestResult {
        let dir = TempDir::new()?;
        let (tx, _seen) = mpsc::unbounded_channel();
        let registry = PerJob::new();
        registry.register("job1", Arc::new(Echo(tx.clone())))?;
        let poisoner = registry.clone();
        let outcome = std::thread::spawn(move || {
            let _guard = poisoner.jobs.lock();
            panic!("poison the registry lock");
        })
        .join();
        assert!(outcome.is_err());
        assert!(registry.jobs.is_poisoned());
        registry.register("job3", Arc::new(Echo(tx)))?;
        assert!(registry.contains("job3"));
        let sock = per_job_socket(&dir, &registry)?;
        let mut stream = dial(&sock).await?;
        echoes(&mut stream).await?;
        assert!(registry.unregister("job1"));
        Ok(())
    }
}

//! The job spec handoff between the launcher and `fleetd agent-exec`.
//!
//! The launcher writes `spec.json` into the job's run directory. The unit runs
//! `fleetd agent-exec <id>` as the job uid, which reads that file, changes into the working
//! directory and runs the agent as a child, next to the egress [`Forwarder`] that carries the
//! agent's proxy traffic to the Job socket. The environment comes from the unit's
//! `EnvironmentFile`, so the spec file never holds it.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::time::{Instant, sleep_until, timeout};

use crate::jobsock::{ServiceName, connect, socket_path};
use crate::runner::AgentSpec;
use crate::tools::{MisePins, verify_mise};
use crate::workspace::validate_job_id;

/// File name of the spec inside a job's run directory.
pub const SPEC_FILE: &str = "spec.json";

const PROXY_URL_ENV: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const PROXY_CLEARED_ENV: [&str; 4] = ["NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"];
const NODE_PROXY_ENV: &str = "NODE_USE_ENV_PROXY";
const MAX_SPEC_BYTES: u64 = 1024 * 1024;
const SPEC_MODE: u32 = 0o600;
const SPEC_SHARED_MODE: u32 = 0o640;

#[derive(Debug, Serialize, Deserialize)]
struct SpecFile {
    id: String,
    argv: Vec<String>,
    cwd: PathBuf,
}

/// Why `agent-exec` could not start the agent. No variant carries an argument or an
/// environment value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentExecError {
    /// The job id is not `[A-Za-z0-9_]{1,64}`.
    InvalidId,
    /// The spec file is missing or unreadable.
    MissingSpec,
    /// The spec file is too large or is not a valid spec.
    MalformedSpec,
    /// The spec names a different job than the argument.
    IdMismatch,
    /// The spec holds no program.
    EmptyArgv,
    /// The program could not be executed in the working directory.
    Exec(io::ErrorKind),
    /// The egress forwarder could not listen on the loopback.
    Listen(io::ErrorKind),
}

impl fmt::Display for AgentExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId => f.write_str("job id is not valid"),
            Self::MissingSpec => f.write_str("job spec is missing or unreadable"),
            Self::MalformedSpec => f.write_str("job spec is malformed or too large"),
            Self::IdMismatch => f.write_str("job spec belongs to a different job"),
            Self::EmptyArgv => f.write_str("job spec has an empty command line"),
            Self::Exec(kind) => write!(f, "agent could not be executed: {kind}"),
            Self::Listen(kind) => write!(f, "egress forwarder could not listen: {kind}"),
        }
    }
}

impl std::error::Error for AgentExecError {}

/// Writes the spec for job `id` to `path` with mode 0600, or 0640 and group `gid` when it is
/// set. Never writes the environment.
///
/// # Errors
///
/// Fails when `path` exists, an argument is not UTF-8, or the file cannot be written. A
/// partial file is removed.
pub fn write_spec(path: &Path, id: &str, spec: &AgentSpec, gid: Option<u32>) -> io::Result<()> {
    let argv = spec
        .argv
        .iter()
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let body = serde_json::to_vec(&SpecFile {
        id: id.to_owned(),
        argv,
        cwd: spec.cwd.clone(),
    })
    .map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SPEC_MODE)
        .open(path)?;
    let written = file.write_all(&body).and_then(|()| {
        gid.map_or(Ok(()), |gid| {
            std::os::unix::fs::chown(path, None, Some(gid))?;
            fs::set_permissions(path, fs::Permissions::from_mode(SPEC_SHARED_MODE))
        })
    });
    if written.is_err() {
        let _ = fs::remove_file(path);
    }
    written
}

fn read_spec(path: &Path) -> Result<SpecFile, AgentExecError> {
    let mut body = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_SPEC_BYTES + 1).read_to_end(&mut body))
        .map_err(|_| AgentExecError::MissingSpec)?;
    if u64::try_from(body.len()).map_or(true, |len| len > MAX_SPEC_BYTES) {
        return Err(AgentExecError::MalformedSpec);
    }
    serde_json::from_slice(&body).map_err(|_| AgentExecError::MalformedSpec)
}

/// Most connections the forwarder serves at once. It equals the default tunnel cap of the
/// proxy, so the forwarder never holds more Job socket slots than the proxy will serve.
pub const MAX_FORWARDED: usize = 4;

/// Idle time after which the forwarder closes a connection.
pub const FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Bounds of the in-namespace forwarder.
#[derive(Debug, Clone, Copy)]
pub struct ForwardLimits {
    /// Most concurrent connections. Further ones are closed unread.
    pub max_connections: usize,
    /// Longest time without a byte in either direction.
    pub idle_timeout: Duration,
}

impl Default for ForwardLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_FORWARDED,
            idle_timeout: FORWARD_IDLE_TIMEOUT,
        }
    }
}

const COPY_CHUNK: usize = 16 * 1024;
const ACCEPT_RETRY: Duration = Duration::from_millis(10);

/// The loopback listener that relays to the Job socket.
///
/// It dials only the socket path it was given at start, never one read from the environment,
/// and selects only [`ServiceName::EgressProxy`]. It runs on its own thread, so it dies with
/// the process. Dropping it stops the accept loop and closes every open connection.
#[derive(Debug)]
pub struct Forwarder {
    port: u16,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

struct Dial {
    socket: PathBuf,
    uid: u32,
    idle: Duration,
}

impl Forwarder {
    /// Binds an ephemeral port on 127.0.0.1.
    ///
    /// # Errors
    ///
    /// Fails when the bind fails.
    pub fn start(socket: PathBuf, uid: u32, limits: ForwardLimits) -> io::Result<Self> {
        Self::start_on(SocketAddr::from(([127, 0, 0, 1], 0)), socket, uid, limits)
    }

    /// Binds `addr`.
    ///
    /// # Errors
    ///
    /// Fails when the bind fails.
    pub fn start_on(
        addr: SocketAddr,
        socket: PathBuf,
        uid: u32,
        limits: ForwardLimits,
    ) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (stop, stopped) = oneshot::channel();
        let dial = Arc::new(Dial {
            socket,
            uid,
            idle: limits.idle_timeout,
        });
        let permits = Arc::new(Semaphore::new(limits.max_connections));
        let thread = std::thread::Builder::new()
            .name("egress-forwarder".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    if let Ok(listener) = TcpListener::from_std(listener) {
                        accept_loop(listener, dial, permits, stopped).await;
                    }
                });
            })?;
        Ok(Self {
            port,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// The bound port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    dial: Arc<Dial>,
    permits: Arc<Semaphore>,
    mut stopped: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stopped => return,
            accepted = listener.accept() => match accepted {
                Ok((client, _)) => match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => {
                        let dial = Arc::clone(&dial);
                        tokio::spawn(async move {
                            relay(client, &dial).await;
                            drop(permit);
                        });
                    }
                    Err(_) => drop(client),
                },
                Err(_) => tokio::time::sleep(ACCEPT_RETRY).await,
            },
        }
    }
}

async fn relay(client: TcpStream, dial: &Dial) {
    let Ok(upstream) = connect(&dial.socket, ServiceName::EgressProxy, dial.uid).await else {
        return;
    };
    pump(client, upstream, dial.idle).await;
}

async fn pump(client: TcpStream, upstream: UnixStream, idle: Duration) {
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut up_rd, mut up_wr) = upstream.into_split();
    let mut from_client = vec![0_u8; COPY_CHUNK];
    let mut from_upstream = vec![0_u8; COPY_CHUNK];
    let mut deadline = Instant::now() + idle;
    loop {
        tokio::select! {
            () = sleep_until(deadline) => return,
            read = client_rd.read(&mut from_client) => {
                let Ok(n @ 1..) = read else { return };
                let chunk = from_client.get(..n).unwrap_or_default();
                if !matches!(timeout(idle, up_wr.write_all(chunk)).await, Ok(Ok(()))) {
                    return;
                }
                deadline = Instant::now() + idle;
            }
            read = up_rd.read(&mut from_upstream) => {
                let Ok(n @ 1..) = read else { return };
                let chunk = from_upstream.get(..n).unwrap_or_default();
                if !matches!(timeout(idle, client_wr.write_all(chunk)).await, Ok(Ok(()))) {
                    return;
                }
                deadline = Instant::now() + idle;
            }
        }
    }
}

/// Points the four proxy URL variables of `command` at `proxy` and removes `NO_PROXY` and
/// `ALL_PROXY` in both cases, so no inherited value bypasses the forwarder.
pub fn apply_proxy_env(command: &mut Command, proxy: &str) {
    for name in PROXY_URL_ENV {
        command.env(name, proxy);
    }
    for name in PROXY_CLEARED_ENV {
        command.env_remove(name);
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Runs the agent for job `id` described by `run_dir/<id>/spec.json`, run in the spec's working
/// directory, and exits this process with the agent's exit code.
///
/// Before it starts the agent it binds a [`Forwarder`] on an ephemeral 127.0.0.1 port in the
/// unit's network namespace, aimed at `run_dir/<id>/job.sock`. The agent inherits the
/// environment of the unit, except that `HTTPS_PROXY`, `HTTP_PROXY` and their lowercase forms
/// name the forwarder, `NODE_USE_ENV_PROXY` is `1`, and `NO_PROXY` and `ALL_PROXY` are removed.
/// The forwarder thread lives as long as this process, which waits for the agent, so no
/// forwarder outlives it. The unit's cgroup kill ends both when systemd stops the unit.
///
/// Only returns on failure, with the reason.
pub fn exec_job(run_dir: &Path, id: &str) -> AgentExecError {
    if validate_job_id(id).is_err() {
        return AgentExecError::InvalidId;
    }
    let spec = match read_spec(&run_dir.join(id).join(SPEC_FILE)) {
        Ok(spec) => spec,
        Err(err) => return err,
    };
    if spec.id != id {
        return AgentExecError::IdMismatch;
    }
    let Some((program, args)) = spec.argv.split_first() else {
        return AgentExecError::EmptyArgv;
    };
    let Some(socket) = socket_path(run_dir, id) else {
        return AgentExecError::InvalidId;
    };
    let uid = fs::metadata(run_dir.join(id)).map_or(u32::MAX, |meta| meta.uid());
    let forwarder = match Forwarder::start(socket, uid, ForwardLimits::default()) {
        Ok(forwarder) => forwarder,
        Err(err) => return AgentExecError::Listen(err.kind()),
    };
    let proxy = format!("http://127.0.0.1:{}", forwarder.port());
    let mut command = Command::new(program);
    command.args(args).current_dir(&spec.cwd);
    apply_proxy_env(&mut command, &proxy);
    command.env(NODE_PROXY_ENV, "1");
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => return AgentExecError::Exec(err.kind()),
    };
    let code = child.wait().map_or(1, exit_code);
    drop(forwarder);
    std::process::exit(code)
}

/// Port of the install forwarder inside the install unit's private network namespace.
///
/// The namespace is empty, so the port cannot clash. [`crate::tools::write_tool_env`] callers
/// write the same port into `tool-env`, and the wrapper sets the same URL on the child.
pub const TOOL_PROXY_PORT: u16 = 3128;

/// Path of the bundled mise binary the install unit runs, owned by root.
pub const MISE_BINARY: &str = "/usr/local/libexec/fleet/mise";

/// Uid that must own [`MISE_BINARY`] and its directory.
pub const MISE_OWNER_UID: u32 = 0;

/// Arguments the wrapper passes to the bundled mise.
pub const TOOL_INSTALL_ARGS: [&str; 2] = ["install", "--locked"];

/// Why `tool-install-exec` did not run the install. Display text is fixed and holds no path,
/// pin or environment value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolInstallError {
    /// The job id is not `[A-Za-z0-9_]{1,64}`.
    InvalidId,
    /// Box config has no complete `[mise]` pin table.
    MissingPins,
    /// The bundled mise failed its pin, owner, mode or signature checks.
    Unverified,
    /// The egress forwarder could not listen on the loopback.
    Listen(io::ErrorKind),
    /// The install program could not be executed.
    Exec(io::ErrorKind),
}

impl fmt::Display for ToolInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId => f.write_str("job id is not valid"),
            Self::MissingPins => f.write_str("mise pins are not configured"),
            Self::Unverified => f.write_str("bundled mise failed verification"),
            Self::Listen(kind) => write!(f, "egress forwarder could not listen: {kind}"),
            Self::Exec(kind) => write!(f, "tool install could not be executed: {kind}"),
        }
    }
}

impl std::error::Error for ToolInstallError {}

/// Verifies the bundled `mise` against `pins`, then runs `mise install --locked` for job `id`
/// next to an egress [`Forwarder`], and exits this process with the install's exit code.
///
/// The forwarder binds `127.0.0.1` on [`TOOL_PROXY_PORT`] in the unit's network namespace and
/// dials only `run_dir/<id>/job.sock`, as `agent-exec` does. Without `pins`, or when the binary
/// does not verify, nothing is started and the error comes back.
///
/// Only returns on failure, with the reason.
pub fn exec_tool_install(
    run_dir: &Path,
    id: &str,
    mise: &Path,
    pins: Option<&MisePins>,
    expected_owner: u32,
) -> ToolInstallError {
    if validate_job_id(id).is_err() {
        return ToolInstallError::InvalidId;
    }
    let Some(pins) = pins else {
        return ToolInstallError::MissingPins;
    };
    let Ok(verified) = verify_mise(mise, pins, expected_owner) else {
        return ToolInstallError::Unverified;
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], TOOL_PROXY_PORT));
    match run_tool_install(run_dir, id, verified.path(), addr) {
        Ok(code) => std::process::exit(code),
        Err(err) => err,
    }
}

/// Runs `program install --locked` with the proxy variables of an egress [`Forwarder`] bound on
/// `addr`, and returns the exit code. The forwarder is dropped before this returns.
///
/// # Errors
///
/// Returns [`ToolInstallError`] when the id is invalid, the forwarder cannot listen or the
/// program cannot be executed.
#[doc(hidden)]
pub fn run_tool_install(
    run_dir: &Path,
    id: &str,
    program: &Path,
    addr: SocketAddr,
) -> Result<i32, ToolInstallError> {
    if validate_job_id(id).is_err() {
        return Err(ToolInstallError::InvalidId);
    }
    let socket = socket_path(run_dir, id).ok_or(ToolInstallError::InvalidId)?;
    let uid = fs::metadata(run_dir.join(id)).map_or(u32::MAX, |meta| meta.uid());
    let forwarder = Forwarder::start_on(addr, socket, uid, ForwardLimits::default())
        .map_err(|err| ToolInstallError::Listen(err.kind()))?;
    let proxy = format!("http://127.0.0.1:{}", forwarder.port());
    let mut command = Command::new(program);
    command.args(TOOL_INSTALL_ARGS);
    apply_proxy_env(&mut command, &proxy);
    let mut child = command
        .spawn()
        .map_err(|err| ToolInstallError::Exec(err.kind()))?;
    let code = child.wait().map_or(1, exit_code);
    drop(forwarder);
    Ok(code)
}

/// Fixed system directories that follow the cache bin dirs on the agent `PATH`.
pub const SYSTEM_PATH_TAIL: &str = "/usr/local/bin:/usr/bin:/bin";

/// Most tools one agent `PATH` may name. It equals the cache entry cap.
pub const MAX_PATH_TOOLS: usize = crate::tools::MAX_CACHE_ENTRIES;

/// Why the agent `PATH` could not be built or an environment was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentPathError {
    /// A name is outside the registry or a version is not an exact pin.
    InvalidTool,
    /// The list names one tool twice.
    DuplicateTool,
    /// The list is longer than [`MAX_PATH_TOOLS`].
    TooMany,
    /// An entry or its `bin` directory failed the cache check.
    NotCached,
    /// The cache could not be read.
    Cache,
    /// The environment sets `PATH`.
    PathOverride,
}

impl fmt::Display for AgentPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidTool => "tool name or version is not valid",
            Self::DuplicateTool => "tool list names a tool twice",
            Self::TooMany => "tool list is too long",
            Self::NotCached => "tool is not in the cache",
            Self::Cache => "tool cache could not be read",
            Self::PathOverride => "environment sets PATH",
        })
    }
}

impl std::error::Error for AgentPathError {}

/// Builds the agent `PATH` from the job's resolved `(name, version)` list.
///
/// The result is the `bin` directory of each cache entry in list order, then
/// [`SYSTEM_PATH_TAIL`]. Every entry must pass [`ToolCache::lookup`] and its `bin` must be a real
/// directory (never a symlink) without group or other write bits; a miss or a failed check is
/// an error, never skipped. A repeated name is refused so list order alone decides precedence.
/// Nothing comes from the parent environment or the profile.
///
/// Layout: the entry is `root/<name>/<version>` and this function assumes the tool puts its
/// executables in `bin` below it, the layout mise uses for `installs/<tool>/<version>/bin`.
/// Unverified: that every registry tool installs into that `bin` (tools that unpack to a
/// differently named directory, or that mise shims, are not mapped). No live run has confirmed
/// it, and the install unit's layout (TOOL-8) may need a mapping here.
///
/// # Errors
///
/// Returns the [`AgentPathError`] for the first failing entry.
pub fn build_agent_path(
    cache: &crate::tools::ToolCache,
    tools: &[(String, String)],
) -> Result<String, AgentPathError> {
    if tools.len() > MAX_PATH_TOOLS {
        return Err(AgentPathError::TooMany);
    }
    let mut seen: Vec<&str> = Vec::with_capacity(tools.len());
    let mut path = String::new();
    for (name, version) in tools {
        let hit = cache
            .lookup(name, version)
            .map_err(|err| match err {
                crate::tools::ToolsError::InvalidTool => AgentPathError::InvalidTool,
                _ => AgentPathError::Cache,
            })?
            .ok_or(AgentPathError::NotCached)?;
        if seen.contains(&name.as_str()) {
            return Err(AgentPathError::DuplicateTool);
        }
        seen.push(name);
        let bin = hit.path().join("bin");
        let usable =
            fs::symlink_metadata(&bin).is_ok_and(|meta| meta.is_dir() && meta.mode() & 0o022 == 0);
        if !usable {
            return Err(AgentPathError::NotCached);
        }
        path.push_str(bin.to_str().ok_or(AgentPathError::Cache)?);
        path.push(':');
    }
    path.push_str(SYSTEM_PATH_TAIL);
    Ok(path)
}

/// Refuses an environment that sets `PATH` in any letter case. A profile or job env never
/// sets it, so a key that matches is an error rather than a value to ignore.
///
/// # Errors
///
/// Returns [`AgentPathError::PathOverride`] for the first matching key.
pub fn refuse_path_override<'a>(
    keys: impl IntoIterator<Item = &'a str>,
) -> Result<(), AgentPathError> {
    if keys.into_iter().any(|key| key.eq_ignore_ascii_case("PATH")) {
        Err(AgentPathError::PathOverride)
    } else {
        Ok(())
    }
}

/// Sets `PATH` on `command` to `path`, replacing any inherited value. Call it after the
/// environment is applied so nothing the parent holds survives.
pub fn apply_agent_path(command: &mut Command, path: &str) {
    command.env_remove("PATH");
    command.env("PATH", path);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UnixStream};
    use tokio::time::timeout;

    use super::{ForwardLimits, Forwarder};
    use crate::jobsock::{
        AGENT_SLICE, JobContext, JobSocket, Limits, Peer, PeerId, ServeFuture, Service,
        ServiceName, Services,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const OUTER: Duration = Duration::from_secs(10);
    const REFUSAL: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";

    struct AgentPeer;

    impl Peer for AgentPeer {
        fn identity(&self, _: &UnixStream) -> std::io::Result<PeerId> {
            Ok(PeerId {
                pid: 1,
                cgroup: format!("0::/{AGENT_SLICE}/fleet-agent@job1.service\n"),
            })
        }
    }

    struct Echo(Arc<AtomicUsize>);

    impl Service for Echo {
        fn serve(&self, _: JobContext, mut stream: UnixStream) -> ServeFuture<'_> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0_u8; 256];
                while let Ok(n @ 1..) = stream.read(&mut buf).await {
                    if stream
                        .write_all(buf.get(..n).unwrap_or_default())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            })
        }
    }

    struct Refuse;

    impl Service for Refuse {
        fn serve(&self, _: JobContext, mut stream: UnixStream) -> ServeFuture<'_> {
            Box::pin(async move {
                let mut buf = [0_u8; 256];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(REFUSAL).await;
            })
        }
    }

    struct Hold;

    impl Service for Hold {
        fn serve(&self, _: JobContext, stream: UnixStream) -> ServeFuture<'_> {
            Box::pin(async move {
                let _held = stream;
                std::future::pending::<()>().await;
            })
        }
    }

    struct Rig {
        _dir: TempDir,
        _socket: JobSocket,
        forwarder: Forwarder,
    }

    impl Rig {
        fn start(service: impl Service + 'static, limits: ForwardLimits) -> TestResult2<Self> {
            let dir = TempDir::new()?;
            let mut services = Services::new();
            services.insert(ServiceName::EgressProxy, Arc::new(service));
            let socket = JobSocket::bind(
                &dir.path().join("job.sock"),
                "job1",
                services,
                Arc::new(AgentPeer),
                Limits::default(),
            )?;
            let uid = rustix::process::geteuid().as_raw();
            let forwarder = Forwarder::start(socket.path().to_path_buf(), uid, limits)?;
            Ok(Self {
                _dir: dir,
                _socket: socket,
                forwarder,
            })
        }

        async fn client(&self) -> std::io::Result<TcpStream> {
            TcpStream::connect(("127.0.0.1", self.forwarder.port())).await
        }
    }

    type TestResult2<T> = Result<T, Box<dyn std::error::Error>>;

    fn limits(max_connections: usize, idle_ms: u64) -> ForwardLimits {
        ForwardLimits {
            max_connections,
            idle_timeout: Duration::from_millis(idle_ms),
        }
    }

    async fn reads_eof(stream: &mut TcpStream) -> TestResult2<Vec<u8>> {
        let mut got = Vec::new();
        timeout(OUTER, async {
            let mut buf = [0_u8; 256];
            while let Ok(n @ 1..) = stream.read(&mut buf).await {
                got.extend_from_slice(buf.get(..n).unwrap_or_default());
            }
        })
        .await
        .map_err(|_| "connection was not closed in time")?;
        Ok(got)
    }

    async fn stays_open(stream: &mut TcpStream) -> bool {
        let mut buf = [0_u8; 1];
        timeout(Duration::from_millis(300), stream.read(&mut buf))
            .await
            .is_err()
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_through_the_job_socket() -> TestResult {
        let seen = Arc::new(AtomicUsize::new(0));
        let rig = Rig::start(Echo(Arc::clone(&seen)), ForwardLimits::default())?;
        let mut client = rig.client().await?;
        client.write_all(b"hello tunnel").await?;
        let mut back = [0_u8; 12];
        timeout(OUTER, client.read_exact(&mut back)).await??;
        assert_eq!(&back, b"hello tunnel");
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn garbage_gets_the_upstream_refusal_and_a_close() -> TestResult {
        let rig = Rig::start(Refuse, ForwardLimits::default())?;
        let mut client = rig.client().await?;
        client.write_all(&[0xff, 0x00, 0xfe, b'\r', b'\n']).await?;
        assert_eq!(reads_eof(&mut client).await?, REFUSAL);
        Ok(())
    }

    #[tokio::test]
    async fn a_client_that_never_sends_is_closed_at_the_idle_timeout() -> TestResult {
        let rig = Rig::start(Echo(Arc::default()), limits(4, 300))?;
        let mut client = rig.client().await?;
        assert_eq!(reads_eof(&mut client).await?, Vec::<u8>::new());
        Ok(())
    }

    #[tokio::test]
    async fn connections_over_the_cap_are_closed_unread_and_a_slot_frees_on_close() -> TestResult {
        let rig = Rig::start(Hold, limits(2, 60_000))?;
        let first = rig.client().await?;
        let mut second = rig.client().await?;
        let mut third = rig.client().await?;
        assert_eq!(reads_eof(&mut third).await?, Vec::<u8>::new());
        assert!(stays_open(&mut second).await);
        drop(first);
        let end = tokio::time::Instant::now() + OUTER;
        loop {
            let mut again = rig.client().await?;
            if stays_open(&mut again).await {
                break;
            }
            assert!(tokio::time::Instant::now() < end, "slot never freed");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_job_socket_closes_the_client() -> TestResult {
        let dir = TempDir::new()?;
        let forwarder = Forwarder::start(dir.path().join("job.sock"), 0, limits(4, 60_000))?;
        let mut client = TcpStream::connect(("127.0.0.1", forwarder.port())).await?;
        client.write_all(b"x").await?;
        assert_eq!(reads_eof(&mut client).await?, Vec::<u8>::new());
        Ok(())
    }

    #[tokio::test]
    async fn a_port_in_use_fails_the_start() -> TestResult {
        let taken = TcpListener::bind(("127.0.0.1", 0)).await?;
        let err = Forwarder::start_on(
            taken.local_addr()?,
            "/nonexistent/job.sock".into(),
            0,
            ForwardLimits::default(),
        )
        .err()
        .map(|err| err.kind());
        assert_eq!(err, Some(std::io::ErrorKind::AddrInUse));
        Ok(())
    }

    #[tokio::test]
    async fn dropping_the_forwarder_closes_the_port_and_open_connections() -> TestResult {
        let rig = Rig::start(Hold, limits(4, 60_000))?;
        let port = rig.forwarder.port();
        let mut client = rig.client().await?;
        assert!(stays_open(&mut client).await);
        let Rig {
            _dir,
            _socket,
            forwarder,
        } = rig;
        drop(forwarder);
        assert_eq!(reads_eof(&mut client).await?, Vec::<u8>::new());
        let end = tokio::time::Instant::now() + OUTER;
        while TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            assert!(tokio::time::Instant::now() < end, "port still open");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    }
}

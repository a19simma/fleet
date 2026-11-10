//! Job environments: the `GetJobEnvironment` client, the held secret map and its redaction
//! (ADR-0067).
//!
//! A [`ReleasedEnvironment`] holds the secret values the server released to one claimed job, in
//! memory only. It zeroes them on drop and prints names only. [`EnvDelivery`] writes the
//! values the agent may see to a tmpfs delivery tree and shreds it when the Job ends.
//!
//! Every refusal of the call, whatever its cause, becomes the one [`EnvDenied`] with the fixed
//! reason [`ERR_ENV_DENIED`], so a User cannot probe the server's reasons through the Job
//! error. A refused call fails the Job before its workspace exists.
//!
//! Zeroing is partial. The bearer header value, the `prost` decode buffers and the [`Redactor`]
//! copies are plain allocations that are not zeroed when dropped.
//!
//! The Redactor registers each secret in full and each line of 8 or more bytes of a multi-line
//! secret, at most [`MAX_REDACT_LINES`] lines in total, longest first.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rustix::fs::{
    AtFlags, CWD, Dir, FileType, Gid, Mode, OFlags, Uid, fchmod, fchown, fstat, mkdirat, openat,
    renameat, statat, unlinkat,
};
use rustix::io::Errno;

use fleet_core::environment::{DEFAULT_TIMEOUT_S, Delivery};
use fleet_core::{MIN_SECRET_LEN, Redactor};
use fleet_proto::ERR_ENV_RELEASE_DENIED;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    EnvironmentDelivery, EnvironmentOnFail, GetJobEnvironmentReply, GetJobEnvironmentRequest,
};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Status};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::poller::{CALL_BACKSTOP, TOKEN_ENV};
use crate::workspace::validate_job_id;

/// Job failure reason for every refused environment release.
pub const ERR_ENV_DENIED: &str = ERR_ENV_RELEASE_DENIED;

/// Most secret lines the Redactor registers for one Job.
pub const MAX_REDACT_LINES: usize = 4096;

/// Largest `GetJobEnvironment` reply the client decodes, in bytes: the ADR-0018 decode limit.
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// Job note text when [`MAX_REDACT_LINES`] cut the registered lines.
pub const NOTE_COVERAGE_REDUCED: &str = "redaction coverage reduced";

/// The refusal of a `GetJobEnvironment` call. Carries no cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvDenied;

impl EnvDenied {
    /// The fixed Job failure reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        ERR_ENV_DENIED
    }
}

impl fmt::Display for EnvDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ERR_ENV_DENIED)
    }
}

impl StdError for EnvDenied {}

/// A [`Redactor`] over released values and whether the line limit cut its coverage.
#[derive(Debug, Clone)]
pub struct Redaction {
    /// Masks every registered value and line.
    pub redactor: Redactor,
    /// True when more lines qualified than the limit allows and the shortest were left out.
    pub reduced: bool,
}

/// The secret values released to one Job, by name.
///
/// Values are zeroed on [`ReleasedEnvironment::wipe`] and on drop. `Debug` prints names only.
#[derive(Default)]
pub struct ReleasedEnvironment {
    secrets: BTreeMap<String, Held>,
    scripts: Vec<SetupScript>,
}

/// One Environment script step, in execution order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupScript {
    /// The step name.
    pub name: String,
    /// The script text, which starts with a `#!/` line.
    pub body: String,
    /// Whether a failure fails the Job. Only `Abort` is acted on; `Continue` is read as `Abort`.
    pub abort: bool,
    /// The step timeout.
    pub timeout: Duration,
}

struct Held {
    value: Zeroizing<String>,
    agent_visible: bool,
    delivery: Delivery,
}

impl fmt::Debug for ReleasedEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleasedEnvironment")
            .field("names", &self.secrets.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ZeroizeOnDrop for ReleasedEnvironment {}

impl Drop for ReleasedEnvironment {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl ReleasedEnvironment {
    /// Takes the secrets out of `reply`. A name sent twice keeps its last value.
    #[must_use]
    pub fn from_reply(mut reply: GetJobEnvironmentReply) -> Self {
        let mut secrets = BTreeMap::new();
        for secret in std::mem::take(&mut reply.secrets) {
            let delivery = if secret.delivery == i32::from(EnvironmentDelivery::Env) {
                Delivery::Env
            } else {
                Delivery::File
            };
            secrets.insert(
                secret.name,
                Held {
                    value: Zeroizing::new(secret.value),
                    agent_visible: secret.agent_visible,
                    delivery,
                },
            );
        }
        let scripts = std::mem::take(&mut reply.scripts)
            .into_iter()
            .map(|script| SetupScript {
                name: script.name,
                body: script.body,
                abort: script.on_fail != i32::from(EnvironmentOnFail::Continue),
                timeout: Duration::from_secs(u64::from(
                    script.timeout_s.unwrap_or(DEFAULT_TIMEOUT_S),
                )),
            })
            .collect();
        Self { secrets, scripts }
    }

    /// The scripts of this environment, in execution order.
    #[must_use]
    pub fn scripts(&self) -> &[SetupScript] {
        &self.scripts
    }

    /// The value held under `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(|held| held.value.as_str())
    }

    /// Every held secret as `(name, value, agent_visible, delivery)`, by name.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str, bool, Delivery)> {
        self.secrets.iter().map(|(name, held)| {
            (
                name.as_str(),
                held.value.as_str(),
                held.agent_visible,
                held.delivery,
            )
        })
    }

    /// Number of secrets held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether no secret is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Zeroes every value and empties the map.
    pub fn wipe(&mut self) {
        for held in self.secrets.values_mut() {
            zeroize::Zeroize::zeroize(&mut held.value);
        }
        self.secrets.clear();
        self.scripts.clear();
    }

    /// The redactor of these values under [`MAX_REDACT_LINES`].
    #[must_use]
    pub fn redaction(&self) -> Redaction {
        self.redaction_with_limit(MAX_REDACT_LINES)
    }

    /// The redactor of these values with at most `limit` registered lines.
    ///
    /// Each value is registered in full. Each line of [`MIN_SECRET_LEN`] bytes or more of a value
    /// with more than one line is registered too. When more lines qualify than `limit`, the
    /// longest `limit` are kept, ties broken by text, and `reduced` is set. A single-line value
    /// is its own line and does not count against the limit.
    #[must_use]
    pub fn redaction_with_limit(&self, limit: usize) -> Redaction {
        let mut lines = BTreeSet::new();
        for held in self.secrets.values() {
            let value = &held.value;
            if value.contains('\n') {
                lines.extend(
                    value
                        .lines()
                        .filter(|line| line.len() >= MIN_SECRET_LEN)
                        .map(str::to_owned),
                );
            }
        }
        let mut lines: Vec<String> = lines.into_iter().collect();
        lines.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        let reduced = lines.len() > limit;
        lines.truncate(limit);
        let values = self
            .secrets
            .values()
            .map(|held| held.value.as_str().to_owned());
        Redaction {
            redactor: Redactor::new(values.chain(lines)),
            reduced,
        }
    }
}

fn bearer_header(token: &str) -> Result<MetadataValue<tonic::metadata::Ascii>, Error> {
    let text = Zeroizing::new(format!("Bearer {token}"));
    let mut header: MetadataValue<_> = text.as_str().parse().map_err(|_| Error::InvalidValue {
        name: TOKEN_ENV,
        value: String::from("<redacted>"),
    })?;
    header.set_sensitive(true);
    Ok(header)
}

#[derive(Clone)]
struct Attach(MetadataValue<tonic::metadata::Ascii>);

impl Interceptor for Attach {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("authorization", self.0.clone());
        Ok(request)
    }
}

type Client = FleetWorkerClient<InterceptedService<Channel, Attach>>;

/// The `GetJobEnvironment` caller, with the bearer token attached.
///
/// Each call builds its own client over a clone of the channel and runs under a backstop.
pub struct EnvironmentClient {
    channel: Channel,
    attach: Attach,
    backstop: Duration,
}

impl fmt::Debug for EnvironmentClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvironmentClient").finish_non_exhaustive()
    }
}

impl EnvironmentClient {
    /// A client over `channel`. The caller sets the request timeout on the channel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidValue`] when the token is not a valid header value. The error
    /// never contains it.
    pub fn new(channel: Channel, token: &str) -> Result<Self, Error> {
        Ok(Self {
            channel,
            attach: Attach(bearer_header(token)?),
            backstop: CALL_BACKSTOP,
        })
    }

    /// Replaces the longest time one call may take, [`CALL_BACKSTOP`] by default.
    #[must_use]
    pub const fn with_backstop(mut self, backstop: Duration) -> Self {
        self.backstop = backstop;
        self
    }

    fn client(&self) -> Client {
        FleetWorkerClient::with_interceptor(self.channel.clone(), self.attach.clone())
            .max_decoding_message_size(MAX_REPLY_BYTES)
    }

    /// Fetches the secrets the lease of `job_id` and `attempt` releases.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDenied`] for every failure: a refusal, a transport error, a reply over
    /// [`MAX_REPLY_BYTES`] or a call past the backstop. The cause is not kept.
    pub async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<ReleasedEnvironment, EnvDenied> {
        let request = GetJobEnvironmentRequest {
            job_id: job_id.to_owned(),
            attempt,
            r#box: box_name.to_owned(),
        };
        let mut client = self.client();
        let call = tokio::time::timeout(self.backstop, client.get_job_environment(request)).await;
        let reply = call.map_err(|_| EnvDenied)?.map_err(|_| EnvDenied)?;
        Ok(ReleasedEnvironment::from_reply(reply.into_inner()))
    }
}

/// Name of the delivery directory under the Job run directory.
pub const DELIVERY_DIR: &str = "envd";

/// Name of the `EnvironmentFile=` for env delivery, inside [`DELIVERY_DIR`].
pub const ENV_FILE_NAME: &str = "envd.env";

/// Job failure reason when the delivery tree cannot be written.
pub const ERR_ENV_DELIVERY: &str = "environment delivery failed";

/// Why a delivery tree was refused or could not be written. Carries no name and no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryError {
    /// A root or id that is not absolute or not a valid job id.
    BadPath,
    /// The run directory is not on tmpfs.
    NotTmpfs,
    /// A secret name that is unsafe as a file name.
    InvalidName,
    /// Two secret names equal after case folding.
    DuplicateName,
    /// An env-delivered value with a line break.
    EnvMultiline,
    /// A filesystem error.
    Io(io::ErrorKind),
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ERR_ENV_DELIVERY)
    }
}

impl StdError for DeliveryError {}

/// Answers whether an open directory sits on tmpfs.
pub trait MountCheck: Send + Sync + fmt::Debug {
    /// # Errors
    ///
    /// Returns the error of the filesystem query.
    fn is_tmpfs(&self, dir: BorrowedFd<'_>) -> io::Result<bool>;
}

/// The production [`MountCheck`]: `fstatfs` and the tmpfs magic number.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatfsCheck;

#[cfg(target_os = "linux")]
impl MountCheck for StatfsCheck {
    fn is_tmpfs(&self, dir: BorrowedFd<'_>) -> io::Result<bool> {
        const TMPFS_MAGIC: u64 = 0x0102_1994;
        let stat = rustix::fs::fstatfs(dir)?;
        Ok(u64::try_from(stat.f_type).ok() == Some(TMPFS_MAGIC))
    }
}

#[cfg(not(target_os = "linux"))]
impl MountCheck for StatfsCheck {
    fn is_tmpfs(&self, _dir: BorrowedFd<'_>) -> io::Result<bool> {
        Ok(false)
    }
}

/// The uid and group that own a delivery tree.
///
/// With a `uid` the tree is private to it: directory 0700, files 0400. Changing the owner to
/// another uid needs `CAP_CHOWN`, and removing what it owns needs `CAP_DAC_OVERRIDE`. With no
/// `uid` and a `gid` the tree stays owned by the fleetd uid and is shared with the job group,
/// the way the run directory and the job socket already are: directory 0750, files 0440, no
/// capability needed. With neither, the tree is private to the fleetd uid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// The job uid, when the tree is handed to it.
    pub uid: Option<u32>,
    /// The job group, when set.
    pub gid: Option<u32>,
}

impl Owner {
    const fn group_shared(self) -> bool {
        self.uid.is_none() && self.gid.is_some()
    }

    fn dir_mode(self) -> Mode {
        if self.group_shared() {
            Mode::RWXU | Mode::RGRP | Mode::XGRP
        } else {
            Mode::RWXU
        }
    }

    fn file_mode(self) -> Mode {
        if self.group_shared() {
            Mode::RUSR | Mode::RGRP
        } else {
            Mode::RUSR
        }
    }
}

/// Probe called with the job id of each shred just before it removes the tree.
pub type ShredProbe = Arc<dyn Fn(&str) + Send + Sync>;

const ASIDE_DIR: &str = ".envd-shred";
const MAX_NAME_LEN: usize = 64;
const MAX_TREE_DEPTH: usize = 8;

/// Writes and shreds the delivery tree of each Job.
///
/// The tree is `<run_root>/<id>/envd`: the directory is 0700 and every file 0400, all owned by
/// the job uid, created with `O_NOFOLLOW` and `O_EXCL` relative to open directory handles.
/// File-delivered secrets are one file per name with the exact bytes. Env-delivered secrets
/// are one `envd.env` for `EnvironmentFile=`. Secrets the agent may not see are in neither.
/// [`EnvDelivery::end`] overwrites each file with zeros, unlinks it, removes the tree and only
/// then drops the held values.
pub struct EnvDelivery {
    run_root: PathBuf,
    owner: Owner,
    mount: Arc<dyn MountCheck>,
    probe: Option<ShredProbe>,
    held: Mutex<BTreeMap<String, ReleasedEnvironment>>,
}

impl fmt::Debug for EnvDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held = lock(&self.held);
        f.debug_struct("EnvDelivery")
            .field("run_root", &self.run_root)
            .field("owner", &self.owner)
            .field("held", &*held)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn io_err(error: impl Into<io::Error>) -> DeliveryError {
    DeliveryError::Io(error.into().kind())
}

fn absolute_plain(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| !matches!(c, Component::ParentDir | Component::CurDir))
}

fn valid_secret_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let head = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    head && name.len() <= MAX_NAME_LEN
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !name.eq_ignore_ascii_case("out")
}

fn quote_env(value: &str) -> Result<String, DeliveryError> {
    if value.contains(['\n', '\r']) || value.chars().any(|c| c.is_ascii_control() && c != '\t') {
        return Err(DeliveryError::EnvMultiline);
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if matches!(c, '\\' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

struct Plan {
    files: Vec<(String, Zeroizing<String>)>,
}

fn plan(env: &ReleasedEnvironment) -> Result<Plan, DeliveryError> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    let mut env_lines = Zeroizing::new(String::new());
    for (name, value, visible, delivery) in env.entries() {
        if !visible {
            continue;
        }
        if !valid_secret_name(name) {
            return Err(DeliveryError::InvalidName);
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(DeliveryError::DuplicateName);
        }
        match delivery {
            Delivery::Env => {
                env_lines.push_str(name);
                env_lines.push('=');
                env_lines.push_str(&quote_env(value)?);
                env_lines.push('\n');
            }
            Delivery::File => files.push((name.to_owned(), Zeroizing::new(value.to_owned()))),
        }
    }
    if !env_lines.is_empty() {
        files.push((ENV_FILE_NAME.to_owned(), env_lines));
    }
    Ok(Plan { files })
}

const DIR_FLAGS: OFlags = OFlags::DIRECTORY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn open_dir_at(parent: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    Ok(openat(
        parent,
        name,
        DIR_FLAGS.union(OFlags::RDONLY),
        Mode::empty(),
    )?)
}

fn open_root(root: &Path) -> io::Result<OwnedFd> {
    Ok(openat(
        CWD,
        root,
        DIR_FLAGS.union(OFlags::RDONLY),
        Mode::empty(),
    )?)
}

impl EnvDelivery {
    /// # Errors
    ///
    /// Returns [`DeliveryError::BadPath`] for a relative `run_root` or one with `.` or `..`.
    pub fn new(
        run_root: &Path,
        owner: Owner,
        mount: Arc<dyn MountCheck>,
    ) -> Result<Self, DeliveryError> {
        if !absolute_plain(run_root) {
            return Err(DeliveryError::BadPath);
        }
        Ok(Self {
            run_root: run_root.to_path_buf(),
            owner,
            mount,
            probe: None,
            held: Mutex::default(),
        })
    }

    /// Calls `probe` before each shred removes a tree.
    #[must_use]
    pub fn with_shred_probe(mut self, probe: ShredProbe) -> Self {
        self.probe = Some(probe);
        self
    }

    /// Holds `env` for `job_id` until [`EnvDelivery::end`].
    pub fn hold(&self, job_id: &str, env: ReleasedEnvironment) {
        lock(&self.held).insert(job_id.to_owned(), env);
    }

    /// The scripts held for `job_id`, empty when none.
    #[must_use]
    pub fn scripts(&self, job_id: &str) -> Vec<SetupScript> {
        lock(&self.held)
            .get(job_id)
            .map(|env| env.scripts().to_vec())
            .unwrap_or_default()
    }

    /// Whether `job_id` has a held environment.
    #[must_use]
    pub fn is_held(&self, job_id: &str) -> bool {
        lock(&self.held).contains_key(job_id)
    }

    /// Writes the tree of `job_id` under its existing run directory. A job with no secret the
    /// agent may see gets no tree. A failure removes what it wrote.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`]. Every refusal happens before any file is created.
    pub fn write_tree(&self, job_id: &str) -> Result<(), DeliveryError> {
        validate_job_id(job_id).map_err(|_| DeliveryError::BadPath)?;
        let plan = {
            let held = lock(&self.held);
            match held.get(job_id) {
                Some(env) => plan(env)?,
                None => return Ok(()),
            }
        };
        if plan.files.is_empty() {
            return Ok(());
        }
        let root = open_root(&self.run_root).map_err(io_err)?;
        let run = open_dir_at(root.as_fd(), job_id).map_err(io_err)?;
        if !self.mount.is_tmpfs(run.as_fd()).map_err(io_err)? {
            return Err(DeliveryError::NotTmpfs);
        }
        mkdirat(run.as_fd(), DELIVERY_DIR, self.owner.dir_mode()).map_err(io_err)?;
        let written = self.fill(run.as_fd(), &plan);
        if written.is_err() {
            let _ = remove_entry(run.as_fd(), DELIVERY_DIR, 0);
        }
        written
    }

    fn fill(&self, run: BorrowedFd<'_>, plan: &Plan) -> Result<(), DeliveryError> {
        let dir = open_dir_at(run, DELIVERY_DIR).map_err(io_err)?;
        self.chown(dir.as_fd())?;
        for (name, value) in &plan.files {
            let fd = openat(
                dir.as_fd(),
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                self.owner.file_mode(),
            )
            .map_err(io_err)?;
            self.chown(fd.as_fd())?;
            let mut file = std::fs::File::from(fd);
            file.write_all(value.as_bytes()).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
        }
        Ok(())
    }

    fn chown(&self, fd: BorrowedFd<'_>) -> Result<(), DeliveryError> {
        if self.owner.uid.is_none() && self.owner.gid.is_none() {
            return Ok(());
        }
        fchown(
            fd,
            self.owner.uid.map(Uid::from_raw),
            self.owner.gid.map(Gid::from_raw),
        )
        .map_err(io_err)
    }

    /// Shreds the tree of `job_id`, then drops what is held for it. Idempotent.
    pub fn end(&self, job_id: &str) {
        if validate_job_id(job_id).is_ok() {
            if let Some(probe) = &self.probe {
                probe(job_id);
            }
            shred_run_dir(&self.run_root, job_id);
        }
        lock(&self.held).remove(job_id);
    }

    /// The job end hook.
    pub fn end_hook(self: &Arc<Self>) -> impl Fn(&str) + Send + Sync + 'static {
        let this = Arc::clone(self);
        move |job_id| this.end(job_id)
    }
}

fn shred_run_dir(run_root: &Path, job_id: &str) {
    let Ok(root) = open_root(run_root) else {
        return;
    };
    let Ok(run) = open_dir_at(root.as_fd(), job_id) else {
        return;
    };
    shred_trees(run.as_fd());
}

fn shred_trees(run: BorrowedFd<'_>) {
    let _ = remove_entry(run, ASIDE_DIR, 0);
    if renameat(run, DELIVERY_DIR, run, ASIDE_DIR).is_ok() {
        let _ = remove_entry(run, ASIDE_DIR, 0);
    } else {
        let _ = remove_entry(run, DELIVERY_DIR, 0);
    }
}

fn remove_entry(parent: BorrowedFd<'_>, name: &str, depth: usize) -> io::Result<()> {
    let stat = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory if depth < MAX_TREE_DEPTH => {
            let dir = open_dir_at(parent, name)?;
            let _ = fchmod(dir.as_fd(), Mode::from_raw_mode(0o700));
            let names: Vec<String> = Dir::read_from(dir.as_fd())?
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|n| n != "." && n != "..")
                .collect();
            let mut result = Ok(());
            for child in names {
                if let Err(error) = remove_entry(dir.as_fd(), &child, depth + 1) {
                    result = Err(error);
                }
            }
            result?;
            Ok(unlinkat(parent, name, AtFlags::REMOVEDIR)?)
        }
        FileType::Directory => Err(io::Error::from(io::ErrorKind::InvalidData)),
        FileType::RegularFile => {
            let _ = overwrite_zero(parent, name);
            Ok(unlinkat(parent, name, AtFlags::empty())?)
        }
        _ => Ok(unlinkat(parent, name, AtFlags::empty())?),
    }
}

fn overwrite_zero(parent: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    let probe = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = fstat(&probe)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    fchmod(&probe, Mode::from_raw_mode(0o600))?;
    let fd = openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut file = std::fs::File::from(fd);
    let len = u64::try_from(stat.st_size).unwrap_or(0);
    io::copy(&mut io::repeat(0).take(len), &mut file)?;
    file.sync_all()
}

/// Removes the delivery trees of Jobs for which `live` is false, under `run_root`.
///
/// Each tree goes through the same descriptor-relative removal as [`EnvDelivery::end`]: a
/// symlink is unlinked as a link and never followed. A run directory that is itself a link, or
/// whose name is not a job id, is left alone. A missing root does nothing.
pub fn sweep_trees(run_root: &Path, live: &dyn Fn(&str) -> bool) {
    let Ok(root) = open_root(run_root) else {
        return;
    };
    let Ok(entries) = Dir::read_from(root.as_fd()) else {
        return;
    };
    let ids: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| validate_job_id(name).is_ok() && !live(name))
        .collect();
    for id in ids {
        if let Ok(run) = open_dir_at(root.as_fd(), &id) {
            shred_trees(run.as_fd());
        }
    }
}

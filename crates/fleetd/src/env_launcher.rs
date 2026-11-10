//! The production Setup launcher and the `env-setup-exec` shim (ADR-0067 decision 6).
//!
//! [`SystemdSetupLauncher`] runs one step as the unit `fleet-env@<id>.service`. Per step it
//! binds `step.sock` in the job directory `<run_root>/<id>/`, names the attempt directory in
//! the `attempt` file, binds the job socket when a [`JobSocketSetup`] is set, and starts the
//! unit with `systemctl start --no-block`. A start that fails is a [`std::io::Error`], so the
//! step is `could not start` and fails the Job.
//!
//! Inside the unit the shim ([`run_env_step`]) connects to `step.sock`, hands that socket to the
//! script as standard output and error, and runs the script through its shebang interpreter, so
//! a `noexec` run directory does not matter. The exit status is never read from the socket: it
//! is the `ExecMainStatus` that `systemctl show` reports for the unit, so a script cannot
//! forge success by writing to its output.
//!
//! The unit is stopped and its failed state reset on every end path, by the kill closure of the
//! [`StepProc`]. That closure runs `systemctl` synchronously, so it blocks the runtime thread
//! for as long as `systemctl stop` takes, at most the unit's `TimeoutStopSec`.
//!
//! The step sees `$FLEET_ENV_OUT` (the writable `out` directory of the job directory) and
//! `$FLEET_ENV_SECRETS` (the setup-only secret files). Neither is readable after the Job ends.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::agent_exec::{
    ForwardLimits, Forwarder, SYSTEM_PATH_TAIL, TOOL_PROXY_PORT, apply_proxy_env, exit_code,
};
use crate::env_setup::{OUT_DIR, SetupLauncher, StepProc, StepRun};
use crate::envd::{SETUP_SECRETS_DIR, sweep_setup_root};
use crate::jobsock::{ENV_SLICE, SOCKET_NAME};
use crate::systemd::{Ctl, DEFAULT_SYSTEMCTL, JobSocketSetup, Show, bind_socket, parse_show};
use crate::workspace::validate_job_id;

/// Parent of the per-job setup directories on a production Box.
pub const DEFAULT_RUN_ROOT: &str = "/run/fleet-env";

/// Name of the socket the step output travels on, inside the job directory.
pub const STEP_SOCKET: &str = "step.sock";

/// Name of the file that names the attempt directory to run, inside the job directory.
pub const ATTEMPT_FILE: &str = "attempt";

/// Environment variable that holds the writable output directory of a step.
pub const OUT_ENV: &str = "FLEET_ENV_OUT";

/// Environment variable that holds the setup-only secret directory of a step.
pub const SECRETS_ENV: &str = "FLEET_ENV_SECRETS";

const SCRIPT_FILE: &str = "step";
const MAX_ATTEMPT_BYTES: usize = 32;
const MAX_ATTEMPT_DIGITS: usize = 18;
const MAX_SHEBANG_BYTES: usize = 256;
const MAX_UNITS_BYTES: usize = 64 * 1024;
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const PUMP_GRACE: Duration = Duration::from_millis(300);
const PIPE_BYTES: usize = 64 * 1024;
const DEFAULT_POLL: Duration = Duration::from_millis(500);
const DEFAULT_START_DEADLINE: Duration = Duration::from_secs(60);
const UNIT_PREFIX: &str = "fleet-env@";
const UNIT_SUFFIX: &str = ".service";

/// The unit that runs the Setup steps of job `id`.
#[must_use]
pub fn env_unit_name(id: &str) -> String {
    format!("{UNIT_PREFIX}{id}{UNIT_SUFFIX}")
}

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidInput)
}

fn valid_attempt(name: &str) -> bool {
    name.strip_prefix('a').is_some_and(|digits| {
        (1..=MAX_ATTEMPT_DIGITS).contains(&digits.len())
            && digits.bytes().all(|b| b.is_ascii_digit())
    })
}

/// Starts each Setup step as the systemd unit `fleet-env@<id>.service`.
#[derive(Debug, Clone)]
pub struct SystemdSetupLauncher {
    ctl: Ctl,
    run_root: PathBuf,
    gid: Option<u32>,
    socket: Option<JobSocketSetup>,
    poll: Duration,
    start_deadline: Duration,
}

impl SystemdSetupLauncher {
    /// A launcher that runs `systemctl` and keeps job directories under `run_root`, which must
    /// be the root the [`crate::env_setup::EnvSetup`] driver uses.
    pub fn new(systemctl: impl Into<PathBuf>, run_root: impl Into<PathBuf>) -> Self {
        Self {
            ctl: Ctl::new(systemctl),
            run_root: run_root.into(),
            gid: None,
            socket: None,
            poll: DEFAULT_POLL,
            start_deadline: DEFAULT_START_DEADLINE,
        }
    }

    /// The production launcher: the default `systemctl` under [`DEFAULT_RUN_ROOT`].
    #[must_use]
    pub fn production() -> Self {
        Self::new(DEFAULT_SYSTEMCTL, DEFAULT_RUN_ROOT)
    }

    /// Shares the step socket and the job socket with `gid`, the job group.
    #[must_use]
    pub const fn with_job_gid(mut self, gid: Option<u32>) -> Self {
        self.gid = gid;
        self
    }

    /// Binds a job socket in each job directory that offers `setup`'s services, so the step
    /// reaches the egress proxy through the in-unit forwarder.
    #[must_use]
    pub fn with_job_socket(mut self, setup: JobSocketSetup) -> Self {
        self.socket = Some(setup);
        self
    }

    /// Sets how often the unit state is polled.
    #[must_use]
    pub const fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// Sets how long a started unit may stay inactive before the step fails.
    #[must_use]
    pub const fn with_start_deadline(mut self, deadline: Duration) -> Self {
        self.start_deadline = deadline;
        self
    }

    /// Whether the cgroup of the unit of `id` is the one [`ENV_SLICE`] names, as the job socket
    /// peer check expects.
    ///
    /// # Errors
    ///
    /// Fails for an invalid id or when `systemctl show` fails.
    pub async fn confirm_slice(&self, id: &str) -> io::Result<bool> {
        validate_job_id(id).map_err(|_| invalid())?;
        check_slice(&self.ctl, &env_unit_name(id)).await
    }

    /// Stops the `fleet-env@*` units of Jobs that are not `live`, then shreds every setup
    /// directory of a dead Job under the run root. Each failure is logged and skipped.
    pub async fn sweep_stale(&self, live: &(dyn Fn(&str) -> bool + Sync)) {
        match self.list_units().await {
            Ok(units) => {
                for unit in units {
                    let Some(id) = unit_id(&unit) else {
                        continue;
                    };
                    if live(id) {
                        continue;
                    }
                    let _ = self.ctl.run(&["stop", &unit]);
                    let _ = self.ctl.run(&["reset-failed", &unit]);
                    tracing::info!(job_id = id, "stopped a leftover setup unit");
                }
            }
            Err(error) => tracing::warn!(%error, "setup units could not be listed"),
        }
        sweep_setup_root(&self.run_root, live);
    }

    async fn list_units(&self) -> io::Result<Vec<String>> {
        let pattern = format!("{UNIT_PREFIX}*{UNIT_SUFFIX}");
        let mut command = tokio::process::Command::from(self.ctl.command(&[
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
            &pattern,
        ]));
        command.stdout(Stdio::piped()).kill_on_drop(true);
        let out = tokio::time::timeout(CALL_TIMEOUT, command.output())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if !out.status.success() || out.stdout.len() > MAX_UNITS_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let text = String::from_utf8(out.stdout)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(text
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|unit| unit_id(unit).is_some())
            .map(str::to_owned)
            .collect())
    }

    fn bind_step_socket(&self, job_dir: &Path) -> io::Result<StdListener> {
        let path = job_dir.join(STEP_SOCKET);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = StdListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let mode = if self.gid.is_some() { 0o660 } else { 0o600 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        if let Some(gid) = self.gid {
            std::os::unix::fs::chown(&path, None, Some(gid))?;
        }
        Ok(listener)
    }

    fn write_attempt(&self, job_dir: &Path, attempt: &str) -> io::Result<()> {
        let path = job_dir.join(ATTEMPT_FILE);
        let _ = fs::remove_file(&path);
        fs::write(&path, attempt)?;
        let mode = if self.gid.is_some() { 0o640 } else { 0o600 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        if let Some(gid) = self.gid {
            std::os::unix::fs::chown(&path, None, Some(gid))?;
        }
        Ok(())
    }
}

fn unit_id(unit: &str) -> Option<&str> {
    let id = unit.strip_prefix(UNIT_PREFIX)?.strip_suffix(UNIT_SUFFIX)?;
    validate_job_id(id).ok().map(|()| id)
}

async fn check_slice(ctl: &Ctl, unit: &str) -> io::Result<bool> {
    let group = ctl.control_group(unit).await?;
    Ok(group == format!("/{ENV_SLICE}/{unit}"))
}

struct Drive {
    ctl: Ctl,
    unit: String,
    poll: Duration,
    start_deadline: Duration,
}

impl Drive {
    async fn run(self, mut pump: JoinHandle<()>, done: oneshot::Sender<io::Result<bool>>) {
        let started = Instant::now();
        let mut checked = false;
        let result = loop {
            let shown = match self.ctl.show(&self.unit).await {
                Ok(text) => parse_show(&text, 0),
                Err(error) => Err(error),
            };
            match shown {
                Ok(Show::Ended(status)) => break Ok(status.success()),
                Ok(Show::Idle) if started.elapsed() >= self.start_deadline => {
                    break Err(io::Error::from(io::ErrorKind::TimedOut));
                }
                Ok(Show::Running) => {
                    if !checked {
                        checked = true;
                        self.log_slice().await;
                    }
                    tokio::time::sleep(self.poll).await;
                }
                Ok(Show::Idle) => tokio::time::sleep(self.poll).await,
                Err(error) => break Err(error),
            }
        };
        let _ = tokio::time::timeout(PUMP_GRACE, &mut pump).await;
        let _ = done.send(result);
    }

    async fn log_slice(&self) {
        match check_slice(&self.ctl, &self.unit).await {
            Ok(true) => tracing::info!(unit = %self.unit, "setup unit runs in the env slice"),
            Ok(false) => tracing::warn!(
                unit = %self.unit,
                expected = ENV_SLICE,
                "setup unit is not in the env slice: its egress peer check will refuse it"
            ),
            Err(error) => tracing::warn!(%error, "setup unit cgroup could not be read"),
        }
    }
}

impl SetupLauncher for SystemdSetupLauncher {
    fn start(&self, run: &StepRun<'_>) -> io::Result<StepProc> {
        validate_job_id(run.job_id).map_err(|_| invalid())?;
        if !self.ctl.is_absolute() || !self.run_root.is_absolute() {
            return Err(invalid());
        }
        let job_dir = run.scratch.parent().ok_or_else(invalid)?;
        if job_dir != self.run_root.join(run.job_id) {
            return Err(invalid());
        }
        let attempt = run
            .scratch
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_attempt(name))
            .ok_or_else(invalid)?;
        let listener = tokio::net::UnixListener::from_std(self.bind_step_socket(job_dir)?)?;
        self.write_attempt(job_dir, attempt)?;
        let job_socket = bind_socket(self.socket.as_ref(), &self.run_root, self.gid, run.job_id)?;
        let unit = env_unit_name(run.job_id);
        self.ctl.run(&["start", "--no-block", &unit])?;
        let (mut writer, output) = tokio::io::duplex(PIPE_BYTES);
        let pump = tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                let _ = tokio::io::copy(&mut conn, &mut writer).await;
            }
        });
        let pump_abort = pump.abort_handle();
        let (done, exit) = oneshot::channel();
        let drive = Drive {
            ctl: self.ctl.clone(),
            unit: unit.clone(),
            poll: self.poll,
            start_deadline: self.start_deadline,
        };
        let driver = tokio::spawn(async move {
            let _socket = job_socket;
            drive.run(pump, done).await;
        });
        let driver_abort = driver.abort_handle();
        let ctl = self.ctl.clone();
        Ok(StepProc {
            output: Box::pin(output),
            exit: Box::pin(async move {
                exit.await
                    .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }),
            kill: Box::new(move || {
                driver_abort.abort();
                let _ = ctl.run(&["kill", "--kill-whom=all", "--signal=SIGKILL", &unit]);
                let _ = ctl.run(&["stop", &unit]);
                let _ = ctl.run(&["reset-failed", &unit]);
                pump_abort.abort();
            }),
        })
    }
}

/// Why `env-setup-exec` did not run its step. Display text is fixed and holds no path or
/// environment value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvExecError {
    /// The job id is not `[A-Za-z0-9_]{1,64}`.
    InvalidId,
    /// The `attempt` file does not name an attempt directory.
    BadAttempt,
    /// The step script is missing or does not start with a `#!/` interpreter line.
    BadScript,
    /// The egress forwarder could not listen on the loopback.
    Listen(io::ErrorKind),
    /// The step socket could not be reached.
    Connect(io::ErrorKind),
    /// The interpreter could not be executed.
    Exec(io::ErrorKind),
}

impl fmt::Display for EnvExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId => f.write_str("job id is not valid"),
            Self::BadAttempt => f.write_str("step attempt is not valid"),
            Self::BadScript => f.write_str("step script is not valid"),
            Self::Listen(kind) => write!(f, "egress forwarder could not listen: {kind}"),
            Self::Connect(kind) => write!(f, "step output socket could not be reached: {kind}"),
            Self::Exec(kind) => write!(f, "step could not be executed: {kind}"),
        }
    }
}

impl std::error::Error for EnvExecError {}

fn read_capped(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(u64::try_from(cap + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_attempt(job_dir: &Path) -> Result<String, EnvExecError> {
    let bytes = read_capped(&job_dir.join(ATTEMPT_FILE), MAX_ATTEMPT_BYTES)
        .map_err(|_| EnvExecError::BadAttempt)?;
    let name = String::from_utf8(bytes).map_err(|_| EnvExecError::BadAttempt)?;
    if valid_attempt(&name) {
        Ok(name)
    } else {
        Err(EnvExecError::BadAttempt)
    }
}

fn read_interpreter(script: &Path) -> Result<Vec<String>, EnvExecError> {
    let bytes = read_capped(script, MAX_SHEBANG_BYTES).map_err(|_| EnvExecError::BadScript)?;
    let line = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = std::str::from_utf8(line).map_err(|_| EnvExecError::BadScript)?;
    let rest = line.strip_prefix("#!").ok_or(EnvExecError::BadScript)?;
    if rest.bytes().any(|b| b == 0 || b == b'\r') || !rest.starts_with('/') {
        return Err(EnvExecError::BadScript);
    }
    let words: Vec<String> = rest.split_whitespace().map(str::to_owned).collect();
    if words.is_empty() || words.len() > 2 {
        return Err(EnvExecError::BadScript);
    }
    Ok(words)
}

/// Runs the step the `attempt` file of `run_root/<id>` names, with its output on `step.sock`,
/// and returns its exit code.
///
/// The script runs through the interpreter its first line names, in the `out` directory, with
/// a cleared environment: `PATH`, `HOME`, [`OUT_ENV`], [`SECRETS_ENV`] and, when a `job.sock`
/// exists, the proxy variables of an egress [`Forwarder`] bound on `addr` that dials only that
/// socket. Every input is checked before the forwarder or the socket is touched.
///
/// # Errors
///
/// Returns [`EnvExecError`] when an input is invalid, the socket cannot be reached, the
/// forwarder cannot listen or the interpreter cannot be executed.
pub fn run_env_step(run_root: &Path, id: &str, addr: SocketAddr) -> Result<i32, EnvExecError> {
    if validate_job_id(id).is_err() {
        return Err(EnvExecError::InvalidId);
    }
    let job_dir = run_root.join(id);
    let attempt = read_attempt(&job_dir)?;
    let script = job_dir.join(&attempt).join(SCRIPT_FILE);
    let words = read_interpreter(&script)?;
    let (program, args) = words.split_first().ok_or(EnvExecError::BadScript)?;
    let stdout = UnixStream::connect(job_dir.join(STEP_SOCKET))
        .map_err(|error| EnvExecError::Connect(error.kind()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|error| EnvExecError::Connect(error.kind()))?;
    let out = job_dir.join(OUT_DIR);
    let mut command = Command::new(program);
    command
        .args(args)
        .arg(&script)
        .env_clear()
        .env("PATH", SYSTEM_PATH_TAIL)
        .env("HOME", &out)
        .env(OUT_ENV, &out)
        .env(SECRETS_ENV, job_dir.join(SETUP_SECRETS_DIR))
        .current_dir(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(stdout)))
        .stderr(Stdio::from(OwnedFd::from(stderr)));
    let socket = job_dir.join(SOCKET_NAME);
    let forwarder = if fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket())
    {
        let uid = fs::metadata(&job_dir).map_or(u32::MAX, |meta| meta.uid());
        let forwarder = Forwarder::start_on(addr, socket, uid, ForwardLimits::default())
            .map_err(|error| EnvExecError::Listen(error.kind()))?;
        apply_proxy_env(
            &mut command,
            &format!("http://127.0.0.1:{}", forwarder.port()),
        );
        Some(forwarder)
    } else {
        None
    };
    let mut child = command
        .spawn()
        .map_err(|error| EnvExecError::Exec(error.kind()))?;
    let code = child.wait().map_or(1, exit_code);
    drop(forwarder);
    Ok(code)
}

/// Runs the step for `id` and exits this process with its exit code.
///
/// Only returns on failure, with the reason. The forwarder listens on [`TOOL_PROXY_PORT`].
pub fn exec_env_setup(run_root: &Path, id: &str) -> EnvExecError {
    let addr = SocketAddr::from(([127, 0, 0, 1], TOOL_PROXY_PORT));
    match run_env_step(run_root, id, addr) {
        Ok(code) => std::process::exit(code),
        Err(error) => error,
    }
}

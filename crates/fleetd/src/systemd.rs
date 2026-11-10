//! Runs the agent as a `fleet-agent@<id>.service` unit through `systemctl`.
//!
//! Per job the launcher makes `<run_dir>/<id>/` holding the env file (0600), the stdout
//! FIFO and `spec.json`, then starts the unit without waiting. The unit is delivered
//! separately and runs `fleetd agent-exec <id>` as the job uid. Every `systemctl` call uses
//! the configured absolute path with an argv array and an empty environment.
//!
//! With a [`JobSocketSetup`] the launcher also binds the job socket (ADR-0036) inside that
//! dir after the FIFO and before `start`, so the unit never runs without it. The launcher
//! closes the socket as soon as the unit has ended and before `stop`, so it is unlinked
//! before the dir is removed, on every path: poll end, failed start and drop.
//!
//! The unit sets `RemainAfterExit=yes`, so a clean exit stays `active (exited)`. The launcher
//! reads that as ended, then runs `stop` and `reset-failed` before it reports the result.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::io::Read;
use std::num::NonZeroU16;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::net::unix::pipe::Receiver;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use fleet_core::tools::{ToolName, ToolSpec};

use crate::agent_exec::{SPEC_FILE, TOOL_PROXY_PORT, write_spec_telemetry};
use crate::config::{AgentLauncher, Config};
use crate::envd::EnvDelivery;
use crate::fetch_policy::HostPattern;
use crate::jobenv::{create_stdout_fifo, open_fifo_reader, render_env_file, write_env_file};
use crate::jobsock::{JobSocket, Limits, Peer, ProcPeer, ServiceName, Services, socket_path};
use crate::runner::{
    AgentProc, AgentSpec, DirectLauncher, InstallFuture, Launched, Launcher, TelemetryCapture,
    ToolInstaller,
};
use crate::tools::{
    MAX_CACHE_ENTRIES, check_tool_hosts, tool_hosts, write_mise_toml, write_tool_env,
};
use crate::workspace::validate_job_id;

/// Default parent of the per-job run directories.
pub const DEFAULT_RUN_DIR: &str = "/run/fleet";
/// Default `systemctl` binary.
pub const DEFAULT_SYSTEMCTL: &str = "/usr/bin/systemctl";

const DEFAULT_POLL: Duration = Duration::from_millis(500);
const DEFAULT_START_DEADLINE: Duration = Duration::from_secs(60);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const SHOW_CAP: usize = 4096;
/// Mode of the per-job run dir. With no `job_gid` set the job uid is neither owner nor group,
/// so it cannot read `spec.json` under this mode.
const DIR_MODE: u32 = 0o750;
const DEFAULT_INSTALL_RUN_DEADLINE: Duration = Duration::from_secs(16 * 60);
const HOOK_DIR: &str = "hook";
const ENV_FILE: &str = "env";
const STDOUT_FIFO: &str = "stdout";
const JOB_ID_ENV: &str = "FLEET_JOB_ID";
const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;
const MAX_SIGNAL: i32 = 64;

/// The one log line written when a job socket is asked for in direct mode (ADR-0036).
pub const JOB_SOCKET_REFUSED: &str = "job socket refused: agent_launcher is direct";

/// The one log line written when the systemd launcher starts with no services registered.
pub const NO_SERVICES_WARNING: &str = "agent_launcher is systemd and no services are registered: the unit sets PrivateNetwork=yes, so jobs cannot reach the model API";

/// The one error text of a job whose install hosts the Box egress list does not cover.
pub const TOOL_HOSTS_REFUSED: &str = "tool install hosts are not covered by egress_allow";

/// The tools of one job, looked up by job id. An empty list means no install.
pub type ToolLookup = Arc<dyn Fn(&str) -> Vec<ToolName> + Send + Sync>;

/// What the launcher needs to prepare the tool install unit of each job (ADR-0048).
///
/// Before the unit starts, the launcher requires `egress_allow` to hold every host of the
/// job's tools ([`check_tool_hosts`]) and writes `tool-env` into the run dir
/// ([`write_tool_env`]). A refusal fails the launch before any directory or unit exists.
#[derive(Clone)]
pub struct ToolInstallSetup {
    tools: ToolLookup,
    egress_allow: Vec<String>,
}

impl ToolInstallSetup {
    /// A setup that asks `tools` for each job and checks against `egress_allow`, the exact host
    /// names of the Box egress list. A wildcard entry is not an exact name and must be left out.
    /// A job whose lookup returns no tools needs no host, so the host check is vacuous and
    /// passes for it, even on an empty list. An entry that is not a plain DNS name still fails.
    #[must_use]
    pub fn new(tools: ToolLookup, egress_allow: Vec<String>) -> Self {
        Self {
            tools,
            egress_allow,
        }
    }
}

impl std::fmt::Debug for ToolInstallSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolInstallSetup")
            .field("egress_allow", &self.egress_allow.len())
            .finish_non_exhaustive()
    }
}

/// The launcher the config selects.
///
/// With the systemd launcher every job gets a socket that offers `services`, which may be
/// empty. The direct launcher makes no socket: when `services` is not empty it logs
/// [`JOB_SOCKET_REFUSED`] once and drops them, because the agent there shares fleetd's uid and
/// reads its environment, so a peer check adds nothing. The systemd launcher with no services
/// logs [`NO_SERVICES_WARNING`] once, because the unit's `PrivateNetwork=yes` leaves the job
/// without the egress proxy. The systemd launcher gets telemetry capture only when
/// [`Config::require_host_netns`] succeeds. Otherwise it logs the refusal and runs with none.
#[must_use]
pub fn select_launcher(
    config: &Config,
    job_gid: Option<u32>,
    services: Services,
) -> Arc<dyn Launcher> {
    select_launcher_delivering(config, job_gid, services, None)
}

/// [`select_launcher`] with the Environment delivery of the systemd launcher. The direct
/// launcher ignores it: its agent shares the fleetd uid, so no tree can keep a value from it.
#[must_use]
pub fn select_launcher_delivering(
    config: &Config,
    job_gid: Option<u32>,
    services: Services,
    delivery: Option<Arc<EnvDelivery>>,
) -> Arc<dyn Launcher> {
    match config.agent_launcher {
        AgentLauncher::Direct => {
            if !services.is_empty() {
                tracing::warn!("{JOB_SOCKET_REFUSED}");
            }
            Arc::new(DirectLauncher)
        }
        AgentLauncher::Systemd => {
            if services.is_empty() {
                tracing::warn!("{NO_SERVICES_WARNING}");
            }
            let mut launcher = SystemdLauncher::new(&config.systemctl_path)
                .with_job_gid(job_gid)
                .with_run_timeout(config.agent_timeout)
                .with_job_socket(JobSocketSetup::new(services));
            if let Some(delivery) = delivery {
                launcher = launcher.with_delivery(delivery);
            }
            match config.require_host_netns() {
                Ok(()) => {
                    launcher = launcher
                        .with_telemetry(TelemetrySetup::new(crate::otel::Limits::default()));
                }
                Err(refused) => tracing::warn!("{refused}"),
            }
            Arc::new(if tool_install_configured(config) {
                launcher.with_tool_install(ToolInstallSetup::new(
                    Arc::new(|_| Vec::new()),
                    exact_egress_hosts(config),
                ))
            } else {
                launcher
            })
        }
    }
}

fn tool_install_configured(config: &Config) -> bool {
    config.mise_pins().is_ok_and(|pins| pins.is_some())
}

fn exact_egress_hosts(config: &Config) -> Vec<String> {
    config
        .egress_allow
        .iter()
        .filter_map(|pattern| match pattern {
            HostPattern::Exact(host) => Some(host.clone()),
            HostPattern::Subdomain(_) => None,
        })
        .collect()
}

/// The production [`ToolInstaller`]: `Some` only when the config selects the systemd launcher
/// and holds valid `[mise]` pins, else `None` and every missing tool fails the pre-flight.
///
/// `services` are the job socket services the install unit may select (only the egress proxy is
/// accepted for it), `hosts` receives the job id and the install hosts before the unit starts.
#[must_use]
pub fn select_tool_installer(
    config: &Config,
    job_gid: Option<u32>,
    services: Services,
    hosts: Option<HostsHook>,
) -> Option<Arc<dyn ToolInstaller>> {
    if config.agent_launcher != AgentLauncher::Systemd || !tool_install_configured(config) {
        return None;
    }
    let mut installer =
        SystemdToolInstaller::new(&config.systemctl_path, exact_egress_hosts(config))
            .with_job_gid(job_gid)
            .with_job_socket(JobSocketSetup::new(services));
    if let Some(hosts) = hosts {
        installer = installer.with_hosts_hook(hosts);
    }
    Some(Arc::new(installer))
}

/// What the launcher needs to bind the job socket of each job.
#[derive(Clone)]
pub struct JobSocketSetup {
    /// The services the socket offers by handshake name.
    pub services: Services,
    /// How the identity of a connecting peer is read.
    pub peer: Arc<dyn Peer>,
    /// The connection and handshake limits.
    pub limits: Limits,
}

impl JobSocketSetup {
    /// The production setup: peers read through `/proc` and the default limits.
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self {
            services,
            peer: Arc::new(ProcPeer),
            limits: Limits::default(),
        }
    }
}

impl std::fmt::Debug for JobSocketSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobSocketSetup")
            .field("services", &self.services.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Removes the run dirs a crashed fleetd left under `run_dir` when the config selects the
/// systemd launcher. The direct launcher leaves them alone. Never fails: each problem is logged.
pub async fn sweep_stale_runs(config: &Config, run_dir: &Path) {
    if config.agent_launcher == AgentLauncher::Systemd {
        SystemdLauncher::new(&config.systemctl_path)
            .with_run_dir(run_dir)
            .sweep_stale()
            .await;
    }
}

/// Starts each agent as a systemd unit.
#[derive(Debug, Clone)]
pub struct SystemdLauncher {
    ctl: Ctl,
    run_dir: PathBuf,
    poll: Duration,
    start_deadline: Duration,
    run_timeout: Option<Duration>,
    gid: Option<u32>,
    socket: Option<JobSocketSetup>,
    tool_install: Option<ToolInstallSetup>,
    telemetry: Option<TelemetrySetup>,
    delivery: Option<Arc<EnvDelivery>>,
}

/// Source of a nonzero port for the in-namespace telemetry forwarder.
pub type PortSource = Arc<dyn Fn() -> io::Result<NonZeroU16> + Send + Sync>;

/// Source of a fresh bearer token for one job's receiver.
pub type TokenSource = Arc<dyn Fn() -> io::Result<String> + Send + Sync>;

/// Enables the per-job OTLP receiver in a [`SystemdLauncher`].
///
/// The launcher asks `port` for the forwarder port and `token` for the bearer token. When
/// either fails, or the receiver cannot bind, the job runs with no capture and the spec names
/// no port: capture never fails a job.
#[derive(Clone)]
pub struct TelemetrySetup {
    port: PortSource,
    token: TokenSource,
    limits: crate::otel::Limits,
}

impl TelemetrySetup {
    /// Setup with an ephemeral nonzero port and a 192-bit random token.
    #[must_use]
    pub fn new(limits: crate::otel::Limits) -> Self {
        Self {
            port: Arc::new(ephemeral_port),
            token: Arc::new(random_token),
            limits,
        }
    }

    /// Replaces the port source.
    #[must_use]
    pub fn with_port_source(mut self, port: PortSource) -> Self {
        self.port = port;
        self
    }

    /// Replaces the token source.
    #[must_use]
    pub fn with_token_source(mut self, token: TokenSource) -> Self {
        self.token = token;
        self
    }
}

impl std::fmt::Debug for TelemetrySetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetrySetup")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn ephemeral_port() -> io::Result<NonZeroU16> {
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    NonZeroU16::new(port).ok_or_else(|| io::Error::other("ephemeral port is zero"))
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0_u8; 24];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    Ok(token)
}

struct Telemetry {
    port: NonZeroU16,
    token: String,
    vars: crate::agent::TelemetryEnv,
    receiver: crate::otel::OtelReceiver,
    bodies: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

fn safe_token(token: &str) -> bool {
    token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn start_telemetry(setup: &TelemetrySetup, dir: &Path, gid: Option<u32>) -> io::Result<Telemetry> {
    let port = (setup.port)()?;
    let token = (setup.token)()?;
    if !safe_token(&token) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let vars = crate::agent::TelemetryEnv::new(port, &token)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let bearer = crate::otel::BearerToken::new(&token)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let (receiver, bodies) = crate::otel::OtelReceiver::bind(
        &dir.join(crate::otel::SOCKET_NAME),
        bearer,
        gid,
        setup.limits,
    )?;
    Ok(Telemetry {
        port,
        token,
        vars,
        receiver,
        bodies,
    })
}

impl SystemdLauncher {
    /// Binds a receiver in each run dir for a Claude job and writes its port into the spec.
    ///
    /// Only a job whose [`AgentSpec::otel`] is set gets a receiver. The launcher then adds the
    /// `OTel` exporter variables to the env file, so the token stays out of argv and the spec. A
    /// token source that returns a byte outside `[A-Za-z0-9_-]` starts no capture.
    ///
    /// The receiver socket is owned by the fleetd uid with the job group and mode 0660, the
    /// group set by [`Self::with_job_gid`].
    #[must_use]
    pub fn with_telemetry(mut self, setup: TelemetrySetup) -> Self {
        self.telemetry = Some(setup);
        self
    }
}

impl SystemdLauncher {
    /// A launcher that runs `systemctl`, an absolute path, under [`DEFAULT_RUN_DIR`].
    pub fn new(systemctl: impl Into<PathBuf>) -> Self {
        Self {
            ctl: Ctl {
                systemctl: systemctl.into(),
            },
            run_dir: PathBuf::from(DEFAULT_RUN_DIR),
            poll: DEFAULT_POLL,
            start_deadline: DEFAULT_START_DEADLINE,
            run_timeout: None,
            gid: None,
            socket: None,
            tool_install: None,
            telemetry: None,
            delivery: None,
        }
    }

    /// Writes the Environment delivery tree of each job into its run dir before its unit starts.
    /// A failed write fails the launch and removes the run dir.
    #[must_use]
    pub fn with_delivery(mut self, delivery: Arc<EnvDelivery>) -> Self {
        self.delivery = Some(delivery);
        self
    }

    /// Writes `tool-env` and checks the install hosts before each unit start.
    #[must_use]
    pub fn with_tool_install(mut self, setup: ToolInstallSetup) -> Self {
        self.tool_install = Some(setup);
        self
    }

    /// Binds a job socket in each run dir, offering the services in `setup`.
    #[must_use]
    pub fn with_job_socket(mut self, setup: JobSocketSetup) -> Self {
        self.socket = Some(setup);
        self
    }

    /// Puts the per-job run directories under `run_dir`.
    #[must_use]
    pub fn with_run_dir(mut self, run_dir: impl Into<PathBuf>) -> Self {
        self.run_dir = run_dir.into();
        self
    }

    /// Sets how often the unit state is polled.
    #[must_use]
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// Sets how long a unit may stay inactive without having run before the start counts as failed.
    #[must_use]
    pub fn with_start_deadline(mut self, deadline: Duration) -> Self {
        self.start_deadline = deadline;
        self
    }

    /// Sets the run deadline. A unit that ends by a signal after it has passed reads as
    /// timed out through [`AgentProc::timed_out`], as the unit's own timeout does. That includes
    /// a real crash such as `SIGSEGV`. The deadline is checked when the poller sees the unit end,
    /// so the verdict can be one 500 ms poll late.
    #[must_use]
    pub fn with_run_timeout(mut self, timeout: Duration) -> Self {
        self.run_timeout = Some(timeout);
        self
    }

    /// Removes every run dir under the run root, which at startup belongs to no live job of
    /// this process. Only real directories named like a job id are touched, never symlinks,
    /// files, the `hook` dir or any other name. A unit still active for the id is stopped and
    /// reset first, and a failed unit is reset. A failure is logged and the sweep goes on.
    pub async fn sweep_stale(&self) {
        if !self.ctl.systemctl.is_absolute() {
            tracing::warn!("run dir sweep skipped: systemctl path is not absolute");
            return;
        }
        let entries = match fs::read_dir(&self.run_dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                tracing::warn!(%err, "run dir sweep skipped: cannot list the run root");
                return;
            }
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            if !is_dir || id == HOOK_DIR || validate_job_id(&id).is_err() {
                continue;
            }
            self.sweep_one(&id, entry.path()).await;
        }
    }

    async fn sweep_one(&self, id: &str, path: PathBuf) {
        let unit = unit_name(id);
        match self.ctl.show(&unit).await {
            Ok(text) if is_live(&text) => {
                tracing::warn!(job_id = %id, "stopping a unit left by a crash");
                self.ctl.stop(&unit).await;
                self.ctl.reset_failed(&unit).await;
            }
            Ok(text) if is_failed(&text) => {
                tracing::warn!(job_id = %id, "resetting a failed unit left by a crash");
                self.ctl.reset_failed(&unit).await;
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(job_id = %id, %err, "stale run dir kept: unit state unknown");
                return;
            }
        }
        drop(RunDir(path.clone()));
        if path.exists() {
            tracing::warn!(job_id = %id, "stale run dir could not be removed");
        } else {
            tracing::info!(job_id = %id, "removed a stale run dir");
        }
    }

    /// Shares the run directory, the FIFO and the spec with `gid`, the job group.
    #[must_use]
    pub fn with_job_gid(mut self, gid: Option<u32>) -> Self {
        self.gid = gid;
        self
    }
}

#[derive(Debug, Clone)]
struct Ctl {
    systemctl: PathBuf,
}

impl Ctl {
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.systemctl);
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> io::Result<()> {
        if self.command(args).status()?.success() {
            Ok(())
        } else {
            Err(io::Error::other("systemctl failed"))
        }
    }

    async fn show(&self, unit: &str) -> io::Result<String> {
        let mut command = tokio::process::Command::from(self.command(&[
            "show",
            unit,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "Result",
            "-p",
            "ExecMainCode",
            "-p",
            "ExecMainStatus",
        ]));
        command.stdout(Stdio::piped()).kill_on_drop(true);
        let out = tokio::time::timeout(CALL_TIMEOUT, command.output())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if !out.status.success() || out.stdout.len() > SHOW_CAP {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        String::from_utf8(out.stdout).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }

    async fn start(&self, unit: &str) -> io::Result<()> {
        let mut command =
            tokio::process::Command::from(self.command(&["start", "--no-block", unit]));
        command.kill_on_drop(true);
        let status = tokio::time::timeout(CALL_TIMEOUT, command.status())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("systemctl failed"))
        }
    }

    async fn kill_unit(&self, unit: &str) {
        let mut command = tokio::process::Command::from(self.command(&[
            "kill",
            "--kill-whom=all",
            "--signal=SIGKILL",
            unit,
        ]));
        command.kill_on_drop(true);
        let _ = tokio::time::timeout(CALL_TIMEOUT, command.status()).await;
    }

    async fn stop(&self, unit: &str) {
        let mut command = tokio::process::Command::from(self.command(&["stop", unit]));
        command.kill_on_drop(true);
        let _ = tokio::time::timeout(CALL_TIMEOUT, command.status()).await;
    }

    async fn reset_failed(&self, unit: &str) {
        let mut command = tokio::process::Command::from(self.command(&["reset-failed", unit]));
        command.kill_on_drop(true);
        let _ = tokio::time::timeout(CALL_TIMEOUT, command.status()).await;
    }
}

fn is_live(show: &str) -> bool {
    show.lines()
        .filter_map(|line| line.strip_prefix("ActiveState="))
        .any(|state| !matches!(state, "inactive" | "failed"))
}

fn is_failed(show: &str) -> bool {
    show.lines()
        .filter_map(|line| line.strip_prefix("ActiveState="))
        .any(|state| state == "failed")
}

fn unit_name(id: &str) -> String {
    format!("fleet-agent@{id}.service")
}

#[derive(Debug)]
struct RunDir(PathBuf);

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fail<T>(kind: io::ErrorKind) -> io::Result<T> {
    Err(io::Error::from(kind))
}

impl SystemdLauncher {
    fn checked_tools(&self, id: &str) -> io::Result<Vec<ToolName>> {
        let Some(setup) = &self.tool_install else {
            return Ok(Vec::new());
        };
        let tools = (setup.tools)(id);
        check_tool_hosts(&setup.egress_allow, &tools)
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, TOOL_HOSTS_REFUSED))?;
        Ok(tools)
    }

    fn bind_job_socket(&self, id: &str) -> io::Result<Option<JobSocket>> {
        bind_socket(self.socket.as_ref(), &self.run_dir, self.gid, id)
    }
}

/// Binds the job socket for `id` under `run_dir`, then sets its group to `gid` when one is given.
///
/// The group change follows the bind, so the socket briefly keeps the fleetd group. The run dir
/// is mode-restricted, so no job uid can reach it in that window.
fn bind_socket(
    setup: Option<&JobSocketSetup>,
    run_dir: &Path,
    gid: Option<u32>,
    id: &str,
) -> io::Result<Option<JobSocket>> {
    let Some(setup) = setup else {
        return Ok(None);
    };
    let path =
        socket_path(run_dir, id).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let socket = JobSocket::bind(
        &path,
        id,
        setup.services.clone(),
        Arc::clone(&setup.peer),
        setup.limits,
    )?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(&path, None, Some(gid))?;
    }
    Ok(Some(socket))
}

impl Launcher for SystemdLauncher {
    fn job_services(&self) -> Vec<ServiceName> {
        self.socket
            .as_ref()
            .map(|setup| setup.services.keys().copied().collect())
            .unwrap_or_default()
    }

    fn launch(&self, mut spec: AgentSpec) -> io::Result<Launched> {
        let id = spec
            .env
            .get(std::ffi::OsStr::new(JOB_ID_ENV))
            .and_then(|id| id.to_str())
            .filter(|id| validate_job_id(id).is_ok())
            .map(str::to_owned);
        let Some(id) = id else {
            return fail(io::ErrorKind::InvalidInput);
        };
        if !self.ctl.systemctl.is_absolute() {
            return fail(io::ErrorKind::InvalidInput);
        }
        let tools = self.checked_tools(&id)?;
        fs::create_dir_all(&self.run_dir)?;
        let dir = self.run_dir.join(&id);
        fs::DirBuilder::new().mode(DIR_MODE).create(&dir)?;
        let guard = RunDir(dir.clone());
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?;
        if let Some(gid) = self.gid {
            std::os::unix::fs::chown(&dir, None, Some(gid))?;
        }
        let telemetry = self
            .telemetry
            .as_ref()
            .filter(|_| spec.otel)
            .and_then(|setup| {
                start_telemetry(setup, &dir, self.gid)
                    .inspect_err(|err| {
                        tracing::warn!(kind = ?err.kind(), "telemetry capture not started");
                    })
                    .ok()
            });
        if let Some(capture) = &telemetry {
            capture.vars.apply(&mut spec.env);
        }
        let body =
            render_env_file(&spec).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        write_env_file(&dir.join(ENV_FILE), &body)?;
        write_spec_telemetry(
            &dir.join(SPEC_FILE),
            &id,
            &spec,
            self.gid,
            telemetry.as_ref().map(|capture| capture.port),
        )?;
        write_tool_env(&self.run_dir, &id, TOOL_PROXY_PORT, &tools)
            .map_err(|err| io::Error::other(err.to_string()))?;
        if let Some(delivery) = &self.delivery {
            delivery.write_tree(&id).map_err(io::Error::other)?;
        }
        let fifo = dir.join(STDOUT_FIFO);
        create_stdout_fifo(&fifo, self.gid)?;
        let reader = Receiver::from_file(open_fifo_reader(&fifo)?)?;
        let keepalive = fs::OpenOptions::new().write(true).open(&fifo)?;
        let socket = self.bind_job_socket(&id)?;
        let unit = unit_name(&id);
        self.ctl.run(&["start", "--no-block", &unit])?;
        let (receiver, capture) = match telemetry {
            Some(Telemetry {
                port,
                token,
                receiver,
                bodies,
                ..
            }) => (
                Some(receiver),
                Some(TelemetryCapture {
                    port,
                    token,
                    bodies,
                }),
            ),
            None => (None, None),
        };
        Ok(Launched {
            telemetry: capture,
            stdout: Box::new(reader),
            proc: Box::new(SystemdProc {
                _receiver: receiver,
                ctl: self.ctl.clone(),
                unit,
                poll: self.poll,
                start_deadline: self.start_deadline,
                run_timeout: self.run_timeout,
                launched: Instant::now(),
                keepalive: Some(keepalive),
                shared: Arc::new(Shared::with_socket(socket)),
                result: None,
                task: None,
                dir: guard,
            }),
        })
    }
}

type Outcome = Result<ExitStatus, io::ErrorKind>;

#[derive(Debug, Default)]
struct Shared {
    sent: AtomicI32,
    cleaned: AtomicBool,
    timed_out: AtomicBool,
    socket: Mutex<Option<JobSocket>>,
}

impl Shared {
    fn with_socket(socket: Option<JobSocket>) -> Self {
        Self {
            socket: Mutex::new(socket),
            ..Self::default()
        }
    }

    fn cancel_socket(&self) {
        if let Some(socket) = self
            .socket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            socket.cancel();
        }
    }

    fn close_socket(&self) {
        let socket = self
            .socket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(socket);
    }
}

struct SystemdProc {
    _receiver: Option<crate::otel::OtelReceiver>,
    ctl: Ctl,
    unit: String,
    poll: Duration,
    start_deadline: Duration,
    run_timeout: Option<Duration>,
    launched: Instant,
    keepalive: Option<fs::File>,
    shared: Arc<Shared>,
    result: Option<watch::Receiver<Option<Outcome>>>,
    task: Option<JoinHandle<()>>,
    dir: RunDir,
}

struct Poller {
    ctl: Ctl,
    unit: String,
    poll: Duration,
    deadline: Instant,
    run_deadline: Option<Instant>,
    shared: Arc<Shared>,
}

impl Poller {
    async fn watch(&self) -> Outcome {
        loop {
            let sent = self.shared.sent.load(Ordering::SeqCst);
            let shown = match self.ctl.show(&self.unit).await {
                Ok(text) => parse_show(&text, sent),
                Err(err) => Err(err),
            };
            match shown {
                Ok(Show::Idle) if Instant::now() >= self.deadline => {
                    break Err(io::ErrorKind::TimedOut);
                }
                Ok(Show::Running | Show::Idle) => tokio::time::sleep(self.poll).await,
                Ok(Show::Ended(status)) => {
                    let late = self.run_deadline.is_some_and(|at| Instant::now() >= at);
                    self.shared
                        .timed_out
                        .store(late && status.signal().is_some(), Ordering::SeqCst);
                    break Ok(status);
                }
                Err(err) => break Err(err.kind()),
            }
        }
    }

    async fn run(
        self,
        keepalive: Option<fs::File>,
        dir: PathBuf,
        tx: watch::Sender<Option<Outcome>>,
    ) {
        let outcome = self.watch().await;
        self.shared.close_socket();
        drop(keepalive);
        self.ctl.stop(&self.unit).await;
        self.ctl.reset_failed(&self.unit).await;
        let _ = fs::remove_dir_all(&dir);
        self.shared.cleaned.store(true, Ordering::SeqCst);
        let _ = tx.send(Some(outcome));
    }
}

impl SystemdProc {
    fn start_polling(&mut self) -> watch::Receiver<Option<Outcome>> {
        if let Some(rx) = &self.result {
            return rx.clone();
        }
        let (tx, rx) = watch::channel(None);
        let poller = Poller {
            ctl: self.ctl.clone(),
            unit: self.unit.clone(),
            poll: self.poll,
            deadline: self.launched + self.start_deadline,
            run_deadline: self.run_timeout.map(|timeout| self.launched + timeout),
            shared: Arc::clone(&self.shared),
        };
        let keepalive = self.keepalive.take();
        let dir = self.dir.0.clone();
        self.task = Some(tokio::spawn(poller.run(keepalive, dir, tx)));
        self.result = Some(rx.clone());
        rx
    }

    fn signal(&self, name: &str, number: i32) {
        if !self.shared.cleaned.load(Ordering::SeqCst) {
            self.shared.sent.store(number, Ordering::SeqCst);
            let _ = self.ctl.run(&[
                "kill",
                "--kill-whom=all",
                &format!("--signal={name}"),
                &self.unit,
            ]);
        }
    }
}

impl AgentProc for SystemdProc {
    fn wait(&mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + '_>> {
        let mut rx = self.start_polling();
        Box::pin(async move {
            let outcome = rx
                .wait_for(Option::is_some)
                .await
                .map_err(|_| io::Error::other("unit poller stopped"))?;
            (*outcome)
                .ok_or_else(|| io::Error::other("unit poller stopped"))?
                .map_err(io::Error::from)
        })
    }

    fn terminate(&mut self) {
        self.signal("SIGTERM", SIGTERM);
    }

    fn kill(&mut self) {
        self.signal("SIGKILL", SIGKILL);
    }

    fn timed_out(&self) -> bool {
        self.shared.timed_out.load(Ordering::SeqCst)
    }

    fn cancel_services(&self) {
        self.shared.cancel_socket();
    }
}

impl Drop for SystemdProc {
    fn drop(&mut self) {
        self.shared.close_socket();
        if let Some(task) = &self.task {
            task.abort();
        }
        if !self.shared.cleaned.load(Ordering::SeqCst) {
            let _ = self
                .ctl
                .run(&["kill", "--kill-whom=all", "--signal=SIGKILL", &self.unit]);
            let _ = self.ctl.run(&["reset-failed", &self.unit]);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Show {
    Running,
    Idle,
    Ended(ExitStatus),
}

fn bad() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

fn parse_show(text: &str, sent: i32) -> io::Result<Show> {
    let (mut state, mut sub, mut result, mut code, mut status) = (None, None, None, None, None);
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once('=').ok_or_else(bad)?;
        let slot = match key {
            "ActiveState" => &mut state,
            "SubState" => &mut sub,
            "Result" => &mut result,
            "ExecMainCode" => &mut code,
            "ExecMainStatus" => &mut status,
            _ => return Err(bad()),
        };
        if slot.replace(value).is_some() {
            return Err(bad());
        }
    }
    let (Some(state), Some(sub), Some(result), Some(code), Some(status)) =
        (state, sub, result, code, status)
    else {
        return Err(bad());
    };
    let code: u32 = code.parse().map_err(|_| bad())?;
    let status: u32 = status.parse().map_err(|_| bad())?;
    match (state, sub) {
        ("active", "exited") => ended(result, code, status, sent),
        _ => running_or_ended(state, result, code, status, sent),
    }
}

fn running_or_ended(
    state: &str,
    result: &str,
    code: u32,
    status: u32,
    sent: i32,
) -> io::Result<Show> {
    match state {
        "active" | "reloading" | "refreshing" | "activating" | "deactivating" | "maintenance" => {
            Ok(Show::Running)
        }
        "inactive" | "failed" => ended(result, code, status, sent),
        _ => Err(bad()),
    }
}

fn ended(result: &str, code: u32, status: u32, sent: i32) -> io::Result<Show> {
    let signalled = |signal: i32| Ok(Show::Ended(ExitStatus::from_raw(signal)));
    let signal_number = || {
        i32::try_from(status)
            .ok()
            .filter(|n| (1..=MAX_SIGNAL).contains(n))
            .unwrap_or(SIGKILL)
    };
    match result {
        "success" if code == 0 && sent != 0 => signalled(sent),
        "success" if code == 0 => Ok(Show::Idle),
        "success" if status == 0 => Ok(Show::Ended(ExitStatus::from_raw(0))),
        "exit-code" if (1..=255).contains(&status) => {
            let raw = i32::try_from(status << 8).map_err(|_| bad())?;
            Ok(Show::Ended(ExitStatus::from_raw(raw)))
        }
        "signal" | "core-dump" => signalled(signal_number()),
        "timeout" | "watchdog" => signalled(SIGTERM),
        "oom-kill" => signalled(SIGKILL),
        _ => Err(bad()),
    }
}

/// Receives the job id and the exact hosts of an install before its unit starts.
pub type HostsHook = Arc<dyn Fn(&str, &[&str]) + Send + Sync>;

fn install_unit_name(id: &str) -> String {
    format!("fleet-tool-install@{id}.service")
}

/// Installs the missing tools of a job through `fleet-tool-install@<id>.service` (ADR-0048).
///
/// For one install it checks the Box egress list against the tool hosts, makes
/// `<run_dir>/<id>/`, writes `mise.toml` and `tool-env` into it, binds the job socket the
/// install unit's forwarder dials, starts the unit with `systemctl start --no-block`, and
/// polls its state until it ends. The unit and the run dir are always cleaned up before the
/// result returns, and a dropped future kills the unit. The run dir is gone before the agent
/// launch, which makes the same dir.
///
/// Every failure is an [`io::Error`] with a bare kind: a non-zero unit exit is `Other`, an
/// unreadable or malformed state, a start that never ran and a unit past its deadline end the
/// unit with a kill request and count as ended. No unit output or path leaves this type.
///
/// Nothing here is verified on a live box.
#[derive(Clone)]
pub struct SystemdToolInstaller {
    ctl: Ctl,
    run_dir: PathBuf,
    poll: Duration,
    start_deadline: Duration,
    run_deadline: Duration,
    gid: Option<u32>,
    socket: Option<JobSocketSetup>,
    egress_allow: Vec<String>,
    hosts: Option<HostsHook>,
}

impl std::fmt::Debug for SystemdToolInstaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemdToolInstaller")
            .field("egress_allow", &self.egress_allow.len())
            .field("hosts_hook", &self.hosts.is_some())
            .finish_non_exhaustive()
    }
}

struct InstallGuard {
    ctl: Ctl,
    unit: String,
    socket: Option<JobSocket>,
    armed: bool,
    _dir: RunDir,
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        drop(self.socket.take());
        if self.armed {
            let _ = self
                .ctl
                .run(&["kill", "--kill-whom=all", "--signal=SIGKILL", &self.unit]);
            let _ = self.ctl.run(&["reset-failed", &self.unit]);
        }
    }
}

impl SystemdToolInstaller {
    /// An installer that runs `systemctl`, an absolute path, under [`DEFAULT_RUN_DIR`], and
    /// requires `egress_allow` (exact host names) to cover each install.
    pub fn new(systemctl: impl Into<PathBuf>, egress_allow: Vec<String>) -> Self {
        Self {
            ctl: Ctl {
                systemctl: systemctl.into(),
            },
            run_dir: PathBuf::from(DEFAULT_RUN_DIR),
            poll: DEFAULT_POLL,
            start_deadline: DEFAULT_START_DEADLINE,
            run_deadline: DEFAULT_INSTALL_RUN_DEADLINE,
            gid: None,
            socket: None,
            egress_allow,
            hosts: None,
        }
    }

    /// Puts the per-job run directories under `run_dir`.
    #[must_use]
    pub fn with_run_dir(mut self, run_dir: impl Into<PathBuf>) -> Self {
        self.run_dir = run_dir.into();
        self
    }

    /// Sets how often the unit state is polled.
    #[must_use]
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// Sets how long the unit may stay inactive without having run before it counts as failed.
    #[must_use]
    pub fn with_start_deadline(mut self, deadline: Duration) -> Self {
        self.start_deadline = deadline;
        self
    }

    /// Sets how long the unit may run before it is killed. The default is above the unit's own
    /// `RuntimeMaxSec`.
    #[must_use]
    pub fn with_run_deadline(mut self, deadline: Duration) -> Self {
        self.run_deadline = deadline;
        self
    }

    /// Shares the run directory, `mise.toml` and the socket with `gid`, the job group.
    #[must_use]
    pub fn with_job_gid(mut self, gid: Option<u32>) -> Self {
        self.gid = gid;
        self
    }

    /// Binds a job socket offering the services in `setup` for the install unit.
    #[must_use]
    pub fn with_job_socket(mut self, setup: JobSocketSetup) -> Self {
        self.socket = Some(setup);
        self
    }

    /// Calls `hook` with the job id and the install hosts before the unit starts.
    #[must_use]
    pub fn with_hosts_hook(mut self, hook: HostsHook) -> Self {
        self.hosts = Some(hook);
        self
    }

    async fn install_tools(&self, job_id: &str, tools: &[ToolSpec]) -> io::Result<()> {
        if validate_job_id(job_id).is_err()
            || !self.ctl.systemctl.is_absolute()
            || tools.is_empty()
            || tools.len() > MAX_CACHE_ENTRIES
        {
            return fail(io::ErrorKind::InvalidInput);
        }
        let names: Vec<ToolName> = tools.iter().map(ToolSpec::name).collect();
        check_tool_hosts(&self.egress_allow, &names)
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
        fs::create_dir_all(&self.run_dir)?;
        let dir = self.run_dir.join(job_id);
        fs::DirBuilder::new().mode(DIR_MODE).create(&dir)?;
        let mut guard = InstallGuard {
            ctl: self.ctl.clone(),
            unit: install_unit_name(job_id),
            socket: None,
            armed: false,
            _dir: RunDir(dir.clone()),
        };
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?;
        if let Some(gid) = self.gid {
            std::os::unix::fs::chown(&dir, None, Some(gid))?;
        }
        write_mise_toml(&self.run_dir, job_id, tools, self.gid)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        write_tool_env(&self.run_dir, job_id, TOOL_PROXY_PORT, &names)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        guard.socket = bind_socket(self.socket.as_ref(), &self.run_dir, self.gid, job_id)?;
        if let Some(hook) = &self.hosts {
            hook(job_id, &tool_hosts(&names));
        }
        guard.armed = true;
        let outcome = match self.ctl.start(&guard.unit).await {
            Ok(()) => self.wait_for_end(&guard.unit).await,
            Err(err) => Err(err.kind()),
        };
        drop(guard.socket.take());
        self.ctl.stop(&guard.unit).await;
        self.ctl.reset_failed(&guard.unit).await;
        guard.armed = false;
        outcome.map_err(io::Error::from)
    }

    async fn wait_for_end(&self, unit: &str) -> Result<(), io::ErrorKind> {
        let started = Instant::now();
        loop {
            let shown = match self.ctl.show(unit).await {
                Ok(text) => parse_show(&text, 0),
                Err(err) => Err(err),
            };
            let waited = started.elapsed();
            match shown {
                Ok(Show::Ended(status)) if status.success() => return Ok(()),
                Ok(Show::Ended(_)) => return Err(io::ErrorKind::Other),
                Ok(Show::Idle) if waited >= self.start_deadline => {
                    self.ctl.kill_unit(unit).await;
                    return Err(io::ErrorKind::TimedOut);
                }
                Ok(Show::Running) if waited >= self.run_deadline => {
                    self.ctl.kill_unit(unit).await;
                    return Err(io::ErrorKind::TimedOut);
                }
                Ok(Show::Running | Show::Idle) => tokio::time::sleep(self.poll).await,
                Err(err) => {
                    self.ctl.kill_unit(unit).await;
                    return Err(err.kind());
                }
            }
        }
    }
}

impl ToolInstaller for SystemdToolInstaller {
    fn install<'a>(&'a self, job_id: &'a str, tools: &'a [ToolSpec]) -> InstallFuture<'a> {
        Box::pin(self.install_tools(job_id, tools))
    }
}

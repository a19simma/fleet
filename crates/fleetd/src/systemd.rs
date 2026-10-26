//! Runs the agent as a `fleet-agent@<id>.service` unit through `systemctl`.
//!
//! Per job the launcher makes `<run_dir>/<id>/` holding the env file (0600), the stdout
//! FIFO and `spec.json`, then starts the unit without waiting. The unit is delivered
//! separately and runs `fleetd agent-exec <id>` as the job uid. Every `systemctl` call uses
//! the configured absolute path with an argv array and an empty environment.
//!
//! The unit sets `RemainAfterExit=yes`, so a clean exit stays `active (exited)`. The launcher
//! reads that as ended, then runs `stop` and `reset-failed` before it reports the result.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use tokio::net::unix::pipe::Receiver;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::agent_exec::{SPEC_FILE, write_spec};
use crate::config::{AgentLauncher, Config};
use crate::jobenv::{create_stdout_fifo, open_fifo_reader, render_env_file, write_env_file};
use crate::runner::{AgentProc, AgentSpec, DirectLauncher, Launched, Launcher};
use crate::workspace::validate_job_id;

/// Default parent of the per-job run directories.
pub const DEFAULT_RUN_DIR: &str = "/run/fleet";
/// Default `systemctl` binary.
pub const DEFAULT_SYSTEMCTL: &str = "/usr/bin/systemctl";

const DEFAULT_POLL: Duration = Duration::from_millis(500);
const DEFAULT_START_DEADLINE: Duration = Duration::from_secs(60);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const SHOW_CAP: usize = 4096;
const DIR_MODE: u32 = 0o750;
const HOOK_DIR: &str = "hook";
const ENV_FILE: &str = "env";
const STDOUT_FIFO: &str = "stdout";
const JOB_ID_ENV: &str = "FLEET_JOB_ID";
const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;
const MAX_SIGNAL: i32 = 64;

/// The launcher the config selects.
#[must_use]
pub fn select_launcher(config: &Config, job_gid: Option<u32>) -> Arc<dyn Launcher> {
    match config.agent_launcher {
        AgentLauncher::Direct => Arc::new(DirectLauncher),
        AgentLauncher::Systemd => {
            Arc::new(SystemdLauncher::new(&config.systemctl_path).with_job_gid(job_gid))
        }
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
    gid: Option<u32>,
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
            gid: None,
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

    /// Sets how long a unit may stay inactive without having run before the start counts as failed.
    #[must_use]
    pub fn with_start_deadline(mut self, deadline: Duration) -> Self {
        self.start_deadline = deadline;
        self
    }

    /// Removes every run dir under the run root, which at startup belongs to no live job of
    /// this process. Only real directories named like a job id are touched, never symlinks,
    /// files, the `hook` dir or any other name. A unit still active for the id is stopped and
    /// reset first. A failure is logged and the sweep goes on.
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

impl Launcher for SystemdLauncher {
    fn launch(&self, spec: AgentSpec) -> io::Result<Launched> {
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
        fs::create_dir_all(&self.run_dir)?;
        let dir = self.run_dir.join(&id);
        fs::DirBuilder::new().mode(DIR_MODE).create(&dir)?;
        let guard = RunDir(dir.clone());
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?;
        if let Some(gid) = self.gid {
            std::os::unix::fs::chown(&dir, None, Some(gid))?;
        }
        let body =
            render_env_file(&spec).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        write_env_file(&dir.join(ENV_FILE), &body)?;
        write_spec(&dir.join(SPEC_FILE), &id, &spec, self.gid)?;
        let fifo = dir.join(STDOUT_FIFO);
        create_stdout_fifo(&fifo, self.gid)?;
        let reader = Receiver::from_file(open_fifo_reader(&fifo)?)?;
        let keepalive = fs::OpenOptions::new().write(true).open(&fifo)?;
        let unit = unit_name(&id);
        self.ctl.run(&["start", "--no-block", &unit])?;
        Ok(Launched {
            stdout: Box::new(reader),
            proc: Box::new(SystemdProc {
                ctl: self.ctl.clone(),
                unit,
                poll: self.poll,
                start_deadline: self.start_deadline,
                launched: Instant::now(),
                keepalive: Some(keepalive),
                shared: Arc::new(Shared::default()),
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
}

struct SystemdProc {
    ctl: Ctl,
    unit: String,
    poll: Duration,
    start_deadline: Duration,
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
                Ok(Show::Ended(status)) => break Ok(status),
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
}

impl Drop for SystemdProc {
    fn drop(&mut self) {
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

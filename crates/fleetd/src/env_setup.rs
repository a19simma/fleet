//! Environment script setup (ADR-0067 decision 6): runs the Environment scripts of one Job in
//! order, before its agent starts, and turns each step into Job notes.
//!
//! [`EnvSetup`] never starts a process itself. A [`SetupLauncher`] does, and the production
//! launcher of the Setup unit `fleet-env@<id>.service` is [`UnavailableLauncher`] until the unit
//! shim exists, so a Job with scripts fails closed in phase [`PHASE_SETUP`]. Tests pass a fake.
//!
//! Each step gets a fresh scratch directory under `<run_root>/<job id>/`, holding only the
//! script. The directory and the per-job parent are removed on every end path: success,
//! failure, timeout, cancel (the future is dropped) and panic. Removal is `std::fs::remove_dir_all`
//! on the literal path it created, which never follows a symlink.
//!
//! Step output is read through a bounded buffer and ends up in the notes only after
//! [`sanitise_lines`]: redact, strip, redact, strip, cut to [`OUTPUT_CAP`]. The raw read keeps
//! [`READ_LIMIT`] bytes, which is the cap plus one maximal secret, so a secret that begins before
//! the cap and ends after it is still masked whole before the cut. The reader keeps draining
//! and discarding past the limit so the child never blocks on a full pipe, and it is aborted a
//! short grace after the step ends, so a detached descendant that still holds the pipe cannot
//! hold the step.

use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fleet_core::Redactor;
use fleet_core::environment::MAX_SECRET_BYTES;
use fleet_core::text::{Cap, sanitise_lines};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::envd::{EnvDelivery, SetupScript};
use crate::workspace::validate_job_id;

/// Phase name of a Job that fails while its scripts run.
pub const PHASE_SETUP: &str = "SETUP";

/// Fixed Job error for a failed setup step. The step name is in the Job notes.
pub const ERR_SETUP: &str = "environment setup failed";

/// Fixed Job error for a Job whose scripts cannot run on this Box.
pub const ERR_SETUP_UNAVAILABLE: &str = "environment setup is not available";

/// Most output bytes of one step that reach the notes.
pub const OUTPUT_CAP: usize = 64 * 1024;

/// Raw bytes kept per step before sanitising: [`OUTPUT_CAP`] plus one maximal secret plus one.
pub const READ_LIMIT: usize = OUTPUT_CAP + MAX_SECRET_BYTES + 1;

/// How long the output reader may run on after its step ended.
pub const DEFAULT_DRAIN_GRACE: Duration = Duration::from_millis(500);

const SCRIPT_FILE: &str = "step";

/// Receives the job id and the egress hosts a Job's scripts declared, before its first step.
pub type EgressHook = Arc<dyn Fn(&str, &[&str]) + Send + Sync>;

/// One step, as the launcher sees it.
#[derive(Debug, Clone, Copy)]
pub struct StepRun<'a> {
    /// The Job the step belongs to.
    pub job_id: &'a str,
    /// The step name.
    pub step: &'a str,
    /// The script file, inside `scratch`.
    pub script: &'a Path,
    /// The fresh scratch directory of this attempt.
    pub scratch: &'a Path,
    /// The step timeout.
    pub timeout: Duration,
}

/// A started step: its merged output, its exit and the way to end it.
pub struct StepProc {
    /// Standard output and error of the step, merged.
    pub output: Pin<Box<dyn AsyncRead + Send>>,
    /// Resolves with `true` for exit status 0. Dropping it must not leave the step running.
    pub exit: Pin<Box<dyn Future<Output = io::Result<bool>> + Send>>,
    /// Ends the step and every descendant. Called once on every end path, after the exit too.
    pub kill: Box<dyn FnOnce() + Send>,
}

/// Starts one script step. The production implementation starts the Setup unit.
pub trait SetupLauncher: Send + Sync + fmt::Debug {
    /// Starts `run`.
    ///
    /// # Errors
    ///
    /// Returns the error that stopped the start.
    fn start(&self, run: &StepRun<'_>) -> io::Result<StepProc>;
}

/// The launcher of a Box with no Setup unit shim: every start fails.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableLauncher;

impl SetupLauncher for UnavailableLauncher {
    fn start(&self, _: &StepRun<'_>) -> io::Result<StepProc> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// What a setup run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupReport {
    /// Job notes, already redacted and bounded: a status line per step, then its output.
    pub notes: Vec<String>,
    /// The name of the step that failed the Job, or `None` when every step passed.
    pub failed: Option<String>,
    /// Whether any script ran or was attempted.
    pub ran: bool,
    /// Wall time from the start of the first step to the end of the run.
    pub elapsed: Duration,
    /// The names of the steps the total budget cut off, in order.
    pub skipped: Vec<String>,
}

/// Runs the held scripts of a Job.
pub struct EnvSetup {
    launcher: Arc<dyn SetupLauncher>,
    delivery: Arc<EnvDelivery>,
    run_root: PathBuf,
    gid: Option<u32>,
    grace: Duration,
    budget: Option<Duration>,
    egress: Option<EgressHook>,
}

impl fmt::Debug for EnvSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvSetup")
            .field("run_root", &self.run_root)
            .finish_non_exhaustive()
    }
}

static ATTEMPT: AtomicU64 = AtomicU64::new(0);

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct EndOnDrop(Option<Box<dyn FnOnce() + Send>>);

impl EndOnDrop {
    fn fire(&mut self) {
        if let Some(kill) = self.0.take() {
            kill();
        }
    }
}

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        self.fire();
    }
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type Shared = Arc<Mutex<Vec<u8>>>;

async fn read_bounded(mut output: Pin<Box<dyn AsyncRead + Send>>, kept: Shared) {
    let mut chunk = [0_u8; 8192];
    loop {
        let Ok(n) = output.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            return;
        }
        let mut held = kept.lock().unwrap_or_else(PoisonError::into_inner);
        let room = READ_LIMIT.saturating_sub(held.len());
        let take = n.min(room);
        if let Some(part) = chunk.get(..take) {
            held.extend_from_slice(part);
        }
    }
}

enum Outcome {
    Passed,
    Failed,
    TimedOut,
    NotStarted,
    BudgetCut,
}

impl Outcome {
    const fn word(&self) -> &'static str {
        match self {
            Self::Passed => "ok",
            Self::Failed => "failed",
            Self::TimedOut => "timed out",
            Self::NotStarted => "could not start",
            Self::BudgetCut => "cut by the budget",
        }
    }
}

impl EnvSetup {
    /// A driver that takes scripts from `delivery`, starts them through `launcher` and keeps
    /// its scratch under `run_root` (an absolute path, `/run/fleet-env` in production).
    pub fn new(
        launcher: Arc<dyn SetupLauncher>,
        delivery: Arc<EnvDelivery>,
        run_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            launcher,
            delivery,
            run_root: run_root.into(),
            gid: None,
            grace: DEFAULT_DRAIN_GRACE,
            budget: None,
            egress: None,
        }
    }

    /// Shares each scratch directory and script with `gid`, the job group, with group access.
    #[must_use]
    pub const fn with_job_gid(mut self, gid: Option<u32>) -> Self {
        self.gid = gid;
        self
    }

    /// Sets the hard stop for the whole run. The default is no budget, so the daemon must set
    /// 1200 s.
    #[must_use]
    pub const fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Sets the hook that receives the declared egress hosts before the first step.
    #[must_use]
    pub fn with_egress(mut self, hook: EgressHook) -> Self {
        self.egress = Some(hook);
        self
    }

    /// Sets how long the output reader may run on after its step ended.
    #[must_use]
    pub const fn with_drain_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Whether `job_id` holds any script.
    #[must_use]
    pub fn has_scripts(&self, job_id: &str) -> bool {
        !self.delivery.scripts(job_id).is_empty()
    }

    /// Runs the scripts of `job_id` in order and stops at the first step that does not pass.
    ///
    /// Output is masked with `redactor`. A Job with no script returns an empty report. The
    /// per-job directory is removed before this returns and when the future is dropped.
    pub async fn run(&self, job_id: &str, redactor: &Redactor) -> SetupReport {
        let scripts = self.delivery.scripts(job_id);
        let mut report = SetupReport::default();
        if scripts.is_empty() {
            return report;
        }
        report.ran = true;
        let started = Instant::now();
        let Some(parent) = self.make_parent(job_id) else {
            report.failed = Some(first_name(&scripts));
            report
                .notes
                .push("setup could not prepare its scratch".to_owned());
            report.elapsed = started.elapsed();
            return report;
        };
        if let Some(hook) = &self.egress {
            let declared = self.delivery.egress_hosts(job_id);
            let hosts: Vec<&str> = declared.iter().map(String::as_str).collect();
            hook(job_id, &hosts);
        }
        for (index, script) in scripts.iter().enumerate() {
            let left = self.budget.map_or(Duration::MAX, |budget| {
                budget.saturating_sub(started.elapsed())
            });
            if left.is_zero() {
                skip_rest(&mut report, scripts.get(index..).unwrap_or_default());
                break;
            }
            let step_started = Instant::now();
            let (outcome, raw) = self.run_step(job_id, &parent.0, script, left).await;
            let millis = step_started.elapsed().as_millis();
            report.notes.push(format!(
                "setup step {} {} after {millis} ms",
                script.name,
                outcome.word()
            ));
            let clean = sanitise_lines(
                redactor,
                &String::from_utf8_lossy(&raw),
                Cap::Bytes(OUTPUT_CAP),
            );
            if !clean.text.trim().is_empty() {
                let cut = if clean.cut { " [output cut]" } else { "" };
                report.notes.push(format!(
                    "setup step {} output{cut}: {}",
                    script.name, clean.text
                ));
            }
            if matches!(outcome, Outcome::Passed) {
                continue;
            }
            if matches!(outcome, Outcome::BudgetCut) {
                if script.abort {
                    report.failed = Some(script.name.clone());
                }
                skip_rest(&mut report, scripts.get(index + 1..).unwrap_or_default());
                break;
            }
            if script.abort {
                report.failed = Some(script.name.clone());
                break;
            }
            report
                .notes
                .push(format!("setup step {} continuing", script.name));
        }
        report.elapsed = started.elapsed();
        drop(parent);
        report
    }

    /// Removes the per-job directory of `job_id`. Safe to call when it is gone.
    pub fn end(&self, job_id: &str) {
        if validate_job_id(job_id).is_ok() {
            let _ = fs::remove_dir_all(self.run_root.join(job_id));
        }
    }

    fn make_parent(&self, job_id: &str) -> Option<Dir> {
        validate_job_id(job_id).ok()?;
        if !self.run_root.is_absolute() {
            return None;
        }
        fs::create_dir_all(&self.run_root).ok()?;
        let path = self.run_root.join(job_id);
        let _ = fs::remove_dir_all(&path);
        let guard = self.mkdir(&path)?;
        Some(guard)
    }

    fn mkdir(&self, path: &Path) -> Option<Dir> {
        let mode = if self.gid.is_some() { 0o750 } else { 0o700 };
        fs::DirBuilder::new().mode(mode).create(path).ok()?;
        let guard = Dir(path.to_path_buf());
        if let Some(gid) = self.gid {
            std::os::unix::fs::chown(path, None, Some(gid)).ok()?;
        }
        Some(guard)
    }

    async fn run_step(
        &self,
        job_id: &str,
        parent: &Path,
        script: &SetupScript,
        left: Duration,
    ) -> (Outcome, Vec<u8>) {
        let attempt = ATTEMPT.fetch_add(1, Ordering::Relaxed);
        let Some(scratch) = self.mkdir(&parent.join(format!("a{attempt}"))) else {
            return (Outcome::NotStarted, Vec::new());
        };
        let Some(file) = self.write_script(&scratch.0, script) else {
            return (Outcome::NotStarted, Vec::new());
        };
        let run = StepRun {
            job_id,
            step: &script.name,
            script: &file,
            scratch: &scratch.0,
            timeout: script.timeout,
        };
        let Ok(proc) = self.launcher.start(&run) else {
            return (Outcome::NotStarted, Vec::new());
        };
        let StepProc { output, exit, kill } = proc;
        let mut end = EndOnDrop(Some(kill));
        let kept: Shared = Arc::default();
        let mut reader = tokio::spawn(read_bounded(output, Arc::clone(&kept)));
        let _abort = AbortOnDrop(reader.abort_handle());
        let cap = script.timeout.min(left);
        let outcome = match tokio::time::timeout(cap, exit).await {
            Ok(Ok(true)) => Outcome::Passed,
            Ok(_) => Outcome::Failed,
            Err(_) if left < script.timeout => Outcome::BudgetCut,
            Err(_) => Outcome::TimedOut,
        };
        end.fire();
        let _ = tokio::time::timeout(self.grace, &mut reader).await;
        let raw = kept.lock().unwrap_or_else(PoisonError::into_inner).clone();
        (outcome, raw)
    }

    fn write_script(&self, scratch: &Path, script: &SetupScript) -> Option<PathBuf> {
        let path = scratch.join(SCRIPT_FILE);
        let mode = if self.gid.is_some() { 0o550 } else { 0o500 };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .ok()?;
        file.write_all(script.body.as_bytes()).ok()?;
        file.sync_all().ok()?;
        drop(file);
        if let Some(gid) = self.gid {
            std::os::unix::fs::chown(&path, None, Some(gid)).ok()?;
        }
        Some(path)
    }
}

fn skip_rest(report: &mut SetupReport, rest: &[SetupScript]) {
    for script in rest {
        report
            .notes
            .push(format!("setup step {} skipped", script.name));
        report.skipped.push(script.name.clone());
        if script.abort && report.failed.is_none() {
            report.failed = Some(script.name.clone());
        }
    }
}

fn first_name(scripts: &[SetupScript]) -> String {
    scripts.first().map(|s| s.name.clone()).unwrap_or_default()
}

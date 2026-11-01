//! Restart after a swap: the drain with a lease that outlives its poller task, the health
//! gate order, and the exit request. Time is paused, so the drain cap is exact.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fleet_core::tools::Version;
use fleet_proto::v1::Job;
use fleetd::poller::{ClaimGate, JobRunner, RunError, Shutdown};
use fleetd::update::{
    ApplyOutcome, BAD_VERSIONS_FILE, DrainController, HealthGate, LeaseTracker, RestartSignal,
    Swapper, TrackedRunner, Updater,
};
use tempfile::TempDir;
use tokio::sync::Notify;

const CAP: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_secs(1);

fn version(raw: &str) -> Version {
    Version::new(raw).unwrap()
}

fn stage(root: &Path, name: &str) {
    let dir = root.join(name);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("fleetd"), b"bin").unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Rig {
    _dir: TempDir,
    root: std::path::PathBuf,
    gate: ClaimGate,
    tracker: LeaseTracker,
    restart: RestartSignal,
    updater: Updater,
}

fn rig() -> Rig {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("bin");
    fs::create_dir(&root).unwrap();
    stage(&root, "1.0.0");
    stage(&root, "1.1.0");
    symlink("1.0.0", root.join("current")).unwrap();
    let gate = ClaimGate::new();
    let tracker = LeaseTracker::new();
    let restart = RestartSignal::new();
    let updater = Updater::new(
        DrainController::new(gate.clone(), CAP, POLL),
        tracker.clone(),
        Swapper::new(&root),
        restart.clone(),
    );
    Rig {
        _dir: dir,
        root,
        gate,
        tracker,
        restart,
        updater,
    }
}

fn current(rig: &Rig) -> String {
    fs::read_link(rig.root.join("current"))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

async fn raised(signal: &RestartSignal) -> bool {
    tokio::time::timeout(Duration::from_millis(10), signal.requested())
        .await
        .is_ok()
}

struct Parked(Arc<Notify>);

impl JobRunner for Parked {
    async fn run(&self, _job: Job, _shutdown: Shutdown) -> Result<(), RunError> {
        self.0.notified().await;
        Ok(())
    }
}

struct Failing;

impl JobRunner for Failing {
    fn run(
        &self,
        _job: Job,
        _shutdown: Shutdown,
    ) -> impl Future<Output = Result<(), RunError>> + Send {
        std::future::ready(Err(RunError))
    }
}

fn job(id: &str) -> Job {
    Job {
        job_id: id.to_owned(),
        ..Job::default()
    }
}

fn shutdown() -> Shutdown {
    Shutdown::channel().1
}

#[tokio::test(start_paused = true)]
async fn an_idle_box_swaps_requests_the_restart_and_stays_paused() {
    let rig = rig();
    let outcome = rig.updater.apply(&version("1.1.0")).await;
    assert_eq!(outcome, ApplyOutcome::Restarting);
    assert_eq!(current(&rig), "1.1.0");
    assert!(raised(&rig.restart).await);
    assert!(rig.gate.is_paused());
}

#[tokio::test(start_paused = true)]
async fn a_held_lease_aborts_the_update_at_the_cap_and_resumes_claiming() {
    let rig = rig();
    rig.tracker.begin("job-a");
    let outcome = rig.updater.apply(&version("1.1.0")).await;
    assert_eq!(outcome, ApplyOutcome::DrainAborted);
    assert_eq!(current(&rig), "1.0.0");
    assert!(!raised(&rig.restart).await);
    assert!(!rig.gate.is_paused());
}

#[tokio::test(start_paused = true)]
async fn a_lease_that_outlives_its_poller_task_still_blocks_the_swap() {
    let rig = rig();
    let release = Arc::new(Notify::new());
    let runner = Arc::new(TrackedRunner::new(
        Parked(Arc::clone(&release)),
        rig.tracker.clone(),
    ));
    let task = tokio::spawn({
        let runner = Arc::clone(&runner);
        async move { runner.run(job("job-a"), shutdown()).await }
    });
    tokio::task::yield_now().await;
    assert!(!rig.tracker.is_idle());
    task.abort();
    let _ = task.await;
    assert!(!rig.tracker.is_idle());
    let outcome = rig.updater.apply(&version("1.1.0")).await;
    assert_eq!(outcome, ApplyOutcome::DrainAborted);
    assert_eq!(current(&rig), "1.0.0");
    rig.tracker.end("job-a");
    assert_eq!(
        rig.updater.apply(&version("1.1.0")).await,
        ApplyOutcome::Restarting
    );
}

#[tokio::test(start_paused = true)]
async fn a_lease_released_mid_drain_lets_the_swap_proceed() {
    let rig = rig();
    rig.tracker.begin("job-a");
    let tracker = rig.tracker.clone();
    tokio::spawn(async move {
        tokio::time::sleep(CAP / 2).await;
        tracker.end("job-a");
    });
    let outcome = rig.updater.apply(&version("1.1.0")).await;
    assert_eq!(outcome, ApplyOutcome::Restarting);
    assert_eq!(current(&rig), "1.1.0");
}

#[tokio::test(start_paused = true)]
async fn a_runner_that_returns_ok_or_err_ends_its_lease() {
    let tracker = LeaseTracker::new();
    let release = Arc::new(Notify::new());
    release.notify_one();
    let ok = TrackedRunner::new(Parked(release), tracker.clone());
    ok.run(job("a"), shutdown()).await.unwrap();
    assert!(tracker.is_idle());
    let failing = TrackedRunner::new(Failing, tracker.clone());
    assert!(failing.run(job("b"), shutdown()).await.is_err());
    assert!(tracker.is_idle());
}

#[tokio::test(start_paused = true)]
async fn a_bad_version_is_refused_before_any_drain() {
    let rig = rig();
    fs::write(rig.root.join(BAD_VERSIONS_FILE), "1.1.0\n").unwrap();
    let outcome = rig.updater.apply(&version("1.1.0")).await;
    assert_eq!(outcome, ApplyOutcome::BadVersion);
    assert!(!rig.gate.is_paused());
    assert_eq!(current(&rig), "1.0.0");
}

#[tokio::test(start_paused = true)]
async fn a_swap_failure_resumes_claiming_and_requests_no_restart() {
    let rig = rig();
    let outcome = rig.updater.apply(&version("9.9.9")).await;
    assert_eq!(outcome, ApplyOutcome::SwapFailed);
    assert_eq!(current(&rig), "1.0.0");
    assert!(!rig.gate.is_paused());
    assert!(!raised(&rig.restart).await);
}

#[tokio::test(start_paused = true)]
async fn a_second_apply_during_a_drain_is_busy() {
    let rig = rig();
    let first = rig.updater.apply(&version("1.1.0")).await;
    assert_eq!(first, ApplyOutcome::Restarting);
    let again = rig.updater.apply(&version("1.1.0")).await;
    assert_eq!(again, ApplyOutcome::Busy);
}

fn counting_gate() -> (HealthGate, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    let gate = HealthGate::new(move || {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    (gate, count)
}

#[test]
fn the_health_sink_waits_for_both_ready_and_a_heartbeat() {
    let (gate, count) = counting_gate();
    gate.mark_heartbeat_ok();
    assert_eq!(count.load(Ordering::SeqCst), 0);
    gate.mark_ready();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let (gate, count) = counting_gate();
    gate.mark_ready();
    assert_eq!(count.load(Ordering::SeqCst), 0);
    gate.mark_heartbeat_ok();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn the_health_sink_runs_once() {
    let (gate, count) = counting_gate();
    gate.mark_ready();
    for _ in 0..5 {
        gate.mark_heartbeat_ok();
    }
    gate.mark_ready();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn the_bin_root_gate_writes_the_marker_for_current_only_after_both_signals() {
    let rig = rig();
    let gate = HealthGate::for_bin_root(&rig.root);
    gate.mark_ready();
    assert!(!rig.root.join("health").exists());
    gate.mark_heartbeat_ok();
    assert_eq!(
        fs::read_to_string(rig.root.join("health")).unwrap(),
        "1.0.0\n"
    );
}

#[test]
fn the_bin_root_gate_writes_nothing_without_a_version_link() {
    let dir = TempDir::new().unwrap();
    let gate = HealthGate::for_bin_root(dir.path());
    gate.mark_ready();
    gate.mark_heartbeat_ok();
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

struct Panicking;

impl JobRunner for Panicking {
    #[expect(clippy::panic, reason = "the test needs a runner that panics")]
    async fn run(&self, _job: Job, _shutdown: Shutdown) -> Result<(), RunError> {
        panic!("runner panic");
    }
}

#[tokio::test(start_paused = true)]
async fn a_panicking_runner_ends_its_lease_so_the_drain_is_not_wedged() {
    let rig = rig();
    let runner = Arc::new(TrackedRunner::new(Panicking, rig.tracker.clone()));
    let task = tokio::spawn({
        let runner = Arc::clone(&runner);
        async move { runner.run(job("job-a"), shutdown()).await }
    });
    assert!(task.await.unwrap_err().is_panic());
    assert!(rig.tracker.is_idle());
    assert_eq!(
        rig.updater.apply(&version("1.1.0")).await,
        ApplyOutcome::Restarting
    );
}

#[test]
fn the_bin_root_gate_marks_the_version_running_at_construction_not_a_later_swap() {
    let rig = rig();
    let gate = HealthGate::for_bin_root(&rig.root);
    Swapper::new(&rig.root).activate(&version("1.1.0")).unwrap();
    assert_eq!(current(&rig), "1.1.0");
    gate.mark_ready();
    gate.mark_heartbeat_ok();
    assert_eq!(
        fs::read_to_string(rig.root.join("health")).unwrap(),
        "1.0.0\n"
    );
}

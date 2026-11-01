//! Restart after a swap and the health gate that proves the new binary (ADR-0047).
//!
//! [`Updater::apply`] drains the box, swaps `current` and asks the daemon to exit.
//! `Restart=always` then starts the new binary, so no privilege rule is needed. The claim gate
//! stays paused until the process ends. [`LeaseTracker`] is the idle predicate: it counts jobs
//! from the moment a runner starts them until the runner returns or the job-end hook fires, so
//! a lease that outlives its poller task still blocks the drain. [`HealthGate`] fires its sink
//! once, after both `READY=1` and one good heartbeat, and the sink writes the health marker.

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::tools::Version;
use fleet_proto::v1::Job;
use tokio::sync::Notify;

use super::drain::{DrainController, DrainOutcome, Draining};
use super::guard::{is_bad_version, write_health_marker};
use super::swap::Swapper;
use crate::poller::{ClaimGate, JobRunner, RunError, Shutdown};

/// Job ids a runner started and has not ended.
#[derive(Debug, Clone, Default)]
pub struct LeaseTracker(Arc<Mutex<HashSet<String>>>);

impl LeaseTracker {
    /// An empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn set(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a job as held.
    pub fn begin(&self, job_id: &str) {
        self.set().insert(job_id.to_owned());
    }

    /// Records a job as ended.
    pub fn end(&self, job_id: &str) {
        self.set().remove(job_id);
    }

    /// Whether no job is held.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.set().is_empty()
    }
}

/// A [`JobRunner`] that records each job in a [`LeaseTracker`] while it runs.
///
/// The entry ends when the inner runner returns, `Ok` or `Err`. A runner future that is dropped
/// early, by the poller's abort or a panic, leaves the entry, because its agent may still run
/// under the lease. The job-end hook clears it.
pub struct TrackedRunner<R> {
    inner: R,
    tracker: LeaseTracker,
}

impl<R> TrackedRunner<R> {
    /// Wraps `inner`.
    pub const fn new(inner: R, tracker: LeaseTracker) -> Self {
        Self { inner, tracker }
    }

    /// The wrapped runner.
    pub const fn inner(&self) -> &R {
        &self.inner
    }
}

impl<R: JobRunner> JobRunner for TrackedRunner<R> {
    async fn run(&self, job: Job, shutdown: Shutdown) -> Result<(), RunError> {
        let id = job.job_id.clone();
        self.tracker.begin(&id);
        let outcome = self.inner.run(job, shutdown).await;
        self.tracker.end(&id);
        outcome
    }
}

/// Asks the daemon to exit so systemd starts the new binary.
#[derive(Debug, Clone, Default)]
pub struct RestartSignal(Arc<Notify>);

impl RestartSignal {
    /// A signal nobody has raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raises the signal. A raise before anyone waits is kept.
    pub fn request(&self) {
        self.0.notify_one();
    }

    /// Resolves once the signal is raised.
    pub async fn requested(&self) {
        self.0.notified().await;
    }
}

type Sink = Box<dyn Fn() + Send + Sync>;

struct GateInner {
    ready: AtomicBool,
    beat: AtomicBool,
    fired: AtomicBool,
    sink: Sink,
}

/// Runs a sink once, after both [`HealthGate::mark_ready`] and
/// [`HealthGate::mark_heartbeat_ok`], in either order.
#[derive(Clone)]
pub struct HealthGate(Arc<GateInner>);

impl fmt::Debug for HealthGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthGate").finish_non_exhaustive()
    }
}

impl HealthGate {
    /// A gate that runs `sink` once.
    pub fn new(sink: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(GateInner {
            ready: AtomicBool::new(false),
            beat: AtomicBool::new(false),
            fired: AtomicBool::new(false),
            sink: Box::new(sink),
        }))
    }

    /// A gate whose sink writes the health marker for the version `current` names under
    /// `bin_root`. With no version link it writes nothing.
    pub fn for_bin_root(bin_root: impl Into<PathBuf>) -> Self {
        let root = bin_root.into();
        Self::new(move || {
            let current = Swapper::new(&root).current_version();
            match current {
                Ok(Some(version)) => {
                    if let Err(err) = write_health_marker(&root, &version) {
                        tracing::warn!(%err, "health marker not written");
                    }
                }
                Ok(None) => {}
                Err(err) => tracing::warn!(%err, "health marker not written"),
            }
        })
    }

    /// Records that `READY=1` was sent.
    pub fn mark_ready(&self) {
        self.0.ready.store(true, Ordering::SeqCst);
        self.try_fire();
    }

    /// Records one successful heartbeat.
    pub fn mark_heartbeat_ok(&self) {
        self.0.beat.store(true, Ordering::SeqCst);
        self.try_fire();
    }

    fn try_fire(&self) {
        if self.0.ready.load(Ordering::SeqCst)
            && self.0.beat.load(Ordering::SeqCst)
            && !self.0.fired.swap(true, Ordering::SeqCst)
        {
            (self.0.sink)();
        }
    }
}

/// The update pieces the daemon shares between the poller, the heartbeat and the run loop.
#[derive(Debug, Clone, Default)]
pub struct UpdateWiring {
    /// Pauses claiming during a drain.
    pub gate: ClaimGate,
    /// Counts held jobs for the drain.
    pub tracker: LeaseTracker,
    /// Raised to make the daemon exit after a swap.
    pub restart: RestartSignal,
    /// Writes the health marker. `None` writes none.
    pub health: Option<HealthGate>,
}

impl UpdateWiring {
    /// Wiring whose health gate writes the marker under `bin_root`.
    pub fn for_bin_root(bin_root: impl Into<PathBuf>) -> Self {
        Self {
            health: Some(HealthGate::for_bin_root(bin_root)),
            ..Self::default()
        }
    }

    /// An [`Updater`] over these pieces with the standard drain cap.
    #[must_use]
    pub fn updater(&self, swapper: Swapper) -> Updater {
        Updater::new(
            DrainController::standard(self.gate.clone()),
            self.tracker.clone(),
            swapper,
            self.restart.clone(),
        )
    }
}

/// How [`Updater::apply`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// `current` was swapped and the restart was requested. Claiming stays paused.
    Restarting,
    /// The version is in the bad-version file. Nothing changed.
    BadVersion,
    /// Another drain is running. Nothing changed.
    Busy,
    /// The cap passed with a lease held. Claiming has resumed.
    DrainAborted,
    /// The swap failed. Claiming has resumed and `current` is as it was.
    SwapFailed,
}

/// Drains, swaps and requests the restart.
pub struct Updater {
    drain: DrainController,
    tracker: LeaseTracker,
    swapper: Swapper,
    restart: RestartSignal,
    held: Mutex<Option<Draining>>,
}

impl fmt::Debug for Updater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Updater").finish_non_exhaustive()
    }
}

impl Updater {
    /// An updater over the parts the daemon wires.
    #[must_use]
    pub const fn new(
        drain: DrainController,
        tracker: LeaseTracker,
        swapper: Swapper,
        restart: RestartSignal,
    ) -> Self {
        Self {
            drain,
            tracker,
            swapper,
            restart,
            held: Mutex::new(None),
        }
    }

    /// Applies the staged `version`: refuse a bad one, wait for idle, swap, request the restart.
    pub async fn apply(&self, version: &Version) -> ApplyOutcome {
        if is_bad_version(self.swapper.bin_root(), version) {
            return ApplyOutcome::BadVersion;
        }
        let Ok(mut draining) = self.drain.begin_drain() else {
            return ApplyOutcome::Busy;
        };
        let tracker = self.tracker.clone();
        if draining.wait(move || tracker.is_idle()).await == DrainOutcome::Aborted {
            return ApplyOutcome::DrainAborted;
        }
        if let Err(err) = self.swapper.swap(version) {
            tracing::warn!(%err, "update swap failed");
            return ApplyOutcome::SwapFailed;
        }
        *self.held.lock().unwrap_or_else(PoisonError::into_inner) = Some(draining);
        self.restart.request();
        ApplyOutcome::Restarting
    }
}

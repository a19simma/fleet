//! Idle drain before an update (ADR-0047).
//!
//! [`DrainController::begin_drain`] pauses the poller's [`ClaimGate`]. [`Draining::wait`] then
//! waits until no lease is held. When [`DRAIN_CAP`] passes first, the drain aborts and claiming
//! resumes. The drain never signals or kills a running job: the cap ends the update attempt,
//! not the work. Dropping [`Draining`] resumes claiming, so a cancelled or finished attempt
//! leaves the poller running. Time comes from tokio, so tests pause the clock, and the cap and
//! poll interval are constructor arguments.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::poller::ClaimGate;

/// Longest an update waits for the box to go idle.
pub const DRAIN_CAP: Duration = Duration::from_secs(30 * 60);

/// How often the drain checks that no lease is held.
pub const DRAIN_POLL: Duration = Duration::from_secs(1);

/// Where the drain controller stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainState {
    /// No drain is running.
    Idle,
    /// Claiming is paused and the drain is waiting for the last lease.
    Draining,
    /// The last drain hit the cap. Claiming has resumed.
    Aborted,
}

/// How a drain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// No lease is held and claiming stays paused until [`Draining`] drops.
    Drained,
    /// The cap passed with a lease still held. Claiming has resumed.
    Aborted,
}

/// A drain is already in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainRefused;

impl fmt::Display for DrainRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a drain is already in progress")
    }
}

impl std::error::Error for DrainRefused {}

/// Starts drains and tracks their state.
#[derive(Debug, Clone)]
pub struct DrainController {
    gate: ClaimGate,
    state: Arc<Mutex<DrainState>>,
    cap: Duration,
    poll: Duration,
}

impl DrainController {
    /// A controller over `gate` with the given cap and poll interval.
    #[must_use]
    pub fn new(gate: ClaimGate, cap: Duration, poll: Duration) -> Self {
        Self {
            gate,
            state: Arc::new(Mutex::new(DrainState::Idle)),
            cap,
            poll,
        }
    }

    /// The controller the daemon uses: [`DRAIN_CAP`] and [`DRAIN_POLL`].
    #[must_use]
    pub fn standard(gate: ClaimGate) -> Self {
        Self::new(gate, DRAIN_CAP, DRAIN_POLL)
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> DrainState {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Pauses claiming and returns the drain handle.
    ///
    /// # Errors
    ///
    /// Returns [`DrainRefused`] while another drain is in progress.
    pub fn begin_drain(&self) -> Result<Draining, DrainRefused> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if *state == DrainState::Draining {
            return Err(DrainRefused);
        }
        *state = DrainState::Draining;
        self.gate.pause();
        drop(state);
        Ok(Draining {
            control: self.clone(),
            released: false,
        })
    }

    fn release(&self, aborted: bool) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state = if aborted {
            DrainState::Aborted
        } else {
            DrainState::Idle
        };
        self.gate.resume();
    }
}

/// A drain in progress. Dropping it resumes claiming.
#[derive(Debug)]
pub struct Draining {
    control: DrainController,
    released: bool,
}

impl Draining {
    /// Waits until `idle` reports no lease held and no claim in flight, or the cap passes.
    ///
    /// `idle` is checked at once and then every poll interval. [`ClaimGate::claim_in_flight`]
    /// covers the poller from before a claim until the claimed job's runner returns, so a job
    /// claimed but not yet visible to `idle` still blocks [`DrainOutcome::Drained`]. `idle`
    /// itself must cover leases that outlive a poller task. On the cap this resumes claiming
    /// and returns [`DrainOutcome::Aborted`]. No running job is touched.
    ///
    /// A handle that already aborted returns [`DrainOutcome::Aborted`] at once and touches
    /// neither the state nor the gate, so a newer drain stays paused.
    pub async fn wait(&mut self, idle: impl Fn() -> bool + Send + Sync) -> DrainOutcome {
        if self.released {
            return DrainOutcome::Aborted;
        }
        let gate = self.control.gate.clone();
        let poll = self.control.poll;
        let settled = async {
            while !idle() || gate.claim_in_flight() {
                tokio::time::sleep(poll).await;
            }
        };
        if tokio::time::timeout(self.control.cap, settled)
            .await
            .is_ok()
        {
            DrainOutcome::Drained
        } else {
            self.released = true;
            self.control.release(true);
            DrainOutcome::Aborted
        }
    }
}

impl Drop for Draining {
    fn drop(&mut self) {
        if !self.released {
            self.control.release(false);
        }
    }
}

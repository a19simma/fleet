//! Phase timing of a job: the clone, push and pull request steps, measured through an injected
//! [`Clock`].

use std::fmt::Debug;
use std::time::{Duration, Instant};

use fleet_proto::MAX_PHASE_MS;

/// A monotonic time source. A test passes a fake, so no phase timing needs a sleep.
pub trait Clock: Send + Sync + Debug {
    /// Time since a fixed origin. Later calls never return less.
    fn now(&self) -> Duration;
}

/// The real clock, counting from its creation.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Milliseconds from `start` to now on `clock`, at most [`MAX_PHASE_MS`] so the server accepts it.
pub(crate) fn elapsed_ms(clock: &dyn Clock, start: Duration) -> u64 {
    u64::try_from(clock.now().saturating_sub(start).as_millis())
        .unwrap_or(MAX_PHASE_MS)
        .min(MAX_PHASE_MS)
}

/// Durations of the phases a job ran. A phase that did not run is `None`, never 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Phases {
    pub(crate) checkout: Option<u64>,
    pub(crate) push: Option<u64>,
    pub(crate) pr: Option<u64>,
}

impl Phases {
    /// Takes every figure `other` holds and keeps the rest.
    pub(crate) fn merge(&mut self, other: Self) {
        self.checkout = other.checkout.or(self.checkout);
        self.push = other.push.or(self.push);
        self.pr = other.pr.or(self.pr);
    }
}

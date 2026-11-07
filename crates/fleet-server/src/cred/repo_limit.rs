//! The per-User rate limit on repository checks (ADR-0059).
//!
//! A sliding window per User over an injected clock, so tests drive time directly.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::limiter::Clock;

/// Repository checks one User may start in one [`REPO_CHECK_WINDOW`].
pub const MAX_REPO_CHECKS_PER_USER: usize = 10;

/// Length of the per-User repository check window.
pub const REPO_CHECK_WINDOW: Duration = Duration::from_secs(60);

/// Repository checks the server runs at once, across all Users.
pub const MAX_CONCURRENT_REPO_CHECKS: usize = 8;

/// A per-User sliding-window counter.
pub struct CheckLimiter {
    clock: Clock,
    max: usize,
    window: Duration,
    state: Mutex<HashMap<i64, VecDeque<Instant>>>,
}

impl std::fmt::Debug for CheckLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckLimiter(..)")
    }
}

impl CheckLimiter {
    /// A limiter of `max` checks per `window` over `clock`.
    #[must_use]
    pub fn new(clock: Clock, max: usize, window: Duration) -> Self {
        Self {
            clock,
            max,
            window,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// The production limits over the system clock.
    #[must_use]
    pub fn system() -> Self {
        Self::new(
            Arc::new(Instant::now),
            MAX_REPO_CHECKS_PER_USER,
            REPO_CHECK_WINDOW,
        )
    }

    /// Counts one check for `user_id` and returns true, or returns false at the limit.
    #[must_use]
    pub fn admit(&self, user_id: i64) -> bool {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain(|_, queue| {
            while queue
                .front()
                .is_some_and(|at| now.saturating_duration_since(*at) >= self.window)
            {
                queue.pop_front();
            }
            !queue.is_empty()
        });
        let queue = state.entry(user_id).or_default();
        let admitted = queue.len() < self.max;
        if admitted {
            queue.push_back(now);
        }
        drop(state);
        admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clocked(max: usize) -> (CheckLimiter, Arc<Mutex<Instant>>) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let seen = Arc::clone(&now);
        let clock: Clock = Arc::new(move || *seen.lock().unwrap());
        (CheckLimiter::new(clock, max, Duration::from_secs(60)), now)
    }

    fn advance(now: &Arc<Mutex<Instant>>, by: Duration) {
        *now.lock().unwrap() += by;
    }

    #[test]
    fn the_limit_is_per_user() {
        let (limiter, _) = clocked(2);
        assert!(limiter.admit(1));
        assert!(limiter.admit(1));
        assert!(!limiter.admit(1));
        assert!(limiter.admit(2));
    }

    #[test]
    fn a_check_stops_counting_after_the_window() {
        let (limiter, now) = clocked(1);
        assert!(limiter.admit(1));
        advance(&now, Duration::from_secs(59));
        assert!(!limiter.admit(1));
        advance(&now, Duration::from_secs(1));
        assert!(limiter.admit(1));
    }

    #[test]
    fn a_refused_check_is_not_counted() {
        let (limiter, now) = clocked(1);
        assert!(limiter.admit(1));
        advance(&now, Duration::from_secs(30));
        assert!(!limiter.admit(1));
        advance(&now, Duration::from_secs(30));
        assert!(limiter.admit(1));
    }

    #[test]
    fn idle_users_are_forgotten() {
        let (limiter, now) = clocked(1);
        assert!(limiter.admit(1));
        advance(&now, Duration::from_secs(61));
        assert!(limiter.admit(2));
        assert_eq!(limiter.state.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_production_constants_are_fixed() {
        assert_eq!(MAX_REPO_CHECKS_PER_USER, 10);
        assert_eq!(REPO_CHECK_WINDOW, Duration::from_secs(60));
        assert_eq!(MAX_CONCURRENT_REPO_CHECKS, 8);
    }
}

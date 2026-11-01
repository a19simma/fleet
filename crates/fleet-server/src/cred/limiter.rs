//! Failure limiter for the bootstrap password: one global window and one window per client.
//!
//! An attempt counts when it is reserved and stops counting only if it succeeds. The clock is a constructor parameter so tests drive time directly.
//! Each window slides: an attempt stops counting once it is older than the window.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Failures allowed across all clients in one window.
pub const GLOBAL_MAX_FAILURES: usize = 20;

/// Failures allowed from one client in one window.
pub const IP_MAX_FAILURES: usize = 5;

/// Length of the sliding window.
pub const WINDOW: Duration = Duration::from_secs(15 * 60);

/// A source of the current instant.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

#[derive(Default)]
struct State {
    global: VecDeque<Instant>,
    per_ip: HashMap<IpAddr, VecDeque<Instant>>,
}

/// A global plus per-client failure limiter.
pub struct Limiter {
    clock: Clock,
    global_max: usize,
    ip_max: usize,
    window: Duration,
    state: Mutex<State>,
}

fn live(queue: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while queue
        .front()
        .is_some_and(|at| now.saturating_duration_since(*at) >= window)
    {
        queue.pop_front();
    }
}

fn remove_one(queue: &mut VecDeque<Instant>, at: Instant) {
    if let Some(index) = queue.iter().rposition(|entry| *entry == at) {
        queue.remove(index);
    }
}

/// One counted attempt, held until the attempt resolves.
#[derive(Debug)]
#[must_use]
pub struct Reservation {
    ip: IpAddr,
    at: Instant,
}

impl Limiter {
    /// The production limits over `clock`.
    #[must_use]
    pub fn new(clock: Clock) -> Self {
        Self::with_limits(clock, GLOBAL_MAX_FAILURES, IP_MAX_FAILURES, WINDOW)
    }

    /// A limiter with explicit limits, for tests that shrink them.
    #[must_use]
    pub fn with_limits(clock: Clock, global_max: usize, ip_max: usize, window: Duration) -> Self {
        Self {
            clock,
            global_max,
            ip_max,
            window,
            state: Mutex::new(State::default()),
        }
    }

    /// The production limits over the system clock.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(Instant::now))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reserves one attempt from `ip` in a single locked step: when both windows are
    /// below their limits the attempt is counted at once and a [`Reservation`] returns,
    /// otherwise `None`. Concurrent callers cannot all pass, so in-flight attempts count
    /// against the limits. Call [`release`](Self::release) when the attempt succeeds.
    #[must_use]
    pub fn reserve(&self, ip: IpAddr) -> Option<Reservation> {
        let now = (self.clock)();
        let mut state = self.lock();
        live(&mut state.global, now, self.window);
        state.per_ip.retain(|_, queue| {
            live(queue, now, self.window);
            !queue.is_empty()
        });
        if state.global.len() >= self.global_max
            || state.per_ip.get(&ip).map_or(0, VecDeque::len) >= self.ip_max
        {
            return None;
        }
        state.global.push_back(now);
        state.per_ip.entry(ip).or_default().push_back(now);
        drop(state);
        Some(Reservation { ip, at: now })
    }

    /// Gives back a reservation whose attempt succeeded, so it uses no budget.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "a reservation is spent once, so release takes it by value"
    )]
    pub fn release(&self, reservation: Reservation) {
        let Reservation { ip, at } = reservation;
        let mut state = self.lock();
        remove_one(&mut state.global, at);
        if let Some(queue) = state.per_ip.get_mut(&ip) {
            remove_one(queue, at);
            if queue.is_empty() {
                state.per_ip.remove(&ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    const SMALL_WINDOW: Duration = Duration::from_secs(60);

    fn clock() -> (Clock, Arc<Mutex<Instant>>) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let handle = Arc::clone(&now);
        let read: Clock = Arc::new(move || *handle.lock().unwrap());
        (read, now)
    }

    fn advance(now: &Mutex<Instant>, by: Duration) {
        *now.lock().unwrap() += by;
    }

    #[test]
    fn a_client_is_allowed_up_to_its_limit_and_refused_just_over() {
        let (read, _) = clock();
        let limiter = Limiter::with_limits(read, 100, 3, SMALL_WINDOW);
        for _ in 0..3 {
            assert!(limiter.reserve(A).is_some());
        }
        assert!(limiter.reserve(A).is_none());
        assert!(limiter.reserve(B).is_some());
    }

    #[test]
    fn the_global_window_caps_all_clients_together() {
        let (read, _) = clock();
        let limiter = Limiter::with_limits(read, 4, 100, SMALL_WINDOW);
        assert!(limiter.reserve(A).is_some());
        assert!(limiter.reserve(A).is_some());
        assert!(limiter.reserve(B).is_some());
        assert!(limiter.reserve(B).is_some());
        assert!(limiter.reserve(A).is_none());
        assert!(limiter.reserve(B).is_none());
        assert!(
            limiter
                .reserve(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)))
                .is_none()
        );
    }

    #[test]
    fn failures_age_out_of_the_window() {
        let (read, now) = clock();
        let limiter = Limiter::with_limits(read, 100, 2, SMALL_WINDOW);
        assert!(limiter.reserve(A).is_some());
        assert!(limiter.reserve(A).is_some());
        assert!(limiter.reserve(A).is_none());
        advance(&now, SMALL_WINDOW.saturating_sub(Duration::from_secs(1)));
        assert!(limiter.reserve(A).is_none());
        advance(&now, Duration::from_secs(1));
        assert!(limiter.reserve(A).is_some());
    }

    #[test]
    fn concurrent_reservations_never_exceed_the_per_client_limit() {
        let (read, _) = clock();
        let limiter = Arc::new(Limiter::with_limits(read, 100, 5, SMALL_WINDOW));
        let granted: usize = (0..12)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                std::thread::spawn(move || limiter.reserve(A).is_some())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum();
        assert_eq!(granted, 5);
        assert!(limiter.reserve(B).is_some());
    }

    #[test]
    fn concurrent_reservations_never_exceed_the_global_limit() {
        let (read, _) = clock();
        let limiter = Arc::new(Limiter::with_limits(read, 4, 100, SMALL_WINDOW));
        let granted: usize = (0..12u8)
            .map(|n| {
                let limiter = Arc::clone(&limiter);
                let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100 + n));
                std::thread::spawn(move || limiter.reserve(ip).is_some())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum();
        assert_eq!(granted, 4);
    }

    #[test]
    fn a_released_reservation_uses_no_budget() {
        let (read, _) = clock();
        let limiter = Limiter::with_limits(read, 2, 2, SMALL_WINDOW);
        for _ in 0..10 {
            let held = limiter.reserve(A).unwrap();
            limiter.release(held);
        }
        let first = limiter.reserve(A).unwrap();
        let second = limiter.reserve(A).unwrap();
        assert!(limiter.reserve(A).is_none());
        assert!(limiter.reserve(B).is_none());
        limiter.release(first);
        assert!(limiter.reserve(B).is_some());
        drop(second);
    }

    #[test]
    fn the_production_limits_are_the_named_constants() {
        let (read, _) = clock();
        let limiter = Limiter::new(read);
        for _ in 0..IP_MAX_FAILURES {
            assert!(limiter.reserve(A).is_some());
        }
        assert!(limiter.reserve(A).is_none());
        assert!(limiter.reserve(B).is_some());
    }
}

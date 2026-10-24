//! Full-jitter exponential backoff used by the job poller.
//!
//! The delay ceiling starts at one second and doubles on every failure until it reaches
//! five minutes. Each delay is drawn uniformly from zero up to the current ceiling. A
//! success resets the schedule.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::Duration;

const BASE: Duration = Duration::from_secs(1);

const CAP: Duration = Duration::from_secs(300);

/// A source of uniform values in `[0, 1)`.
pub trait Random {
    /// Returns the next value, at least 0.0 and below 1.0.
    fn next_unit(&mut self) -> f64;
}

/// Process-random values from a seeded `SplitMix64` generator.
///
/// Not suitable for secrets. It only spreads retries in time. It is not `Clone`, because
/// a clone would replay the same sequence and correlate the retries it spreads.
#[derive(Debug)]
pub struct SystemRandom {
    state: u64,
}

impl SystemRandom {
    /// Seeds the generator from the standard library's per-process random keys.
    pub fn new() -> Self {
        Self {
            state: RandomState::new().build_hasher().finish(),
        }
    }
}

impl Default for SystemRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl Random for SystemRandom {
    #[expect(
        clippy::cast_precision_loss,
        reason = "the top 53 bits of a u64 fit an f64 mantissa exactly"
    )]
    fn next_unit(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// An exponential backoff schedule with full jitter.
#[derive(Debug, Clone)]
pub(crate) struct Backoff<R = SystemRandom> {
    base: Duration,
    cap: Duration,
    failures: u32,
    random: R,
}

impl<R: Random> Backoff<R> {
    /// Builds the standard schedule: one second doubling to five minutes.
    pub(crate) fn standard(random: R) -> Self {
        Self::with_random(BASE, CAP, random)
    }

    /// Builds a schedule with a custom base, cap and random source.
    ///
    /// A `cap` below `base` is raised to `base`.
    pub(crate) fn with_random(base: Duration, cap: Duration, random: R) -> Self {
        Self {
            base,
            cap: cap.max(base),
            failures: 0,
            random,
        }
    }

    /// Returns the upper bound of the next delay.
    pub(crate) fn ceiling(&self) -> Duration {
        let factor = 1u32.checked_shl(self.failures.min(31)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.cap)
    }

    /// Records a failure and returns how long to wait before the next try.
    ///
    /// The delay is uniform from zero up to [`Backoff::ceiling`] as it stood before this call.
    pub(crate) fn next_delay(&mut self) -> Duration {
        let ceiling = self.ceiling();
        self.failures = self.failures.saturating_add(1);
        let unit = self.random.next_unit().clamp(0.0, 1.0);
        ceiling.mul_f64(unit)
    }

    /// Returns the number of failures since the last reset.
    #[cfg(test)]
    pub(crate) fn failures(&self) -> u32 {
        self.failures
    }

    /// Restarts the schedule at the base ceiling. Call it after a success.
    pub(crate) fn reset(&mut self) {
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(f64);

    impl Random for Fixed {
        fn next_unit(&mut self) -> f64 {
            self.0
        }
    }

    fn schedule(unit: f64) -> Backoff<Fixed> {
        Backoff::with_random(BASE, CAP, Fixed(unit))
    }

    #[test]
    fn ceiling_doubles_then_holds_at_the_cap() {
        let mut backoff = schedule(1.0);
        let ceilings: Vec<u64> = (0..12)
            .map(|_| {
                let ceiling = backoff.ceiling().as_secs();
                backoff.next_delay();
                ceiling
            })
            .collect();
        assert_eq!(ceilings, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300]);
    }

    #[test]
    fn standard_is_one_second_to_five_minutes() {
        let mut backoff = Backoff::standard(Fixed(1.0));
        assert_eq!(backoff.ceiling(), Duration::from_secs(1));
        for _ in 0..40 {
            backoff.next_delay();
        }
        assert_eq!(backoff.ceiling(), Duration::from_secs(300));
    }

    #[test]
    fn delay_scales_with_the_random_unit() {
        assert_eq!(schedule(0.0).next_delay(), Duration::ZERO);
        assert_eq!(schedule(0.5).next_delay(), Duration::from_millis(500));
    }

    #[test]
    fn reset_restarts_the_schedule() {
        let mut backoff = schedule(1.0);
        for _ in 0..5 {
            backoff.next_delay();
        }
        assert_eq!(backoff.failures(), 5);
        backoff.reset();
        assert_eq!(backoff.failures(), 0);
        assert_eq!(backoff.ceiling(), BASE);
    }

    #[test]
    fn many_failures_do_not_overflow() {
        let mut backoff = schedule(1.0);
        for _ in 0..200 {
            backoff.next_delay();
        }
        assert_eq!(backoff.ceiling(), CAP);
    }

    #[test]
    fn system_random_stays_in_the_unit_interval() {
        let mut random = SystemRandom::new();
        for _ in 0..1000 {
            let unit = random.next_unit();
            assert!((0.0..1.0).contains(&unit));
        }
    }
}

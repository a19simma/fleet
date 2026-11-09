//! Background task that marks jobs with an expired lease `LOST` and closes work attempts past
//! their lease as lost.

use std::time::Duration;

use tokio::sync::{Notify, watch};
use tokio::time::{MissedTickBehavior, interval, sleep};

use crate::store::{Store, StoreError};

/// Seconds between reaper passes in the server binary.
pub const DEFAULT_REAP_PERIOD: Duration = Duration::from_secs(15);

/// Longest extra wait after consecutive failed passes.
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Wait after another failed pass: `period` first, then doubling up to [`MAX_BACKOFF`].
///
/// A `period` above the cap is kept as the floor.
#[must_use]
pub fn backoff_after(previous: Option<Duration>, period: Duration) -> Duration {
    previous
        .map_or(period, |wait| wait.saturating_mul(2))
        .min(MAX_BACKOFF.max(period))
}

/// Short fixed label for a failed pass. The error text is never logged.
#[must_use]
pub fn error_kind(err: &StoreError) -> &'static str {
    match err {
        StoreError::Database(sqlx::Error::PoolTimedOut) => "pool_timeout",
        StoreError::Database(sqlx::Error::PoolClosed) => "pool_closed",
        StoreError::Database(sqlx::Error::Io(_)) => "io",
        StoreError::Database(sqlx::Error::Database(_)) => "database",
        _ => "other",
    }
}

/// One pass: [`Store::reap_expired`] then [`Store::reap_work_leases`]. Returns both counts summed.
///
/// # Errors
///
/// The first failing statement. The work sweep then waits for the next pass.
pub async fn reap_pass(store: &Store) -> Result<u64, StoreError> {
    let jobs = store.reap_expired().await?;
    let attempts = store.reap_work_leases().await?;
    Ok(jobs.saturating_add(attempts))
}

/// Runs [`reap_pass`] every `period` until `stop` turns true.
///
/// A pass that reaps at least one job or attempt logs only the count and wakes `reaped`, which lets a
/// test wait on a signal instead of sleeping. A failed pass logs a fixed message with an
/// [`error_kind`] and sleeps [`backoff_after`]. The ticker uses delay mode and is already
/// due when the sleep ends, so the gap after a failure is the larger of that wait and
/// `period`: the first failure adds no delay. The wait resets after a pass succeeds and
/// `stop` cuts it short. `LOST` jobs are never requeued.
pub async fn run_reaper(
    store: Store,
    period: Duration,
    mut stop: watch::Receiver<bool>,
    reaped: Option<&Notify>,
) {
    let mut backoff = None;
    let mut ticker = interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = stop.wait_for(|halt| *halt) => return,
            _ = ticker.tick() => {}
        }
        match reap_pass(&store).await {
            Ok(0) => backoff = None,
            Ok(count) => {
                backoff = None;
                tracing::warn!(count, "marked expired leases lost");
                if let Some(signal) = reaped {
                    signal.notify_one();
                }
            }
            Err(err) => {
                let wait = backoff_after(backoff, period);
                backoff = Some(wait);
                tracing::error!(kind = error_kind(&err), "lease reaper pass failed");
                tokio::select! {
                    biased;
                    _ = stop.wait_for(|halt| *halt) => return,
                    () = sleep(wait) => {}
                }
            }
        }
    }
}

//! Retention sweep for job telemetry: events and summaries of old terminal jobs.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use tokio::sync::{Notify, watch};
use tokio::time::{MissedTickBehavior, interval};

use crate::reaper::error_kind;
use crate::store::{Store, StoreError};

/// Default days a terminal job's events are kept.
pub const DEFAULT_EVENTS_DAYS: u32 = 90;

/// Default days a terminal job's summary is kept.
pub const DEFAULT_SUMMARIES_DAYS: u32 = 365;

/// Shortest retention, in days.
pub const MIN_RETENTION_DAYS: u32 = 1;

/// Largest retention, in days.
pub const MAX_RETENTION_DAYS: u32 = 3650;

/// Default pause between sweeps.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3600);

/// Shortest accepted pause between sweeps.
pub const MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Default rows one delete statement may remove.
pub const DEFAULT_BATCH_ROWS: u32 = 5000;

/// Default delete statements per table in one sweep.
pub const DEFAULT_MAX_BATCHES: u32 = 20;

/// Why a [`Policy`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// The events retention is outside `MIN_RETENTION_DAYS` to `MAX_RETENTION_DAYS`.
    EventsDaysOutOfRange,
    /// The summaries retention is outside `MIN_RETENTION_DAYS` to `MAX_RETENTION_DAYS`.
    SummariesDaysOutOfRange,
    /// The summaries retention is shorter than the events retention.
    SummariesBeforeEvents,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventsDaysOutOfRange | Self::SummariesDaysOutOfRange => write!(
                f,
                "must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}"
            ),
            Self::SummariesBeforeEvents => {
                write!(f, "must be at least the events retention days")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// How long telemetry rows live and how a sweep is bounded.
///
/// Both ages count from the job's finish time. Only jobs in a terminal state qualify. The
/// fields are private so every value went through [`Policy::new`], which guarantees that a
/// summary outlives its events and that both ages sit inside the allowed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    events_days: u32,
    summaries_days: u32,
    batch_rows: u32,
    max_batches: u32,
}

impl Policy {
    /// Policy with the default batch bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when either age is outside `MIN_RETENTION_DAYS` to
    /// `MAX_RETENTION_DAYS`, or when `summaries_days` is below `events_days`.
    pub fn new(events_days: u32, summaries_days: u32) -> Result<Self, PolicyError> {
        let allowed = MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS;
        if !allowed.contains(&events_days) {
            return Err(PolicyError::EventsDaysOutOfRange);
        }
        if !allowed.contains(&summaries_days) {
            return Err(PolicyError::SummariesDaysOutOfRange);
        }
        if summaries_days < events_days {
            return Err(PolicyError::SummariesBeforeEvents);
        }
        Ok(Self {
            events_days,
            summaries_days,
            batch_rows: DEFAULT_BATCH_ROWS,
            max_batches: DEFAULT_MAX_BATCHES,
        })
    }

    /// The same ages with other batch bounds. The ages stay as validated.
    #[must_use]
    pub fn with_batches(self, batch_rows: u32, max_batches: u32) -> Self {
        Self {
            batch_rows,
            max_batches,
            ..self
        }
    }

    /// Days a terminal job's events are kept.
    #[must_use]
    pub fn events_days(&self) -> u32 {
        self.events_days
    }

    /// Days a terminal job's summary is kept.
    #[must_use]
    pub fn summaries_days(&self) -> u32 {
        self.summaries_days
    }

    /// Rows one delete statement may remove.
    #[must_use]
    pub fn batch_rows(&self) -> u32 {
        self.batch_rows
    }

    /// Delete statements per table in one sweep.
    #[must_use]
    pub fn max_batches(&self) -> u32 {
        self.max_batches
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            events_days: DEFAULT_EVENTS_DAYS,
            summaries_days: DEFAULT_SUMMARIES_DAYS,
            batch_rows: DEFAULT_BATCH_ROWS,
            max_batches: DEFAULT_MAX_BATCHES,
        }
    }
}

/// What one sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionStats {
    /// Event rows deleted.
    pub events_deleted: u64,
    /// Summary rows deleted.
    pub summaries_deleted: u64,
    /// Delete statements run on `job_event`.
    pub event_batches: u32,
    /// Delete statements run on `job_summary`.
    pub summary_batches: u32,
    /// A table used all `max_batches` statements and the last one was full, so rows may
    /// remain for the next sweep.
    pub capped: bool,
    /// Label of the error that ended the sweep early.
    pub error: Option<&'static str>,
}

struct Pass {
    deleted: u64,
    batches: u32,
    capped: bool,
}

async fn drain<F, Fut>(limit: u32, max_batches: u32, mut batch: F) -> (Pass, Option<StoreError>)
where
    F: FnMut(i64) -> Fut,
    Fut: Future<Output = Result<u64, StoreError>>,
{
    let mut pass = Pass {
        deleted: 0,
        batches: 0,
        capped: false,
    };
    while pass.batches < max_batches {
        pass.batches += 1;
        match batch(i64::from(limit)).await {
            Ok(rows) => {
                pass.deleted += rows;
                if rows < u64::from(limit) {
                    return (pass, None);
                }
            }
            Err(err) => return (pass, Some(err)),
        }
    }
    pass.capped = true;
    (pass, None)
}

fn days(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Runs one sweep: events first, then summaries.
///
/// Each table gets up to `max_batches` statements of `batch_rows` rows, and a statement
/// that deletes fewer rows than the limit ends that table. An error ends the sweep and is
/// returned as a label in [`RetentionStats::error`]. Nothing from a row is read.
pub async fn run_retention_once(store: &Store, policy: &Policy) -> RetentionStats {
    let mut stats = RetentionStats::default();
    let events_days = days(policy.events_days());
    let (pass, err) = drain(policy.batch_rows(), policy.max_batches(), |limit| {
        store.prune_events(events_days, limit)
    })
    .await;
    stats.events_deleted = pass.deleted;
    stats.event_batches = pass.batches;
    stats.capped = pass.capped;
    if let Some(err) = err {
        stats.error = Some(error_kind(&err));
        return stats;
    }
    let summaries_days = days(policy.summaries_days());
    let (pass, err) = drain(policy.batch_rows(), policy.max_batches(), |limit| {
        store.prune_summaries(summaries_days, limit)
    })
    .await;
    stats.summaries_deleted = pass.deleted;
    stats.summary_batches = pass.batches;
    stats.capped |= pass.capped;
    stats.error = err.as_ref().map(error_kind);
    stats
}

/// Sweeps every `period` until `stop` turns true.
///
/// The first sweep runs at once. A sweep that deleted rows logs the counts only. A failed
/// sweep logs a fixed message with an error label and the loop tries again next period.
/// `stop` cuts a sweep or the wait short. `swept` wakes after every sweep, so a test waits
/// on a signal instead of sleeping.
pub async fn run_retention(
    store: Store,
    policy: Policy,
    period: Duration,
    mut stop: watch::Receiver<bool>,
    swept: Option<&Notify>,
) {
    let mut ticker = interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = stop.wait_for(|halt| *halt) => return,
            _ = ticker.tick() => {}
        }
        let stats = tokio::select! {
            biased;
            _ = stop.wait_for(|halt| *halt) => return,
            stats = run_retention_once(&store, &policy) => stats,
        };
        if let Some(kind) = stats.error {
            tracing::error!(kind, "retention sweep failed");
        }
        if stats.events_deleted > 0 || stats.summaries_deleted > 0 {
            tracing::info!(
                events = stats.events_deleted,
                summaries = stats.summaries_deleted,
                capped = stats.capped,
                "retention sweep pruned telemetry"
            );
        }
        if let Some(signal) = swept {
            signal.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_may_not_be_shorter_than_events() {
        assert_eq!(
            Policy::new(100, 30),
            Err(PolicyError::SummariesBeforeEvents)
        );
        assert_eq!(
            Policy::new(100, 99),
            Err(PolicyError::SummariesBeforeEvents)
        );
        assert_eq!(
            Policy::new(3650, 1),
            Err(PolicyError::SummariesBeforeEvents)
        );
    }

    #[test]
    fn equal_and_longer_summaries_are_accepted() {
        assert_eq!(Policy::new(100, 100).map(|p| p.summaries_days()), Ok(100));
        assert_eq!(Policy::new(90, 365).map(|p| p.events_days()), Ok(90));
        assert_eq!(Policy::new(1, 1).map(|p| p.events_days()), Ok(1));
        assert_eq!(Policy::new(3650, 3650).map(|p| p.events_days()), Ok(3650));
        assert_eq!(Policy::new(1, 3650).map(|p| p.summaries_days()), Ok(3650));
    }

    #[test]
    fn events_days_outside_the_range_are_refused() {
        assert_eq!(Policy::new(0, 365), Err(PolicyError::EventsDaysOutOfRange));
        assert_eq!(
            Policy::new(3651, 3651),
            Err(PolicyError::EventsDaysOutOfRange)
        );
        assert_eq!(
            Policy::new(u32::MAX, u32::MAX),
            Err(PolicyError::EventsDaysOutOfRange)
        );
    }

    #[test]
    fn summaries_days_outside_the_range_are_refused() {
        assert_eq!(
            Policy::new(90, 0),
            Err(PolicyError::SummariesDaysOutOfRange)
        );
        assert_eq!(
            Policy::new(90, 3651),
            Err(PolicyError::SummariesDaysOutOfRange)
        );
        assert_eq!(
            Policy::new(1, u32::MAX),
            Err(PolicyError::SummariesDaysOutOfRange)
        );
    }

    #[test]
    fn range_is_checked_before_order() {
        assert_eq!(Policy::new(5, 0), Err(PolicyError::SummariesDaysOutOfRange));
        assert_eq!(Policy::new(0, 0), Err(PolicyError::EventsDaysOutOfRange));
    }

    #[test]
    fn batch_overrides_keep_the_ages() {
        let policy = Policy::new(7, 30).map(|p| p.with_batches(10, 2));
        assert_eq!(
            policy.map(|p| (p.events_days(), p.summaries_days())),
            Ok((7, 30))
        );
        assert_eq!(
            policy.map(|p| (p.batch_rows(), p.max_batches())),
            Ok((10, 2))
        );
    }

    #[test]
    fn default_policy_is_one_the_constructor_accepts() {
        let policy = Policy::default();
        assert_eq!(
            Policy::new(policy.events_days(), policy.summaries_days()),
            Ok(policy)
        );
        assert_eq!(policy.batch_rows(), DEFAULT_BATCH_ROWS);
        assert_eq!(policy.max_batches(), DEFAULT_MAX_BATCHES);
    }

    #[test]
    fn error_text_names_the_bounds() {
        assert_eq!(
            PolicyError::EventsDaysOutOfRange.to_string(),
            "must be between 1 and 3650"
        );
        assert_eq!(
            PolicyError::SummariesDaysOutOfRange.to_string(),
            "must be between 1 and 3650"
        );
        assert_eq!(
            PolicyError::SummariesBeforeEvents.to_string(),
            "must be at least the events retention days"
        );
    }
}

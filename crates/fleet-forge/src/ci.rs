//! The CI tally both REST adapters fold their check, status and run entries into.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub on items the sibling adapters share"
)]

use fleet_core::forge::CiResult;
use serde_json::Value;

use crate::ForgeError;

pub(crate) const MAX_SHA_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rank {
    Neutral,
    Success,
    Queued,
    Running,
    Failed,
}

#[derive(Debug, Default)]
pub(crate) struct Tally(Option<Rank>);

impl Tally {
    pub(crate) fn note(&mut self, rank: Rank) {
        self.0 = self.0.max(Some(rank));
    }

    /// Folds the run entries under `key`. A run is `completed` with a `conclusion`, `in_progress`
    /// or one of the queued words. Any other `status`, and a completed run without a string
    /// `conclusion`, is [`ForgeError::Malformed`].
    pub(crate) fn add_runs(&mut self, body: &Value, key: &str) -> Result<(), ForgeError> {
        for run in entries(body, key)? {
            let rank = match run.get("status").and_then(Value::as_str) {
                Some("completed") => match run.get("conclusion").and_then(Value::as_str) {
                    Some("success") => Rank::Success,
                    Some("neutral" | "skipped" | "stale") => Rank::Neutral,
                    Some(_) => Rank::Failed,
                    None => return Err(ForgeError::Malformed),
                },
                Some("in_progress") => Rank::Running,
                Some("queued" | "waiting" | "requested" | "pending") => Rank::Queued,
                _ => return Err(ForgeError::Malformed),
            };
            self.note(rank);
        }
        Ok(())
    }

    pub(crate) const fn result(&self) -> CiResult {
        match self.0 {
            None => CiResult::NoChecks,
            Some(Rank::Neutral) => CiResult::Neutral,
            Some(Rank::Success) => CiResult::Success,
            Some(Rank::Queued) => CiResult::Queued,
            Some(Rank::Running) => CiResult::InProgress,
            Some(Rank::Failed) => CiResult::Failure,
        }
    }
}

/// The array under `key`, failing closed when `total_count` says the page holds fewer entries
/// than exist.
pub(crate) fn entries<'a>(body: &'a Value, key: &str) -> Result<&'a [Value], ForgeError> {
    let list = body
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ForgeError::Malformed)?;
    let incomplete = body
        .get("total_count")
        .and_then(Value::as_u64)
        .is_some_and(|total| total > list.len() as u64);
    if incomplete {
        return Err(ForgeError::Malformed);
    }
    Ok(list)
}

pub(crate) fn valid_sha(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_SHA_BYTES && text.bytes().all(|b| b.is_ascii_hexdigit())
}

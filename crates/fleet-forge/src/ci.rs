//! The CI tally both REST adapters fold their check, status and run entries into.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub on items the sibling adapters share"
)]

use fleet_core::forge::CiResult;
use serde_json::Value;

use crate::ForgeError;

pub(crate) const MAX_SHA_BYTES: usize = 64;

/// The most checks `ci_checks` returns. A source that lists more fails closed as
/// [`ForgeError::Malformed`], the way a full page does. The broker's reply bound is the same
/// number.
pub const MAX_CHECKS: usize = 50;

/// The longest check name `ci_checks` accepts, in bytes. A longer name is
/// [`ForgeError::Malformed`]. The reading is stricter than a forge's own limit for names of
/// multibyte text.
pub const MAX_CHECK_NAME_BYTES: usize = 512;

/// The state of one check. The variants run from least to most severe, and the severest state
/// among the checks of a pull request is its [`CiResult`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// Skipped, stale or neutral: the check neither passed nor failed.
    Neutral,
    /// Passed.
    Success,
    /// Waiting to start.
    Queued,
    /// Started and not finished.
    Running,
    /// Failed, errored or timed out.
    Failed,
}

/// One check of a pull request: the name the forge sent and its state.
///
/// The name is at most [`MAX_CHECK_NAME_BYTES`] bytes, holds at least one letter or digit and
/// only letters, digits, ASCII graphic characters and spaces, so a caller may print it on one
/// line. Symbols, emoji and combining marks outside ASCII are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiCheck {
    name: String,
    state: Rank,
}

impl CiCheck {
    /// Builds a check from a forge's name and a state.
    ///
    /// # Errors
    ///
    /// [`ForgeError::Malformed`] when the name is over [`MAX_CHECK_NAME_BYTES`], holds no letter or
    /// digit, or holds a character that is not a letter, a digit, an ASCII graphic or a space. The
    /// Hangul fillers U+115F, U+1160, U+3164 and U+FFA0 do not count as letters.
    pub fn new(name: &str, state: Rank) -> Result<Self, ForgeError> {
        let ok = name.len() <= MAX_CHECK_NAME_BYTES
            && name.chars().all(allowed_char)
            && name.chars().any(char::is_alphanumeric);
        if ok {
            Ok(Self {
                name: name.to_owned(),
                state,
            })
        } else {
            Err(ForgeError::Malformed)
        }
    }

    /// The name as the forge sent it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The state of the check.
    #[must_use]
    pub const fn state(&self) -> Rank {
        self.state
    }
}

fn allowed_char(c: char) -> bool {
    (c.is_alphanumeric() && !hangul_filler(c)) || c.is_ascii_graphic() || c == ' '
}

/// The Hangul filler code points are letters by category and draw nothing.
const fn hangul_filler(c: char) -> bool {
    matches!(c, '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}')
}

#[derive(Debug, Default)]
pub(crate) struct Tally {
    top: Option<Rank>,
    entries: Vec<(Option<String>, Rank)>,
}

impl Tally {
    pub(crate) fn note(&mut self, rank: Rank) {
        self.top = self.top.max(Some(rank));
    }

    /// Records one entry: its label as the forge sent it, when it sent a string, and its rank.
    pub(crate) fn note_entry(&mut self, entry: &Value, label_key: &str, rank: Rank) {
        self.note(rank);
        let label = entry
            .get(label_key)
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.entries.push((label, rank));
    }

    /// The recorded entries as checks, in the order they were folded.
    ///
    /// # Errors
    ///
    /// [`ForgeError::Malformed`] when more than [`MAX_CHECKS`] entries were recorded or one has no
    /// acceptable name.
    pub(crate) fn checks(&self) -> Result<Vec<CiCheck>, ForgeError> {
        if self.entries.len() > MAX_CHECKS {
            return Err(ForgeError::Malformed);
        }
        self.entries
            .iter()
            .map(|(label, rank)| {
                CiCheck::new(label.as_deref().ok_or(ForgeError::Malformed)?, *rank)
            })
            .collect()
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
            self.note_entry(run, "name", rank);
        }
        Ok(())
    }

    pub(crate) const fn result(&self) -> CiResult {
        match self.top {
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

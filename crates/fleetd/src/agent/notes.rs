//! Job notes for subagent items a runner cannot load (ADR-0053).
//!
//! [`dropped_subagent_events`] resolves the Profile selection against the catalog for the
//! job's runner and returns one phase event per subagent item the runner dropped. Only Kimi
//! drops subagents, so a Claude or Codex job gets none. Items an admin disabled get no note
//! here: the runner did not drop them.

use fleet_core::catalog::{
    CatalogEntry, CatalogKind, NoteReason, ResolveError, RunnerKind, resolve,
};
use fleet_core::{Redactor, Selection};
use fleet_proto::v1 as pb;
use fleet_proto::{MAX_EVENT_DETAIL_BYTES, MAX_EVENTS_PER_JOB};

use super::{CLAUDE, codex, kimi};

fn runner_kind(agent: &str) -> Option<RunnerKind> {
    match agent {
        "" | CLAUDE => Some(RunnerKind::Claude),
        codex::NAME => Some(RunnerKind::Codex),
        kimi::NAME => Some(RunnerKind::Kimi),
        _ => None,
    }
}

/// Most per-item notes one job gets; the rest collapse into one summary note.
pub const MAX_DROPPED_NOTES: usize = 64;

/// Code points stripped besides controls, as sorted inclusive ranges: every `General_Category`
/// `Cf`, `Zl` and `Zp` code point plus the Unicode tag block U+E0000 to U+E007F. Taken from the
/// `Cf`, `Zl` and `Zp` entries of the generated table in `fetch.rs`, which comes from
/// `UnicodeData.txt` of Unicode 18.0.0 (<https://www.unicode.org/Public/UCD/latest/ucd/UnicodeData.txt>).
/// A test in `tests/runners.rs` checks every `Cc`, `Cf`, `Zl` and `Zp` code point against the
/// `unicode-general-category` crate.
const HIDDEN_RANGES: &[(u32, u32)] = &[
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE007F),
];

fn is_hidden(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    let code = u32::from(c);
    HIDDEN_RANGES
        .binary_search_by(|&(low, high)| {
            if high < code {
                std::cmp::Ordering::Less
            } else if low > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn strip_hidden(text: &str) -> String {
    text.chars().filter(|&c| !is_hidden(c)).collect()
}

/// Sanitises note text for a job event.
///
/// Control, format, line and paragraph separator and tag characters are dropped, the text is
/// redacted, dropped again in case redaction exposed more, then cut to
/// [`MAX_EVENT_DETAIL_BYTES`] on a character boundary. Stripping first lets a secret split by
/// invisible characters match the redactor; redacting before the cut keeps a secret that
/// straddles the cap from leaving a prefix.
#[must_use]
pub fn sanitise_note(text: &str, redactor: &Redactor) -> String {
    let stripped = strip_hidden(text);
    let redacted = strip_hidden(&redactor.redact_str(&stripped));
    let mut out = String::new();
    for c in redacted.chars() {
        if out.len() + c.len_utf8() > MAX_EVENT_DETAIL_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// One phase event per subagent item `agent` cannot load.
///
/// Events take `first_seq`, `first_seq + 1` and so on, all stamped `ts_ms`, and their
/// `detail` goes through [`sanitise_note`]. An unknown agent gets none. At most
/// [`MAX_DROPPED_NOTES`] items are named; the rest collapse into one "and N more dropped" note.
/// No event takes a `seq` of [`MAX_EVENTS_PER_JOB`] or more, the server drops those, and the
/// sequence stops instead of wrapping or repeating at `u32::MAX`.
///
/// # Errors
///
/// Returns the [`ResolveError`] of a selection or catalog that does not resolve.
pub fn dropped_subagent_events(
    agent: &str,
    selection: &Selection,
    catalog: &[CatalogEntry],
    redactor: &Redactor,
    first_seq: u32,
    ts_ms: u64,
) -> Result<Vec<pb::JobEvent>, ResolveError> {
    let Some(kind) = runner_kind(agent) else {
        return Ok(Vec::new());
    };
    let set = resolve(kind, selection, catalog)?;
    let ids: Vec<&str> = set
        .notes()
        .iter()
        .filter(|n| n.kind == CatalogKind::Subagent && n.reason == NoteReason::RunnerUnsupported)
        .map(|n| n.id.as_str())
        .collect();
    let slots = usize::try_from(MAX_EVENTS_PER_JOB.saturating_sub(first_seq)).unwrap_or(usize::MAX);
    let listed = if ids.len() <= MAX_DROPPED_NOTES.min(slots) {
        ids.len()
    } else {
        MAX_DROPPED_NOTES.min(slots.saturating_sub(1))
    };
    let mut texts: Vec<String> = ids
        .iter()
        .take(listed)
        .map(|id| format!("{agent} has no subagents: dropped {id}"))
        .collect();
    if listed < ids.len() && slots > 0 {
        texts.push(format!("and {} more dropped", ids.len() - listed));
    }
    let mut events = Vec::with_capacity(texts.len());
    let mut seq = Some(first_seq);
    for text in texts {
        let Some(current) = seq else { break };
        events.push(pb::JobEvent {
            seq: current,
            ts_ms,
            kind: pb::JobEventKind::Phase.into(),
            detail: Some(sanitise_note(&text, redactor)),
            ..pb::JobEvent::default()
        });
        seq = current.checked_add(1);
    }
    Ok(events)
}

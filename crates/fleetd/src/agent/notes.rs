//! Job notes for subagent items a runner cannot load (ADR-0053).
//!
//! [`dropped_subagent_events`] resolves the Profile selection against the catalog for the
//! job's runner and returns one phase event per subagent item the runner dropped. Only Kimi
//! drops subagents, so a Claude or Codex job gets none. Items an admin disabled get no note
//! here: the runner did not drop them.

use fleet_core::catalog::{
    CatalogEntry, CatalogKind, NoteReason, ResolveError, RunnerKind, resolve,
};
use fleet_core::text::{Cap, sanitise_text};
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

/// Sanitises note text for a job event.
///
/// Runs [`sanitise_text`] with a cap of [`MAX_EVENT_DETAIL_BYTES`] bytes: the text is redacted,
/// stripped of control, format, line and paragraph separator and tag characters and of newline
/// and tab, redacted and stripped again, then cut on a character boundary. Redacting before the
/// cut keeps a secret that straddles the cap from leaving a prefix.
#[must_use]
pub fn sanitise_note(text: &str, redactor: &Redactor) -> String {
    sanitise_text(redactor, text, Cap::Bytes(MAX_EVENT_DETAIL_BYTES)).text
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

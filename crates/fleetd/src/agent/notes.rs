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
use fleet_proto::MAX_EVENT_DETAIL_BYTES;
use fleet_proto::v1 as pb;

use super::{CLAUDE, codex, kimi};

fn runner_kind(agent: &str) -> Option<RunnerKind> {
    match agent {
        "" | CLAUDE => Some(RunnerKind::Claude),
        codex::NAME => Some(RunnerKind::Codex),
        kimi::NAME => Some(RunnerKind::Kimi),
        _ => None,
    }
}

fn is_hidden(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{e0000}'..='\u{e007f}')
}

/// Sanitises note text for a job event.
///
/// The text is redacted first, then control characters, line and paragraph separators and
/// bidi or tag characters are dropped, then the result is cut to
/// [`MAX_EVENT_DETAIL_BYTES`] on a character boundary.
#[must_use]
pub fn sanitise_note(text: &str, redactor: &Redactor) -> String {
    let mut out = String::new();
    for c in redactor.redact_str(text).chars() {
        if c.is_control() || is_hidden(c) || matches!(c, '\u{2028}' | '\u{2029}') {
            continue;
        }
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
/// `detail` goes through [`sanitise_note`]. An unknown agent gets none.
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
    let mut seq = first_seq;
    let mut events = Vec::new();
    for note in set.notes() {
        if note.kind != CatalogKind::Subagent || note.reason != NoteReason::RunnerUnsupported {
            continue;
        }
        let text = format!("{agent} has no subagents: dropped {}", note.id);
        events.push(pb::JobEvent {
            seq,
            ts_ms,
            kind: pb::JobEventKind::Phase.into(),
            detail: Some(sanitise_note(&text, redactor)),
            ..pb::JobEvent::default()
        });
        seq = seq.saturating_add(1);
    }
    Ok(events)
}

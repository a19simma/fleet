//! Tool-call hook payloads, reduced to the few fields job telemetry needs.
//!
//! Claude Code posts `PostToolUse` and `PostToolUseFailure` payloads that can hold whole file
//! contents and command output. [`reduce`] runs in the hook process and keeps only the tool use
//! id, the tool name, the exit code and the duration, so no body ever reaches the daemon.
//! [`ToolReport::from_reduced`] reads that reduced form in the daemon, and ignores any other field
//! a caller adds. [`HookHub`] hands each report to the running job it belongs to.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};

/// Hook event name Claude Code fires after a tool call succeeds.
pub const POST_TOOL_USE: &str = "PostToolUse";

/// Hook event name Claude Code fires after a tool call fails.
pub const POST_TOOL_USE_FAILURE: &str = "PostToolUseFailure";

const MAX_ID_BYTES: usize = 128;
const MAX_MAILBOX: usize = 1024;
const EXIT_PREFIX: &str = "Exit code ";
const ERROR_PREFIX: &str = "Error: ";

/// True for the two events this module reduces.
#[must_use]
pub fn is_tool_event(event: &str) -> bool {
    event == POST_TOOL_USE || event == POST_TOOL_USE_FAILURE
}

/// What one tool-call hook tells telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolReport {
    /// The `tool_use_id` of the call.
    pub tool_use_id: String,
    /// The tool name, such as `Bash`.
    pub tool_name: String,
    /// The exit code, when the payload has one.
    pub exit_code: Option<i32>,
    /// The duration Claude Code measured, in milliseconds.
    pub dur_ms: Option<u64>,
}

fn clean_id(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    let ok = !text.is_empty()
        && text.len() <= MAX_ID_BYTES
        && text.bytes().all(|b| b.is_ascii_graphic());
    ok.then(|| text.to_owned())
}

/// Reads the decimal exit code in `Exit code N` at the start of `text`.
///
/// `N` may carry a leading `-`, ends at the first non-digit and must fit an `i32`. Anything else
/// gives `None`.
#[must_use]
pub fn parse_exit_code(text: &str) -> Option<i32> {
    let rest = text.strip_prefix(EXIT_PREFIX)?;
    let (negative, digits) = rest
        .strip_prefix('-')
        .map_or((false, rest), |tail| (true, tail));
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    let number = digits.get(..end).filter(|n| !n.is_empty())?;
    let value: i64 = number.parse().ok()?;
    i32::try_from(if negative { -value } else { value }).ok()
}

fn exit_code(event: &str, tool: &str, payload: &Value) -> Option<i32> {
    if tool != "Bash" {
        return None;
    }
    if event == POST_TOOL_USE_FAILURE {
        if payload.get("is_interrupt").and_then(Value::as_bool) == Some(true) {
            return None;
        }
        return parse_exit_code(payload.get("error")?.as_str()?);
    }
    match payload.get("tool_response")? {
        Value::Object(map) => {
            (map.get("interrupted").and_then(Value::as_bool) != Some(true)).then_some(0)
        }
        Value::String(text) => parse_exit_code(text.strip_prefix(ERROR_PREFIX)?),
        _ => None,
    }
}

/// Reduces a raw hook payload to a [`ToolReport`].
///
/// `event` must be `PostToolUse` or `PostToolUseFailure`. Returns `None` for any other event,
/// for a payload that is not a JSON object, and for one without a usable `tool_use_id` or
/// `tool_name`. A successful `Bash` call has exit code 0, a failed one has the code in its
/// error text, and an interrupt or unparseable text has none. No other field is kept.
#[must_use]
pub fn reduce(event: &str, payload: &[u8]) -> Option<ToolReport> {
    if !is_tool_event(event) {
        return None;
    }
    let value: Value = serde_json::from_slice(payload).ok()?;
    let tool_use_id = clean_id(value.get("tool_use_id"))?;
    let tool_name = clean_id(value.get("tool_name"))?;
    let exit_code = exit_code(event, &tool_name, &value);
    let dur_ms = value.get("duration_ms").and_then(Value::as_u64);
    Some(ToolReport {
        tool_use_id,
        tool_name,
        exit_code,
        dur_ms,
    })
}

impl ToolReport {
    /// The reduced body the hook process posts to the daemon.
    #[must_use]
    pub fn to_body(&self) -> Vec<u8> {
        json!({
            "tool_use_id": self.tool_use_id,
            "tool_name": self.tool_name,
            "exit_code": self.exit_code,
            "dur_ms": self.dur_ms,
        })
        .to_string()
        .into_bytes()
    }

    /// Reads a body made by [`ToolReport::to_body`].
    ///
    /// Reads only the four reduced fields. A body without a usable `tool_use_id` or
    /// `tool_name`, or one that is not JSON, gives `None`.
    #[must_use]
    pub fn from_reduced(body: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(body).ok()?;
        Some(Self {
            tool_use_id: clean_id(value.get("tool_use_id"))?,
            tool_name: clean_id(value.get("tool_name"))?,
            exit_code: value
                .get("exit_code")
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok()),
            dur_ms: value.get("dur_ms").and_then(Value::as_u64),
        })
    }
}

/// Routes tool reports from the hook handler to the running job that owns them.
///
/// A job registers its id while its stream runs and takes its reports with [`HookHub::drain`].
/// A report for an id that is not registered, or that overflows a job's 1024-report mailbox, is
/// dropped and counted.
#[derive(Debug, Default)]
pub struct HookHub {
    mailboxes: Mutex<HashMap<String, VecDeque<ToolReport>>>,
    dropped: AtomicU64,
}

impl HookHub {
    /// A hub with no registered jobs.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Starts accepting reports for `job`. Reports already queued stay.
    pub fn register(&self, job: &str) {
        self.mailboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(job.to_owned())
            .or_default();
    }

    /// Stops accepting reports for `job` and discards the ones queued.
    pub fn unregister(&self, job: &str) {
        self.mailboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job);
    }

    /// Queues `report` for `job`. Returns false and counts a drop when the job is unknown or
    /// its mailbox is full.
    pub fn deliver(&self, job: &str, report: ToolReport) -> bool {
        let mut boxes = self
            .mailboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let queued = boxes.get_mut(job).is_some_and(|mailbox| {
            if mailbox.len() >= MAX_MAILBOX {
                return false;
            }
            mailbox.push_back(report);
            true
        });
        drop(boxes);
        if !queued {
            self.note_dropped();
        }
        queued
    }

    /// Counts one payload that never became a report.
    pub fn note_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes every report queued for `job`, oldest first.
    pub fn drain(&self, job: &str) -> Vec<ToolReport> {
        self.mailboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(job)
            .map(|mailbox| mailbox.drain(..).collect())
            .unwrap_or_default()
    }

    /// Payloads dropped so far.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

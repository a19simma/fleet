//! Pure stream-json parser for job telemetry.
//!
//! [`Telemetry`] reads one redacted stream-json line at a time and builds [`JobEvent`] values and
//! a [`JobSummary`]. It does no IO and never reads a clock: the caller passes each line's
//! arrival time as milliseconds since job start. Event content is never logged.
//!
//! The `permission_denied` system message shape is an assumption: `tool_name`, `tool_use_id` and
//! `message` fields. Inferred, not part of the design.

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::stuck::{Detector, Stuck, StuckRules};

const EVENT_OVERHEAD_BYTES: u64 = 48;
const HASH_HEX_CHARS: usize = 16;
const TRUNCATED: &str = "truncated";
const MODEL_CAP: usize = 128;
const EDIT_TOOLS: [&str; 3] = ["Edit", "Write", "MultiEdit"];

/// Caps on stored events and their text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most events kept before the truncation marker.
    pub max_events: usize,
    /// Most approximate bytes of events kept, see [`JobEvent::approx_size`].
    pub max_event_bytes: u64,
    /// Longest `cmd` in bytes.
    pub cmd_cap: usize,
    /// Longest `detail` in bytes.
    pub detail_cap: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_events: 2000,
            max_event_bytes: 1 << 20,
            cmd_cap: 512,
            detail_cap: 1024,
        }
    }
}

/// What a [`JobEvent`] records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EventKind {
    /// A finished tool call.
    #[default]
    Tool,
    /// A denied permission request.
    Denial,
    /// An API retry.
    ApiRetry,
    /// A phase change, or the truncation marker.
    Phase,
    /// A stuck-job signal.
    Stuck,
}

/// How the job ended, as the caller knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// The job succeeded.
    Succeeded,
    /// The job failed.
    Failed,
    /// The job was cancelled.
    Cancelled,
    /// The job hit its deadline.
    TimedOut,
}

/// One telemetry event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobEvent {
    /// Position in the stored event list.
    pub seq: u32,
    /// Arrival time in ms since job start.
    pub ts_ms: u64,
    /// Event kind.
    pub kind: EventKind,
    /// Id of the tool call.
    pub tool_use_id: Option<String>,
    /// Tool name.
    pub tool: Option<String>,
    /// False when the tool result was an error.
    pub ok: Option<bool>,
    /// Exit code, set only by a hook.
    pub exit_code: Option<i32>,
    /// Duration in ms: arrival delta until a hook gives the authoritative value.
    pub dur_ms: Option<u64>,
    /// Byte length of the result text.
    pub out_bytes: Option<u64>,
    /// First 16 hex chars of the SHA-256 of the result text.
    pub out_hash: Option<String>,
    /// Bash command or file path, cut at the command cap.
    pub cmd: Option<String>,
    /// Free text, cut at the detail cap.
    pub detail: Option<String>,
}

impl JobEvent {
    /// Approximate stored size: the text fields plus a fixed overhead.
    #[must_use]
    pub fn approx_size(&self) -> u64 {
        let text = [
            &self.tool_use_id,
            &self.tool,
            &self.out_hash,
            &self.cmd,
            &self.detail,
        ]
        .into_iter()
        .flatten()
        .map(String::len)
        .sum::<usize>();
        EVENT_OVERHEAD_BYTES.saturating_add(u64::try_from(text).unwrap_or(u64::MAX))
    }
}

/// Figures for a job. A figure never observed is `None`, never zero.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JobSummary {
    /// Turns from the result message.
    pub turns: Option<u64>,
    /// Wall time from the result message.
    pub duration_ms: Option<u64>,
    /// API time from the result message.
    pub duration_api_ms: Option<u64>,
    /// Stop reason from the result message.
    pub stop_reason: Option<String>,
    /// Result subtype, such as `success` or `error_max_turns`.
    pub result_subtype: Option<String>,
    /// Estimated cost in USD from the result message.
    pub cost_est_usd: Option<f64>,
    /// Input tokens.
    pub tokens_in: Option<u64>,
    /// Output tokens.
    pub tokens_out: Option<u64>,
    /// Cache read tokens.
    pub tokens_cache_read: Option<u64>,
    /// Cache write tokens.
    pub tokens_cache_write: Option<u64>,
    /// Tool calls started.
    pub tool_calls: Option<u64>,
    /// Tool results that were errors.
    pub tool_errors: Option<u64>,
    /// Bash calls started.
    pub bash_calls: Option<u64>,
    /// Bash calls with a nonzero exit code, `None` while no exit code is known.
    pub bash_nonzero: Option<u64>,
    /// Permission denials.
    pub denials: Option<u64>,
    /// API retries.
    pub api_retries: Option<u64>,
    /// Arrival time of the first `Edit`, `Write` or `MultiEdit` call.
    pub first_edit_ms: Option<u64>,
    /// True once a result message was seen.
    pub complete: bool,
    /// What was never observed.
    pub missing: Vec<String>,
    /// How the job ended, set by [`Telemetry::finish`].
    pub terminal: Option<Terminal>,
    /// First stuck rule that fired, recorded in shadow mode only.
    pub stuck: Option<Stuck>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Usage {
    input: Option<u64>,
    output: Option<u64>,
    cache_read: Option<u64>,
    cache_write: Option<u64>,
}

impl Usage {
    fn parse(value: &Value) -> Self {
        let field = |name: &str| value.get(name).and_then(Value::as_u64);
        Self {
            input: field("input_tokens"),
            output: field("output_tokens"),
            cache_read: field("cache_read_input_tokens"),
            cache_write: field("cache_creation_input_tokens"),
        }
    }

    fn add(self, other: Self) -> Self {
        let sum = |a: Option<u64>, b: Option<u64>| match (a, b) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
        };
        Self {
            input: sum(self.input, other.input),
            output: sum(self.output, other.output),
            cache_read: sum(self.cache_read, other.cache_read),
            cache_write: sum(self.cache_write, other.cache_write),
        }
    }
}

#[derive(Debug)]
struct Pending {
    tool: String,
    cmd: Option<String>,
    ts_ms: u64,
}

/// Incremental parser. Feed lines, read [`Telemetry::events`], call [`Telemetry::finish`].
#[derive(Debug)]
pub struct Telemetry {
    limits: Limits,
    events: Vec<JobEvent>,
    event_bytes: u64,
    truncated: bool,
    pending: HashMap<String, Pending>,
    fallback: BTreeMap<String, Usage>,
    anonymous_usages: u64,
    result_usage: Option<Usage>,
    result_seen: bool,
    observed: bool,
    ignored: u64,
    tool_calls: u64,
    tool_errors: u64,
    bash_calls: u64,
    denials: u64,
    api_retries: u64,
    result_denials: u64,
    exit_known: u64,
    exit_nonzero: u64,
    first_edit_ms: Option<u64>,
    turns: Option<u64>,
    duration_ms: Option<u64>,
    duration_api_ms: Option<u64>,
    stop_reason: Option<String>,
    result_subtype: Option<String>,
    cost_est_usd: Option<f64>,
    model: Option<String>,
    detector: Detector,
}

impl Telemetry {
    /// A parser with the given caps.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            events: Vec::new(),
            event_bytes: 0,
            truncated: false,
            pending: HashMap::new(),
            fallback: BTreeMap::new(),
            anonymous_usages: 0,
            result_usage: None,
            result_seen: false,
            observed: false,
            ignored: 0,
            tool_calls: 0,
            tool_errors: 0,
            bash_calls: 0,
            denials: 0,
            api_retries: 0,
            result_denials: 0,
            exit_known: 0,
            exit_nonzero: 0,
            first_edit_ms: None,
            turns: None,
            duration_ms: None,
            duration_api_ms: None,
            stop_reason: None,
            result_subtype: None,
            cost_est_usd: None,
            model: None,
            detector: Detector::new(StuckRules::default()),
        }
    }

    /// Replace the stuck thresholds. Call before the first line.
    #[must_use]
    pub fn with_stuck_rules(mut self, rules: StuckRules) -> Self {
        self.detector = Detector::new(rules);
        self
    }

    /// The stuck detector, for inspection.
    #[must_use]
    pub fn detector(&self) -> &Detector {
        &self.detector
    }

    /// Lines that were not valid JSON, not an object of a known type, or matched no tool call.
    #[must_use]
    pub fn ignored(&self) -> u64 {
        self.ignored
    }

    /// Tool calls that have no result yet.
    #[must_use]
    pub fn unmatched(&self) -> usize {
        self.pending.len()
    }

    /// Stored events, including the truncation marker.
    #[must_use]
    pub fn events(&self) -> &[JobEvent] {
        &self.events
    }

    /// Parse one redacted line that arrived `ts_ms` ms after job start.
    ///
    /// Returns the events stored for this line. Never panics on bad input.
    pub fn feed_line(&mut self, line: &str, ts_ms: u64) -> Vec<JobEvent> {
        self.feed_line_with(line, ts_ms, &str::to_owned)
    }

    /// Like [`Telemetry::feed_line`], with `redact` applied to decoded `tool`, `cmd` and `detail`
    /// text before it is cut at its cap, so a cut cannot leave a prefix of a secret that only
    /// matched after JSON decoding.
    ///
    /// The parser stays pure: `redact` is the caller's seam and does no I/O here.
    pub fn feed_line_with(
        &mut self,
        line: &str,
        ts_ms: u64,
        redact: &dyn Fn(&str) -> String,
    ) -> Vec<JobEvent> {
        let mut out = Vec::new();
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            self.ignored += 1;
            return out;
        };
        let kind = value.get("type").and_then(Value::as_str);
        let subtype = value.get("subtype").and_then(Value::as_str);
        match (kind, subtype) {
            (Some("system"), Some("init")) => self.on_init(&value),
            (Some("system"), Some("api_retry")) => self.on_retry(&value, ts_ms, &mut out),
            (Some("system"), Some("permission_denied")) => {
                self.on_denied(&value, ts_ms, redact, &mut out);
            }
            (Some("assistant"), _) => self.on_assistant(&value, ts_ms, redact),
            (Some("user"), _) => self.on_user(&value, ts_ms, &mut out),
            (Some("result"), _) => self.on_result(&value, ts_ms),
            _ => self.ignored += 1,
        }
        out
    }

    /// Fill the exit code and authoritative duration of an emitted tool event.
    ///
    /// A `None` argument leaves the field as it is. An unknown id does nothing and returns
    /// false, so a caller can retry once the tool event exists.
    pub fn apply_hook(
        &mut self,
        tool_use_id: &str,
        exit_code: Option<i32>,
        dur_ms: Option<u64>,
    ) -> bool {
        let Some(event) = self.events.iter_mut().find(|event| {
            event.kind == EventKind::Tool && event.tool_use_id.as_deref() == Some(tool_use_id)
        }) else {
            return false;
        };
        if let Some(code) = exit_code {
            if event.tool.as_deref() == Some("Bash") {
                match event.exit_code {
                    None => self.exit_known += 1,
                    Some(0) => {}
                    Some(_) => self.exit_nonzero -= 1,
                }
                if code != 0 {
                    self.exit_nonzero += 1;
                }
            }
            event.exit_code = Some(code);
        }
        if dur_ms.is_some() {
            event.dur_ms = dur_ms;
        }
        true
    }

    /// The model named by the `init` line, once one was seen and named one.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// The `subtype` of the final result line, once one was seen.
    #[must_use]
    pub fn result_subtype(&self) -> Option<&str> {
        self.result_subtype.as_deref()
    }

    /// The summary so far.
    #[must_use]
    pub fn summary(&self) -> JobSummary {
        let count = |n: u64| self.observed.then_some(n);
        let fallback = self
            .fallback
            .values()
            .copied()
            .reduce(Usage::add)
            .unwrap_or_default();
        let result = self.result_usage.unwrap_or_default();
        let mut missing = Vec::new();
        if !self.result_seen {
            missing.push("result".to_owned());
        }
        if self.exit_known == 0 {
            missing.push("exit_codes".to_owned());
        }
        if self.truncated {
            missing.push("events_truncated".to_owned());
        }
        if !self.pending.is_empty() {
            missing.push("tool_results".to_owned());
        }
        JobSummary {
            turns: self.turns,
            duration_ms: self.duration_ms,
            duration_api_ms: self.duration_api_ms,
            stop_reason: self.stop_reason.clone(),
            result_subtype: self.result_subtype.clone(),
            cost_est_usd: self.cost_est_usd,
            tokens_in: result.input.or(fallback.input),
            tokens_out: result.output.or(fallback.output),
            tokens_cache_read: result.cache_read.or(fallback.cache_read),
            tokens_cache_write: result.cache_write.or(fallback.cache_write),
            tool_calls: count(self.tool_calls),
            tool_errors: count(self.tool_errors),
            bash_calls: count(self.bash_calls),
            bash_nonzero: (self.exit_known > 0).then_some(self.exit_nonzero),
            denials: count(self.denials.max(self.result_denials)),
            api_retries: count(self.api_retries),
            first_edit_ms: self.first_edit_ms,
            complete: self.result_seen,
            missing,
            terminal: None,
            stuck: self.detector.fired(),
        }
    }

    /// End the stream. `complete` is true only when a result message arrived.
    #[must_use]
    pub fn finish(self, terminal: Terminal) -> JobSummary {
        JobSummary {
            terminal: Some(terminal),
            ..self.summary()
        }
    }

    fn emit(&mut self, mut event: JobEvent, out: &mut Vec<JobEvent>) {
        if self.truncated {
            return;
        }
        let size = event.approx_size();
        let over = self.events.len() >= self.limits.max_events
            || self.event_bytes.saturating_add(size) > self.limits.max_event_bytes;
        if over {
            self.truncated = true;
            event = JobEvent {
                ts_ms: event.ts_ms,
                kind: EventKind::Phase,
                detail: Some(TRUNCATED.to_owned()),
                ..JobEvent::default()
            };
        } else {
            self.event_bytes += size;
            event.seq = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
            self.detector.tool(&event);
        }
        event.seq = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        self.events.push(event.clone());
        out.push(event);
    }

    fn on_init(&mut self, value: &Value) {
        let model = value
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|model| is_plain_text(model));
        if self.model.is_none() {
            self.model = model.map(|model| cap(model, MODEL_CAP));
        }
    }

    fn on_retry(&mut self, value: &Value, ts_ms: u64, out: &mut Vec<JobEvent>) {
        self.observed = true;
        self.api_retries += 1;
        let detail = value
            .get("attempt")
            .and_then(Value::as_u64)
            .map(|attempt| cap(&format!("attempt {attempt}"), self.limits.detail_cap));
        let event = JobEvent {
            ts_ms,
            kind: EventKind::ApiRetry,
            detail,
            ..JobEvent::default()
        };
        self.emit(event, out);
    }

    fn on_denied(
        &mut self,
        value: &Value,
        ts_ms: u64,
        redact: &dyn Fn(&str) -> String,
        out: &mut Vec<JobEvent>,
    ) {
        self.observed = true;
        self.denials += 1;
        let text = |name: &str| value.get(name).and_then(Value::as_str);
        let event = JobEvent {
            ts_ms,
            kind: EventKind::Denial,
            tool_use_id: text("tool_use_id").map(str::to_owned),
            tool: text("tool_name").map(redact),
            detail: text("message").map(|message| cap(&redact(message), self.limits.detail_cap)),
            ..JobEvent::default()
        };
        self.emit(event, out);
    }

    fn on_assistant(&mut self, value: &Value, ts_ms: u64, redact: &dyn Fn(&str) -> String) {
        self.observed = true;
        let Some(message) = value.get("message") else {
            return;
        };
        if let Some(usage) = message.get("usage") {
            let key = if let Some(id) = message.get("id").and_then(Value::as_str) {
                id.to_owned()
            } else {
                self.anonymous_usages += 1;
                format!("\0anonymous{}", self.anonymous_usages)
            };
            self.fallback.insert(key, Usage::parse(usage));
        }
        let blocks = message
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        let mut has_tool = false;
        for block in blocks {
            if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                has_tool = true;
                self.on_tool_use(block, ts_ms, redact);
            }
        }
        let seq = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        self.detector.assistant(
            message.get("id").and_then(Value::as_str),
            has_tool,
            seq,
            ts_ms,
        );
    }

    fn on_tool_use(&mut self, block: &Value, ts_ms: u64, redact: &dyn Fn(&str) -> String) {
        let Some(id) = block.get("id").and_then(Value::as_str) else {
            self.ignored += 1;
            return;
        };
        let tool = block
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        self.tool_calls += 1;
        if tool == "Bash" {
            self.bash_calls += 1;
        }
        if self.first_edit_ms.is_none() && EDIT_TOOLS.contains(&tool) {
            self.first_edit_ms = Some(ts_ms);
        }
        let input = block.get("input");
        let key = if tool == "Bash" {
            "command"
        } else {
            "file_path"
        };
        let cmd = input
            .and_then(|input| input.get(key))
            .and_then(Value::as_str)
            .map(|cmd| cap(&redact(cmd), self.limits.cmd_cap));
        self.pending.insert(
            id.to_owned(),
            Pending {
                tool: redact(tool),
                cmd,
                ts_ms,
            },
        );
    }

    fn on_user(&mut self, value: &Value, ts_ms: u64, out: &mut Vec<JobEvent>) {
        let blocks = value
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for block in blocks {
            if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                self.on_tool_result(block, ts_ms, out);
            }
        }
    }

    fn on_tool_result(&mut self, block: &Value, ts_ms: u64, out: &mut Vec<JobEvent>) {
        let pending = block
            .get("tool_use_id")
            .and_then(Value::as_str)
            .and_then(|id| self.pending.remove(id).map(|pending| (id, pending)));
        let Some((id, pending)) = pending else {
            self.ignored += 1;
            return;
        };
        let is_error = block
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if is_error {
            self.tool_errors += 1;
        }
        let text = content_text(block.get("content"));
        let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
        let event = JobEvent {
            ts_ms,
            kind: EventKind::Tool,
            tool_use_id: Some(id.to_owned()),
            tool: Some(pending.tool),
            ok: Some(!is_error),
            dur_ms: Some(ts_ms.saturating_sub(pending.ts_ms)),
            out_bytes: Some(u64::try_from(text.len()).unwrap_or(u64::MAX)),
            out_hash: Some(digest.chars().take(HASH_HEX_CHARS).collect()),
            cmd: pending.cmd,
            ..JobEvent::default()
        };
        self.emit(event, out);
    }

    fn on_result(&mut self, value: &Value, ts_ms: u64) {
        self.observed = true;
        let seq = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        self.detector.end_turn(seq, ts_ms);
        self.result_seen = true;
        let number = |name: &str| value.get(name).and_then(Value::as_u64);
        let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
        self.turns = number("num_turns");
        self.duration_ms = number("duration_ms");
        self.duration_api_ms = number("duration_api_ms");
        self.stop_reason = text("stop_reason");
        self.result_subtype = text("subtype");
        self.cost_est_usd = value.get("total_cost_usd").and_then(Value::as_f64);
        self.result_usage = value.get("usage").map(Usage::parse);
        self.result_denials = value
            .get("permission_denials")
            .and_then(Value::as_array)
            .map_or(0, |denials| {
                u64::try_from(denials.len()).unwrap_or(u64::MAX)
            });
    }
}

fn content_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect(),
        _ => String::new(),
    }
}

/// True when `text` is non-empty and holds no control character.
///
/// Agent and tool output is untrusted, so a value that reaches storage or a terminal must pass this.
pub(crate) fn is_plain_text(text: &str) -> bool {
    !text.is_empty() && !text.chars().any(char::is_control)
}

fn cap(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let end = (0..=max)
        .rev()
        .find(|&index| text.is_char_boundary(index))
        .unwrap_or(0);
    text.get(..end).unwrap_or_default().to_owned()
}

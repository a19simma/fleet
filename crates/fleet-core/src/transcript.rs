//! Transcript entries and the per-chunk stream-json parser. Performs no IO.
//!
//! [`parse_chunk`] turns one stored chunk into [`Entry`] values. It never fails and never
//! panics: input it cannot read becomes [`Entry::Unknown`] or [`Entry::Truncated`].
//!
//! [`Transcript::build`] and [`Assembler`] join those entries into a view: each tool call with
//! its result, sub-agent work nested under its Task call, and per-turn usage.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt;

use serde_json::Value;

use crate::redact::Redactor;
use crate::text::is_hostile;

mod view;

pub use view::{
    Assembler, Item, MAX_NEST_DEPTH, MAX_VIEW_BYTES, MAX_VIEW_ENTRIES, Pair, PairStatus,
    Transcript, TurnUsage, Update, ViewLimits,
};

/// A line over this many bytes is not parsed and becomes [`Entry::Truncated`].
pub const MAX_CHUNK_BYTES: usize = 256 * 1024;
/// Cut for message, thinking, note and raw text, in bytes.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Cut for tool output, in bytes. The "bytes more" note comes after the cut.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024;
/// Cut for a tool call summary, in characters.
pub const MAX_SUMMARY_CHARS: usize = 200;
/// Cut for the compact JSON of a tool call input, in bytes.
pub const MAX_INPUT_BYTES: usize = 4 * 1024;
/// Cut for a tool name, in bytes.
pub const MAX_TOOL_NAME_BYTES: usize = 64;
/// Longest accepted [`ToolId`], in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Longest accepted kind, subtype, status or terminal reason, in bytes.
pub const MAX_LABEL_BYTES: usize = 64;
/// Most entries one line yields. A line with more blocks ends in one [`Entry::Truncated`].
pub const MAX_ENTRIES_PER_LINE: usize = 256;
/// Most keys of one JSON object that are scrubbed and kept in text. The rest are dropped.
pub const MAX_OBJECT_KEYS: usize = 1024;

/// Why a string is not a [`ToolId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolIdError {
    /// The id is empty.
    Empty,
    /// The id is over [`MAX_ID_BYTES`].
    TooLong,
    /// The id holds a byte outside printable ASCII without space.
    NotPrintable,
}

impl fmt::Display for ToolIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "tool id is empty"),
            Self::TooLong => write!(f, "tool id is too long"),
            Self::NotPrintable => write!(f, "tool id holds a non-printable byte"),
        }
    }
}

impl std::error::Error for ToolIdError {}

/// A tool call id: 1 to [`MAX_ID_BYTES`] bytes of printable ASCII without space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ToolId(String);

impl ToolId {
    /// Builds an id from `value`.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolIdError`] when `value` is empty, too long or not printable ASCII.
    pub fn new(value: &str) -> Result<Self, ToolIdError> {
        if value.is_empty() {
            return Err(ToolIdError::Empty);
        }
        if value.len() > MAX_ID_BYTES {
            return Err(ToolIdError::TooLong);
        }
        if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(ToolIdError::NotPrintable);
        }
        Ok(Self(value.to_owned()))
    }

    /// The id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who wrote a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// A user line.
    User,
    /// An assistant line.
    Assistant,
}

/// Token totals of a result line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Input tokens.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Input tokens read from the cache; `None` when the line did not report a count.
    pub cache_read_input_tokens: Option<u64>,
    /// Input tokens written to the cache; `None` when the line did not report a count.
    pub cache_creation_input_tokens: Option<u64>,
}

/// One displayable unit of a transcript.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Entry {
    /// Text from the user or the assistant. `subagent` is the Task call that owns it.
    Message {
        /// The author.
        role: Role,
        /// The sanitised text.
        text: String,
        /// The `parent_tool_use_id` of a sub-agent event.
        subagent: Option<ToolId>,
    },
    /// A thinking block.
    Thinking {
        /// The sanitised text.
        text: String,
    },
    /// A tool call.
    ToolCall {
        /// The call id.
        id: ToolId,
        /// The sanitised tool name.
        name: String,
        /// A one-line summary, at most [`Limits::summary_chars`] characters ([`MAX_SUMMARY_CHARS`]
        /// by default).
        summary: String,
        /// The sanitised, capped compact JSON of the input. A cut can end mid-token, so the text
        /// is not always valid JSON.
        input: String,
        /// The Task call that owns this call, for a sub-agent event.
        parent: Option<ToolId>,
    },
    /// A tool result.
    ToolResult {
        /// The id of the call it answers.
        id: ToolId,
        /// Whether the tool reported an error.
        is_error: bool,
        /// The sanitised, capped output.
        output: String,
        /// The Task call that owns this result, for a sub-agent event.
        parent: Option<ToolId>,
    },
    /// A system event.
    System {
        /// An allowlisted subtype, or `?`.
        subtype: String,
        /// Set for the `init`, `hook_started` and `hook_response` subtypes. No renderer reads it:
        /// the CLI prints one line and the web view always renders a closed row.
        collapsed: bool,
    },
    /// A rate limit event.
    RateLimit {
        /// The sanitised status.
        status: String,
        /// Share of the limit used, when reported.
        utilization: Option<f64>,
        /// Reset time in epoch seconds, when reported.
        resets_at: Option<u64>,
    },
    /// The final result line.
    Result {
        /// Whether the run ended in error.
        is_error: bool,
        /// Number of turns.
        turns: u64,
        /// Run time in milliseconds.
        duration_ms: u64,
        /// Cost in US dollars, when reported.
        cost_usd: Option<f64>,
        /// Token totals.
        usage: Usage,
        /// The sanitised terminal reason, when reported.
        terminal_reason: Option<String>,
        /// Number of permission denials.
        denials: u64,
    },
    /// A line fleetd wrote itself, starting with `fleet: `.
    FleetNote {
        /// The text after the prefix.
        text: String,
    },
    /// A chunk or line that was cut or is over [`MAX_CHUNK_BYTES`], or the end of a line over
    /// [`MAX_ENTRIES_PER_LINE`] entries. Never parsed.
    Truncated,
    /// Input the parser does not know.
    Unknown {
        /// An allowlisted type or subtype, or `?`.
        kind: String,
        /// The sanitised, capped raw text.
        raw: String,
    },
}

/// Caps used by [`parse_chunk_with`]. [`Limits::DEFAULT`] holds the `MAX_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Line cap in bytes.
    pub chunk_bytes: usize,
    /// Text cap in bytes.
    pub text_bytes: usize,
    /// Tool output cap in bytes.
    pub output_bytes: usize,
    /// Summary cap in characters.
    pub summary_chars: usize,
    /// Tool input cap in bytes.
    pub input_bytes: usize,
    /// Tool name cap in bytes.
    pub name_bytes: usize,
    /// Id cap in bytes. Never above [`MAX_ID_BYTES`].
    pub id_bytes: usize,
    /// Label cap in bytes.
    pub label_bytes: usize,
    /// Entry cap per line.
    pub line_entries: usize,
}

impl Limits {
    /// The production caps.
    pub const DEFAULT: Self = Self {
        chunk_bytes: MAX_CHUNK_BYTES,
        text_bytes: MAX_TEXT_BYTES,
        output_bytes: MAX_OUTPUT_BYTES,
        summary_chars: MAX_SUMMARY_CHARS,
        input_bytes: MAX_INPUT_BYTES,
        name_bytes: MAX_TOOL_NAME_BYTES,
        id_bytes: MAX_ID_BYTES,
        label_bytes: MAX_LABEL_BYTES,
        line_entries: MAX_ENTRIES_PER_LINE,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Parses one stored chunk with the production caps.
///
/// A chunk flagged `truncated` becomes one [`Entry::Truncated`] and is never parsed.
pub fn parse_chunk(chunk: &str, truncated: bool, redactor: Option<&Redactor>) -> Vec<Entry> {
    parse_chunk_with(chunk, truncated, redactor, &Limits::DEFAULT)
}

/// Parses one stored chunk with explicit caps.
///
/// The chunk is split on `\n`, one trailing `\r` is dropped from each line and empty lines
/// are skipped. A line over [`Limits::chunk_bytes`] becomes [`Entry::Truncated`] and is not
/// parsed. Lines are never joined across chunks.
///
/// Every decoded string is redacted first with nothing stripped, so a secret holding a
/// control or format character still matches. It is then stripped of hostile characters,
/// redacted again to catch a secret the strip reassembled, and then cut, so a secret across
/// the cut is still caught. JSON values kept as text (tool input, [`Entry::Unknown`] raw)
/// are scrubbed leaf by leaf, keys included, before they are serialised, so a secret holding
/// a quote, a backslash or a line break is matched on its decoded form. At most
/// [`MAX_OBJECT_KEYS`] keys of an object are kept; a key that collides after the scrub gets
/// one `#n` suffix and is dropped when that collides too.
///
/// In a single-line field every `\n`, `\r`, `\t`, VT, FF, NEL, U+2028 and U+2029 becomes one
/// space, except that a CRLF becomes one space. These are the Unicode line break classes
/// BK, CR, LF and NL, plus the tab.
///
/// A line that is not JSON may be a fragment that still holds JSON escapes. With a redactor
/// and a backslash in the text its text is never kept: [`Entry::Unknown`] raw is
/// `[unparseable line, N bytes]` and [`Entry::FleetNote`] text is
/// `[unparseable note, N bytes]`, because an escaped secret cannot be matched undecoded.
///
/// A line yields at most [`Limits::line_entries`] entries plus one [`Entry::Truncated`], which
/// ends a line with more blocks. The stdout and stderr fallback of a tool result without
/// content is scrubbed and cut once per line.
pub fn parse_chunk_with(
    chunk: &str,
    truncated: bool,
    redactor: Option<&Redactor>,
    limits: &Limits,
) -> Vec<Entry> {
    if truncated {
        return vec![Entry::Truncated];
    }
    let mut out = Vec::new();
    for raw in chunk.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        if line.len() > limits.chunk_bytes {
            out.push(Entry::Truncated);
            continue;
        }
        let cx = Cx::new(redactor, limits);
        parse_line(line, &cx, &mut out);
    }
    out
}

const FLEET_PREFIX: &str = "fleet: ";

struct Cx<'a> {
    redactor: Option<&'a Redactor>,
    limits: &'a Limits,
    fallback: OnceCell<String>,
    #[cfg(test)]
    fallback_builds: std::cell::Cell<usize>,
}

fn strip(text: &str) -> String {
    text.chars()
        .filter(|c| matches!(c, '\n' | '\t') || !is_hostile(*c))
        .collect()
}

fn is_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\t' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

fn flatten(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' if chars.peek() == Some(&'\n') => {}
            c if is_break(c) => out.push(' '),
            c if is_hostile(c) => {}
            _ => out.push(c),
        }
    }
    out
}

fn cut_bytes(text: &str, cap: usize) -> &str {
    if text.len() <= cap {
        return text;
    }
    let mut end = cap;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

fn cut_chars(text: &str, cap: usize) -> &str {
    match text.char_indices().nth(cap) {
        Some((end, _)) => text.get(..end).unwrap_or_default(),
        None => text,
    }
}

impl<'a> Cx<'a> {
    fn new(redactor: Option<&'a Redactor>, limits: &'a Limits) -> Self {
        Self {
            redactor,
            limits,
            fallback: OnceCell::new(),
            #[cfg(test)]
            fallback_builds: std::cell::Cell::new(0),
        }
    }
}

impl Cx<'_> {
    fn scrub_with(&self, text: &str, clean: fn(&str) -> String) -> String {
        let Some(redactor) = self.redactor else {
            return clean(text);
        };
        let first = redactor.redact_str(text);
        let cleaned = clean(&first);
        redactor.redact_str(&cleaned).into_owned()
    }

    fn scrub(&self, text: &str) -> String {
        self.scrub_with(text, strip)
    }

    fn flat(&self, text: &str) -> String {
        self.scrub_with(text, flatten)
    }

    fn multi(&self, text: &str, cap: usize) -> String {
        cut_bytes(&self.scrub(text), cap).to_owned()
    }

    fn single(&self, text: &str, cap: usize) -> String {
        cut_bytes(&self.flat(text), cap).to_owned()
    }

    fn text(&self, text: &str) -> String {
        self.multi(text, self.limits.text_bytes)
    }

    fn scrub_leaves(&self, value: &mut Value) {
        let mut stack = vec![value];
        while let Some(node) = stack.pop() {
            match node {
                Value::String(text) => *text = self.scrub(text),
                Value::Array(items) => stack.extend(items.iter_mut()),
                Value::Object(map) => {
                    let entries = std::mem::take(map);
                    let mut seen: HashMap<String, usize> = HashMap::new();
                    for (key, inner) in entries.into_iter().take(MAX_OBJECT_KEYS) {
                        let base = self.scrub(&key);
                        let n = seen.entry(base.clone()).or_insert(0);
                        let name = if *n == 0 { base } else { format!("{base}#{n}") };
                        *n += 1;
                        if !map.contains_key(&name) {
                            map.insert(name, inner);
                        }
                    }
                    stack.extend(map.values_mut());
                }
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }
    }

    fn compact(&self, value: &Value, cap: usize) -> String {
        let mut clean = value.clone();
        self.scrub_leaves(&mut clean);
        let text = serde_json::to_string(&clean).unwrap_or_default();
        cut_bytes(&text, cap).to_owned()
    }

    fn output(&self, text: &str) -> String {
        let clean = self.scrub(text);
        let kept = cut_bytes(&clean, self.limits.output_bytes);
        let more = clean.len() - kept.len();
        if more == 0 {
            kept.to_owned()
        } else {
            format!("{kept}\n[{more} bytes more]")
        }
    }

    fn summary(&self, text: &str) -> String {
        cut_chars(&self.flat(text), self.limits.summary_chars).to_owned()
    }

    fn label(&self, text: &str) -> String {
        let allowed = !text.is_empty()
            && text.len() <= self.limits.label_bytes
            && text.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/')
            });
        let clean = allowed
            && self
                .redactor
                .is_none_or(|r| matches!(r.redact_str(text), Cow::Borrowed(_)));
        if clean {
            text.to_owned()
        } else {
            "?".to_owned()
        }
    }

    fn tool_id(&self, text: &str) -> Option<ToolId> {
        if text.len() > self.limits.id_bytes {
            return None;
        }
        let id = ToolId::new(text).ok()?;
        let clean = self
            .redactor
            .is_none_or(|r| matches!(r.redact_str(text), Cow::Borrowed(_)));
        clean.then_some(id)
    }

    fn undecodable_text(&self, text: &str, what: &str) -> String {
        if self.redactor.is_some() && text.contains('\\') {
            format!("[unparseable {what}, {} bytes]", text.len())
        } else {
            self.single(text, self.limits.text_bytes)
        }
    }

    fn unknown_text(&self, line: &str) -> Entry {
        Entry::Unknown {
            kind: "?".to_owned(),
            raw: self.undecodable_text(line, "line"),
        }
    }

    fn fallback_output(&self, line: &Value) -> String {
        self.fallback
            .get_or_init(|| {
                #[cfg(test)]
                self.fallback_builds.set(self.fallback_builds.get() + 1);
                self.output(&fallback_text(line))
            })
            .clone()
    }

    fn unknown_value(&self, value: &Value) -> Entry {
        Entry::Unknown {
            kind: value
                .get("type")
                .and_then(Value::as_str)
                .map_or_else(|| "?".to_owned(), |k| self.label(k)),
            raw: self.compact(value, self.limits.text_bytes),
        }
    }
}

fn parse_line(line: &str, cx: &Cx<'_>, out: &mut Vec<Entry>) {
    parse_decoded(line, serde_json::from_str::<Value>(line).ok(), cx, out);
}

fn parse_decoded(line: &str, value: Option<Value>, cx: &Cx<'_>, out: &mut Vec<Entry>) {
    let Some(value) = value else {
        match line.strip_prefix(FLEET_PREFIX) {
            Some(note) => out.push(Entry::FleetNote {
                text: cx.undecodable_text(note, "note"),
            }),
            None => out.push(cx.unknown_text(line)),
        }
        return;
    };
    let Some(kind) = value.get("type").and_then(Value::as_str) else {
        out.push(cx.unknown_value(&value));
        return;
    };
    match kind {
        "system" => out.push(system(&value, cx)),
        "assistant" => message_line(&value, Role::Assistant, cx, out),
        "user" => message_line(&value, Role::User, cx, out),
        "result" => out.push(result(&value, cx)),
        "rate_limit_event" => out.push(rate_limit(&value, cx)),
        _ => out.push(cx.unknown_value(&value)),
    }
}

fn system(value: &Value, cx: &Cx<'_>) -> Entry {
    let Some(subtype) = value.get("subtype").and_then(Value::as_str) else {
        return cx.unknown_value(value);
    };
    let known = matches!(subtype, "init" | "hook_started" | "hook_response");
    Entry::System {
        subtype: cx.label(subtype),
        collapsed: known,
    }
}

fn rate_limit(value: &Value, cx: &Cx<'_>) -> Entry {
    let info = value.get("rate_limit_info");
    let Some(status) = info.and_then(|i| i.get("status")).and_then(Value::as_str) else {
        return cx.unknown_value(value);
    };
    Entry::RateLimit {
        status: cx.single(status, cx.limits.label_bytes),
        utilization: info
            .and_then(|i| i.get("utilization"))
            .and_then(Value::as_f64),
        resets_at: info.and_then(|i| i.get("resetsAt")).and_then(Value::as_u64),
    }
}

fn count(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn usage_of(usage: Option<&Value>) -> Usage {
    let tokens = |key: &str| usage.map_or(0, |u| count(u, key));
    let cache = |key: &str| usage.and_then(|u| u.get(key)).and_then(Value::as_u64);
    Usage {
        input_tokens: tokens("input_tokens"),
        output_tokens: tokens("output_tokens"),
        cache_read_input_tokens: cache("cache_read_input_tokens"),
        cache_creation_input_tokens: cache("cache_creation_input_tokens"),
    }
}

fn result(value: &Value, cx: &Cx<'_>) -> Entry {
    Entry::Result {
        is_error: value
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        turns: count(value, "num_turns"),
        duration_ms: count(value, "duration_ms"),
        cost_usd: value.get("total_cost_usd").and_then(Value::as_f64),
        usage: usage_of(value.get("usage")),
        terminal_reason: value
            .get("terminal_reason")
            .and_then(Value::as_str)
            .map(|r| cx.single(r, cx.limits.label_bytes)),
        denials: value
            .get("permission_denials")
            .and_then(Value::as_array)
            .map_or(0, |d| d.len() as u64),
    }
}

fn parent_of(value: &Value, cx: &Cx<'_>) -> Result<Option<ToolId>, ToolIdError> {
    match value.get("parent_tool_use_id") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => cx.tool_id(s).map(Some).ok_or(ToolIdError::NotPrintable),
        Some(_) => Err(ToolIdError::NotPrintable),
    }
}

fn message_line(value: &Value, role: Role, cx: &Cx<'_>, out: &mut Vec<Entry>) {
    let Ok(parent) = parent_of(value, cx) else {
        out.push(cx.unknown_value(value));
        return;
    };
    match value.pointer("/message/content") {
        Some(Value::String(text)) => out.push(Entry::Message {
            role,
            text: cx.text(text),
            subagent: parent,
        }),
        Some(Value::Array(blocks)) => {
            let start = out.len();
            for block in blocks {
                if out.len() - start >= cx.limits.line_entries {
                    out.push(Entry::Truncated);
                    break;
                }
                out.push(block_entry(block, value, role, parent.as_ref(), cx));
            }
        }
        _ => out.push(cx.unknown_value(value)),
    }
}

fn block_entry(
    block: &Value,
    line: &Value,
    role: Role,
    parent: Option<&ToolId>,
    cx: &Cx<'_>,
) -> Entry {
    let field = |key: &str| block.get(key).and_then(Value::as_str);
    let entry = match field("type") {
        Some("text") => field("text").map(|text| Entry::Message {
            role,
            text: cx.text(text),
            subagent: parent.cloned(),
        }),
        Some("thinking") => field("thinking").map(|text| Entry::Thinking {
            text: cx.text(text),
        }),
        Some("tool_use") => tool_call(block, parent, cx),
        Some("tool_result") => tool_result(block, line, parent, cx),
        _ => None,
    };
    entry.unwrap_or_else(|| cx.unknown_value(block))
}

fn tool_call(block: &Value, parent: Option<&ToolId>, cx: &Cx<'_>) -> Option<Entry> {
    let id = cx.tool_id(block.get("id")?.as_str()?)?;
    let name = block.get("name")?.as_str()?;
    let input = block.get("input").unwrap_or(&Value::Null);
    Some(Entry::ToolCall {
        id,
        name: cx.single(name, cx.limits.name_bytes),
        summary: cx.summary(&summary_source(name, input, cx.limits.summary_chars)),
        input: cx.compact(input, cx.limits.input_bytes),
        parent: parent.cloned(),
    })
}

fn summary_source(name: &str, input: &Value, short: usize) -> String {
    let key = match name {
        "Bash" => Some("command"),
        "Read" | "Edit" | "Write" => Some("file_path"),
        "WebFetch" => Some("url"),
        "Task" => Some("description"),
        _ => None,
    };
    if let Some(text) = key.and_then(|k| input.get(k)).and_then(Value::as_str) {
        return text.to_owned();
    }
    input
        .as_object()
        .into_iter()
        .flat_map(|map| map.values())
        .filter_map(Value::as_str)
        .find(|text| text.chars().count() <= short)
        .unwrap_or_default()
        .to_owned()
}

fn tool_result(block: &Value, line: &Value, parent: Option<&ToolId>, cx: &Cx<'_>) -> Option<Entry> {
    let id = cx.tool_id(block.get("tool_use_id")?.as_str()?)?;
    let raw = match block.get("content") {
        None | Some(Value::Null) => {
            return Some(Entry::ToolResult {
                id,
                is_error: is_error(block),
                output: cx.fallback_output(line),
                parent: parent.cloned(),
            });
        }
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => {
            let mut pieces: Vec<&str> = Vec::with_capacity(parts.len());
            for part in parts {
                match part.get("type").and_then(Value::as_str) {
                    Some("text") => pieces.push(part.get("text")?.as_str()?),
                    Some("image") => pieces.push("[image]"),
                    _ => return None,
                }
            }
            pieces.join("\n")
        }
        Some(_) => return None,
    };
    Some(Entry::ToolResult {
        id,
        is_error: is_error(block),
        output: cx.output(&raw),
        parent: parent.cloned(),
    })
}

fn is_error(block: &Value) -> bool {
    block
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn fallback_text(line: &Value) -> String {
    let part = |key: &str| {
        line.pointer("/tool_use_result")
            .and_then(|r| r.get(key))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    [part("stdout"), part("stderr")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_is_built_once_per_line() {
        let block = serde_json::json!({"type": "tool_result", "tool_use_id": "t1"});
        let line = serde_json::json!({
            "type": "user",
            "message": {"content": vec![block; 50]},
            "tool_use_result": {"stdout": "out", "stderr": "err"}
        });
        let cx = Cx {
            redactor: None,
            limits: &Limits::DEFAULT,
            fallback: OnceCell::new(),
            fallback_builds: std::cell::Cell::new(0),
        };
        let mut out = Vec::new();
        message_line(&line, Role::User, &cx, &mut out);
        assert_eq!(out.len(), 50);
        assert_eq!(cx.fallback_builds.get(), 1);
    }
}

//! OTLP/JSON logs parser for Claude Code timing events.
//!
//! [`parse_logs`] reads one already size-capped request body with a real `serde_json` parse and
//! maps `resourceLogs[].scopeLogs[].logRecords[]` to [`ClaudeEvent`] values. It does no IO and
//! never reads a clock. Attributes are `{key, value}` pairs whose value holds one of
//! `stringValue`, `intValue`, `doubleValue` or `boolValue`; an `intValue` may be a JSON string or
//! number, as the OTLP/JSON mapping allows. The event name comes from the `event.name` attribute,
//! else the record body's `stringValue`, with an optional `claude_code.` prefix.
//!
//! The parser fails closed. A repeated object key, nesting deeper than [`MAX_DEPTH`], a refused
//! string, a missing required attribute or a bad value on a known event refuses the whole body.
//! Unknown events are skipped and counted. Errors carry no input text.
//!
//! Commands are returned raw. Redaction happens downstream, so a caller must redact a
//! [`ToolResult::command`] before it stores, logs or forwards it. The `command` and `bash_command`
//! attribute names are an assumption, unverified against a captured Claude Code body.

use std::cell::Cell;
use std::fmt;

use fleet_proto::is_plain_text;
use serde::Deserializer;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

/// Longest event, tool, id, model and decision string in bytes.
pub const MAX_NAME_BYTES: usize = 256;
/// Longest command in bytes. A longer command is refused, never cut.
pub const MAX_COMMAND_BYTES: usize = 16 * 1024;
/// Largest accepted `duration_ms`.
pub const MAX_DURATION_MS: u64 = 366 * 24 * 60 * 60 * 1000;
/// Deepest JSON nesting accepted.
pub const MAX_DEPTH: usize = 16;
/// Longest string of any kind in bytes, checked while parsing.
const MAX_DURATION_F64: f64 = 31_622_400_000.0;
const MAX_STRING_BYTES: usize = 64 * 1024;
/// Most keys in one object.
const MAX_OBJECT_KEYS: usize = 256;
/// Most log records in one body.
pub const MAX_RECORDS: usize = 4096;

/// One timing event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaudeEvent {
    /// A model API call.
    ApiRequest(ApiRequest),
    /// A finished tool call.
    ToolResult(ToolResult),
    /// A permission decision for a tool call.
    ToolDecision(ToolDecision),
}

/// A model API call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    /// Request duration.
    pub duration_ms: u64,
    /// Model name when present.
    pub model: Option<String>,
}

/// A finished tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    /// Id that joins to the decision.
    pub tool_use_id: String,
    /// Tool name.
    pub tool_name: String,
    /// Execution time.
    pub duration_ms: u64,
    /// Whether the tool succeeded.
    pub success: bool,
    /// Raw command when present.
    pub command: Option<String>,
}

/// A permission decision for a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDecision {
    /// Id that joins to the result.
    pub tool_use_id: String,
    /// Tool name.
    pub tool_name: String,
    /// Decision text when present.
    pub decision: Option<String>,
}

/// Events from one body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Known events in body order.
    pub events: Vec<ClaudeEvent>,
    /// Records with an unknown event name.
    pub skipped: usize,
}

/// Why a body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Not valid JSON.
    Json,
    /// An object repeats a key.
    DuplicateKey,
    /// Nesting is too deep.
    TooDeep,
    /// A string is too long.
    TooLong,
    /// A list is too long.
    TooMany,
    /// A field has the wrong JSON type.
    WrongType(&'static str),
    /// A required field is absent.
    Missing(&'static str),
    /// A field has a refused value.
    Invalid(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ParseError {}

/// Parses an OTLP/JSON logs body.
///
/// # Errors
///
/// Returns a [`ParseError`] for invalid JSON, a repeated key, over-deep nesting, an over-long
/// string, too many records or attributes, or a known event with a missing or refused field.
pub fn parse_logs(body: &[u8]) -> Result<Parsed, ParseError> {
    let fail = Cell::new(None);
    let seed = Seed {
        depth: 0,
        fail: &fail,
    };
    let mut de = serde_json::Deserializer::from_slice(body);
    let Ok(root) = seed.deserialize(&mut de).and_then(|n| de.end().map(|()| n)) else {
        return Err(fail.get().unwrap_or(ParseError::Json));
    };
    let Node::Obj(root) = root else {
        return Err(ParseError::WrongType("body"));
    };
    let mut parsed = Parsed::default();
    let mut count = 0_usize;
    for resource in list(&root, "resourceLogs")? {
        let resource = object(resource, "resourceLogs")?;
        for scope in list(resource, "scopeLogs")? {
            let scope = object(scope, "scopeLogs")?;
            for rec in list(scope, "logRecords")? {
                count += 1;
                if count > MAX_RECORDS {
                    return Err(ParseError::TooMany);
                }
                read_record(object(rec, "logRecords")?, &mut parsed)?;
            }
        }
    }
    Ok(parsed)
}

#[derive(Debug)]
enum Node {
    Str(String),
    Int(i64),
    Float(f64),
    Huge,
    Bool(bool),
    Null,
    Arr(Vec<Self>),
    Obj(Vec<(String, Self)>),
}

#[derive(Clone, Copy)]
struct Seed<'a> {
    depth: usize,
    fail: &'a Cell<Option<ParseError>>,
}

impl Seed<'_> {
    fn refuse<E: de::Error>(self, why: ParseError) -> E {
        if self.fail.get().is_none() {
            self.fail.set(Some(why));
        }
        E::custom("refused")
    }

    fn string<E: de::Error>(self, v: &str) -> Result<String, E> {
        if v.len() > MAX_STRING_BYTES {
            return Err(self.refuse(ParseError::TooLong));
        }
        Ok(v.to_owned())
    }

    fn enter<E: de::Error>(self) -> Result<Self, E> {
        if self.depth >= MAX_DEPTH {
            return Err(self.refuse(ParseError::TooDeep));
        }
        Ok(Self {
            depth: self.depth + 1,
            fail: self.fail,
        })
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Node;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Node, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Node;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Node, E> {
        Ok(Node::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Node, E> {
        Ok(Node::Int(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Node, E> {
        Ok(i64::try_from(v).map_or(Node::Huge, Node::Int))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Node, E> {
        Ok(Node::Float(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Node, E> {
        self.string(v).map(Node::Str)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        let inner = self.enter()?;
        let mut out = Vec::new();
        while let Some(node) = seq.next_element_seed(inner)? {
            if out.len() >= MAX_RECORDS {
                return Err(self.refuse(ParseError::TooMany));
            }
            out.push(node);
        }
        Ok(Node::Arr(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let inner = self.enter()?;
        let mut out: Vec<(String, Node)> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_STRING_BYTES {
                return Err(self.refuse(ParseError::TooLong));
            }
            if out.iter().any(|(k, _)| *k == key) {
                return Err(self.refuse(ParseError::DuplicateKey));
            }
            if out.len() >= MAX_OBJECT_KEYS {
                return Err(self.refuse(ParseError::TooMany));
            }
            let value = map.next_value_seed(inner)?;
            out.push((key, value));
        }
        Ok(Node::Obj(out))
    }
}

type Obj = [(String, Node)];

fn field<'a>(obj: &'a Obj, key: &str) -> Option<&'a Node> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn object<'a>(node: &'a Node, what: &'static str) -> Result<&'a Obj, ParseError> {
    match node {
        Node::Obj(o) => Ok(o),
        _ => Err(ParseError::WrongType(what)),
    }
}

fn list<'a>(obj: &'a Obj, key: &'static str) -> Result<&'a [Node], ParseError> {
    match field(obj, key) {
        None => Ok(&[]),
        Some(Node::Arr(a)) => Ok(a),
        Some(_) => Err(ParseError::WrongType(key)),
    }
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Str(&'a str),
    Int(i64),
    Double(f64),
    Bool(bool),
    Other,
}

fn any_value(node: &Node) -> Result<Value<'_>, ParseError> {
    let obj = object(node, "value")?;
    let mut found = None;
    for (key, inner) in obj {
        let value = match (key.as_str(), inner) {
            ("stringValue", Node::Str(s)) => Value::Str(s),
            ("intValue" | "doubleValue", Node::Int(n)) => Value::Int(*n),
            ("intValue", Node::Str(s)) => Value::Int(parse_i64(s)?),
            ("doubleValue", Node::Float(f)) => Value::Double(*f),
            ("doubleValue", Node::Huge) => Value::Double(f64::INFINITY),
            ("boolValue", Node::Bool(b)) => Value::Bool(*b),
            ("stringValue" | "intValue" | "doubleValue" | "boolValue", _) => {
                return Err(ParseError::WrongType("value"));
            }
            _ => Value::Other,
        };
        if found.replace(value).is_some() {
            return Err(ParseError::Invalid("value"));
        }
    }
    found.ok_or(ParseError::Invalid("value"))
}

fn parse_i64(text: &str) -> Result<i64, ParseError> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::Invalid("intValue"));
    }
    text.parse().map_err(|_| ParseError::Invalid("intValue"))
}

struct Attrs<'a>(Vec<(&'a str, Value<'a>)>);

impl<'a> Attrs<'a> {
    fn read(rec: &'a Obj) -> Result<Self, ParseError> {
        let mut out: Vec<(&str, Value<'_>)> = Vec::new();
        for attr in list(rec, "attributes")? {
            if out.len() >= MAX_OBJECT_KEYS {
                return Err(ParseError::TooMany);
            }
            let attr = object(attr, "attributes")?;
            let key = match field(attr, "key") {
                Some(Node::Str(k)) => k.as_str(),
                Some(_) => return Err(ParseError::WrongType("key")),
                None => return Err(ParseError::Missing("key")),
            };
            let value = field(attr, "value").ok_or(ParseError::Missing("value"))?;
            if out.iter().any(|(k, _)| *k == key) {
                return Err(ParseError::DuplicateKey);
            }
            out.push((key, any_value(value)?));
        }
        Ok(Self(out))
    }

    fn get(&self, key: &str) -> Option<Value<'a>> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    fn name(&self, key: &'static str) -> Result<&'a str, ParseError> {
        match self.get(key) {
            None => Err(ParseError::Missing(key)),
            Some(Value::Str(s)) => plain(s, key),
            Some(_) => Err(ParseError::WrongType(key)),
        }
    }

    fn opt_name(&self, key: &'static str) -> Result<Option<&'a str>, ParseError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Str(s)) => plain(s, key).map(Some),
            Some(_) => Err(ParseError::WrongType(key)),
        }
    }

    fn duration(&self) -> Result<u64, ParseError> {
        const KEY: &str = "duration_ms";
        let ms = match self.get(KEY) {
            None => return Err(ParseError::Missing(KEY)),
            Some(Value::Int(n)) => u64::try_from(n).map_err(|_| ParseError::Invalid(KEY))?,
            Some(Value::Str(s)) => {
                if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ParseError::Invalid(KEY));
                }
                s.parse().map_err(|_| ParseError::Invalid(KEY))?
            }
            Some(Value::Double(f)) => {
                if !f.is_finite() || !(0.0..=MAX_DURATION_F64).contains(&f) {
                    return Err(ParseError::Invalid(KEY));
                }
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "range checked above"
                )]
                {
                    f.round() as u64
                }
            }
            Some(_) => return Err(ParseError::WrongType(KEY)),
        };
        if ms > MAX_DURATION_MS {
            return Err(ParseError::Invalid(KEY));
        }
        Ok(ms)
    }

    fn success(&self) -> Result<bool, ParseError> {
        match self.get("success") {
            None => Err(ParseError::Missing("success")),
            Some(Value::Bool(b)) => Ok(b),
            Some(Value::Str("true")) => Ok(true),
            Some(Value::Str("false")) => Ok(false),
            Some(_) => Err(ParseError::Invalid("success")),
        }
    }

    fn command(&self) -> Result<Option<String>, ParseError> {
        for key in ["command", "bash_command"] {
            match self.get(key) {
                None => {}
                Some(Value::Str(s)) => {
                    if s.len() > MAX_COMMAND_BYTES {
                        return Err(ParseError::TooLong);
                    }
                    return Ok((!s.is_empty()).then(|| s.to_owned()));
                }
                Some(_) => return Err(ParseError::WrongType(key)),
            }
        }
        Ok(None)
    }
}

fn plain<'a>(text: &'a str, what: &'static str) -> Result<&'a str, ParseError> {
    if text.len() > MAX_NAME_BYTES {
        return Err(ParseError::TooLong);
    }
    if !is_plain_text(text) {
        return Err(ParseError::Invalid(what));
    }
    Ok(text)
}

fn event_name<'a>(rec: &'a Obj, attrs: &Attrs<'a>) -> Result<&'a str, ParseError> {
    const KEY: &str = "event.name";
    let raw = match attrs.get(KEY) {
        Some(Value::Str(s)) => s,
        Some(_) => return Err(ParseError::WrongType(KEY)),
        None => match field(rec, "body") {
            Some(body) => match field(object(body, "body")?, "stringValue") {
                Some(Node::Str(s)) => s.as_str(),
                _ => return Err(ParseError::WrongType("body")),
            },
            None => return Err(ParseError::Missing(KEY)),
        },
    };
    let name = plain(raw, KEY)?;
    Ok(name.strip_prefix("claude_code.").unwrap_or(name))
}

fn read_record(rec: &Obj, out: &mut Parsed) -> Result<(), ParseError> {
    let attrs = Attrs::read(rec)?;
    let event = match event_name(rec, &attrs)? {
        "api_request" => ClaudeEvent::ApiRequest(ApiRequest {
            duration_ms: attrs.duration()?,
            model: attrs.opt_name("model")?.map(str::to_owned),
        }),
        "tool_result" => ClaudeEvent::ToolResult(ToolResult {
            tool_use_id: attrs.name("tool_use_id")?.to_owned(),
            tool_name: attrs.name("tool_name")?.to_owned(),
            duration_ms: attrs.duration()?,
            success: attrs.success()?,
            command: attrs.command()?,
        }),
        "tool_decision" => ClaudeEvent::ToolDecision(ToolDecision {
            tool_use_id: attrs.name("tool_use_id")?.to_owned(),
            tool_name: attrs.name("tool_name")?.to_owned(),
            decision: attrs.opt_name("decision")?.map(str::to_owned),
        }),
        _ => {
            out.skipped += 1;
            return Ok(());
        }
    };
    out.events.push(event);
    Ok(())
}

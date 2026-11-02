//! Kimi `wire.jsonl` timing.
//!
//! [`parse_wire`] reads one JSON object per line and pairs each `llm.request` record with the
//! `usage.record` that names it into a [`SpanKind::ApiWait`] span from the request time to the
//! usage time. Requests and usages may interleave. A line that is not a known record is counted,
//! never guessed at.
//!
//! The field names are UNVERIFIED (ADR-0055). No real Kimi capture was available, so they follow
//! the synthetic fixture `tests/fixtures/kimi-wire.synthetic.jsonl`: `type` holds `llm.request` or
//! `usage.record`; `id` names a request, `request_id` names the request a usage closes, and
//! `ts_ms` is an unsigned millisecond time. A real capture must replace them.
//!
//! Reads are bounded: a line over [`MAX_LINE_BYTES`] is dropped whole and counted, reading stops
//! after [`MAX_LINES`] lines, and at most [`MAX_PENDING`] requests wait for a usage. A repeated
//! object key at any level, nesting past [`MAX_DEPTH`] or a bad field value refuses that line.
//! Nothing here reads a clock or echoes input text.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, Read};

use fleet_core::timing::{Interval, Span, SpanKind};
use serde::Deserializer;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

/// Longest line in bytes, newline excluded. A longer line is dropped whole.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Most lines read. Reading stops there.
pub const MAX_LINES: usize = 100_000;
/// Most requests waiting for a usage. Later requests are counted and dropped.
pub const MAX_PENDING: usize = 1024;
/// Deepest JSON nesting accepted in one line.
pub const MAX_DEPTH: usize = 16;
/// Longest request id in bytes.
pub const MAX_ID_BYTES: usize = 256;
const MAX_OBJECT_KEYS: usize = 256;
const REQUEST: &str = "llm.request";
const USAGE: &str = "usage.record";

/// Counters for everything the parser did not turn into a span.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Lines read, blank and over-long ones included.
    pub lines: usize,
    /// Well-formed records of a type other than the two known ones.
    pub skipped_unknown: usize,
    /// Lines that are not JSON objects, repeat a key, or hold a bad field.
    pub malformed: usize,
    /// Lines over [`MAX_LINE_BYTES`].
    pub oversized: usize,
    /// Usage records with no waiting request.
    pub unpaired: usize,
    /// Requests dropped because [`MAX_PENDING`] were already waiting.
    pub dropped_requests: usize,
    /// Requests still waiting for a usage at the end.
    pub unclosed: usize,
    /// Whether reading stopped at [`MAX_LINES`] with input left.
    pub line_cap_hit: bool,
}

/// Spans and counters from one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireTiming {
    /// API wait spans in the order their usage records appear.
    pub spans: Vec<Span>,
    /// What was skipped.
    pub stats: Stats,
}

/// Parses a `wire.jsonl` stream into API wait spans.
///
/// # Errors
///
/// Returns the read error of `reader`. Bad content never errors; it is counted in [`Stats`].
pub fn parse_wire<R: BufRead>(mut reader: R) -> io::Result<WireTiming> {
    let mut out = WireTiming::default();
    let mut pending: BTreeMap<String, u64> = BTreeMap::new();
    let mut buf = Vec::new();
    loop {
        if out.stats.lines >= MAX_LINES {
            out.stats.line_cap_hit = !reader.fill_buf()?.is_empty();
            break;
        }
        match read_line(&mut reader, &mut buf)? {
            Line::Eof => break,
            Line::Over => {
                out.stats.lines += 1;
                out.stats.oversized += 1;
            }
            Line::Text => {
                out.stats.lines += 1;
                handle(&buf, &mut pending, &mut out);
            }
        }
    }
    out.stats.unclosed = pending.len();
    Ok(out)
}

enum Line {
    Eof,
    Over,
    Text,
}

fn read_line<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<Line> {
    buf.clear();
    let cap = u64::try_from(MAX_LINE_BYTES + 1).unwrap_or(u64::MAX);
    let n = reader.by_ref().take(cap).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(Line::Text);
    }
    if n <= MAX_LINE_BYTES {
        return Ok(Line::Text);
    }
    buf.clear();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        if let Some(i) = chunk.iter().position(|b| *b == b'\n') {
            reader.consume(i + 1);
            break;
        }
        let len = chunk.len();
        reader.consume(len);
    }
    Ok(Line::Over)
}

fn handle(line: &[u8], pending: &mut BTreeMap<String, u64>, out: &mut WireTiming) {
    if line.iter().all(u8::is_ascii_whitespace) {
        return;
    }
    let Some(record) = decode(line) else {
        out.stats.malformed += 1;
        return;
    };
    match record {
        Record::Unknown => out.stats.skipped_unknown += 1,
        Record::Request { id, ts_ms } => {
            if pending.contains_key(&id) {
                out.stats.malformed += 1;
            } else if pending.len() >= MAX_PENDING {
                out.stats.dropped_requests += 1;
            } else {
                pending.insert(id, ts_ms);
            }
        }
        Record::Usage { request_id, ts_ms } => {
            let Some(start) = pending.get(&request_id).copied() else {
                out.stats.unpaired += 1;
                return;
            };
            match Interval::new(start, ts_ms) {
                Ok(interval) => {
                    pending.remove(&request_id);
                    out.spans.push(Span {
                        kind: SpanKind::ApiWait,
                        interval,
                    });
                }
                Err(_) => out.stats.malformed += 1,
            }
        }
    }
}

enum Record {
    Unknown,
    Request { id: String, ts_ms: u64 },
    Usage { request_id: String, ts_ms: u64 },
}

fn decode(line: &[u8]) -> Option<Record> {
    let fail = Cell::new(false);
    let seed = Seed {
        depth: 0,
        fail: &fail,
    };
    let mut de = serde_json::Deserializer::from_slice(line);
    let root = seed.deserialize(&mut de).and_then(|n| de.end().map(|()| n));
    let Ok(Val::Obj(root)) = root else {
        return None;
    };
    let Some(Val::Str(kind)) = field(&root, "type") else {
        return None;
    };
    let ts = || match field(&root, "ts_ms") {
        Some(Val::UInt(v)) => Some(*v),
        _ => None,
    };
    let text = |key: &str| match field(&root, key) {
        Some(Val::Str(s)) if !s.is_empty() && s.len() <= MAX_ID_BYTES => Some(s.clone()),
        _ => None,
    };
    match kind.as_str() {
        REQUEST => Some(Record::Request {
            id: text("id")?,
            ts_ms: ts()?,
        }),
        USAGE => Some(Record::Usage {
            request_id: text("request_id")?,
            ts_ms: ts()?,
        }),
        _ => Some(Record::Unknown),
    }
}

fn field<'a>(obj: &'a [(String, Val)], key: &str) -> Option<&'a Val> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

enum Val {
    Str(String),
    UInt(u64),
    Obj(Vec<(String, Self)>),
    Other,
}

#[derive(Clone, Copy)]
struct Seed<'a> {
    depth: usize,
    fail: &'a Cell<bool>,
}

impl Seed<'_> {
    fn refuse<E: de::Error>(&self, msg: &'static str) -> E {
        self.fail.set(true);
        E::custom(msg)
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Val;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Val, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Val, E> {
        Ok(Val::Other)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Val, E> {
        Ok(u64::try_from(v).map_or(Val::Other, Val::UInt))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Val, E> {
        Ok(Val::UInt(v))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Val, E> {
        Ok(Val::Other)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Val, E> {
        Ok(Val::Str(v.to_owned()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Val, E> {
        Ok(Val::Other)
    }

    fn visit_none<E: de::Error>(self) -> Result<Val, E> {
        Ok(Val::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Val, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.refuse("too deep"));
        }
        let inner = Seed {
            depth: self.depth + 1,
            fail: self.fail,
        };
        while seq.next_element_seed(inner)?.is_some() {}
        Ok(Val::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Val, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.refuse("too deep"));
        }
        let inner = Seed {
            depth: self.depth + 1,
            fail: self.fail,
        };
        let mut out: Vec<(String, Val)> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.iter().any(|(k, _)| *k == key) {
                return Err(self.refuse("duplicate key"));
            }
            if out.len() >= MAX_OBJECT_KEYS {
                return Err(self.refuse("too many keys"));
            }
            let value = map.next_value_seed(inner)?;
            out.push((key, value));
        }
        if self.depth == 0 {
            Ok(Val::Obj(out))
        } else {
            Ok(Val::Other)
        }
    }
}

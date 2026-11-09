//! The `.ralph` file format: a strict parser and a canonical renderer. Performs no IO.
//!
//! The input is untrusted text. [`parse`] refuses a duplicate key at any nesting level, a document
//! nested deeper than [`MAX_JSON_DEPTH`], an array or object over [`MAX_JSON_ITEMS`] entries and any
//! field of the wrong type, then validates the whole file as a [`Graph`]. Every refusal is a
//! fixed message that holds no text of the file. [`render`] writes the same two files back in one
//! canonical form, so a parse of a render gives the same value and a render of that is byte-equal.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fleet_core::graph::{
    Graph, MAX_DEPENDS, MAX_NODE_SLICES, MAX_NODES, MAX_SLICES, Node, RepoPath, validate,
};
use serde::Serialize;
use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};

use super::{MAX_BODY_BYTES, MAX_TITLE_CHARS, MAX_WHY_CHARS, WorkFault, ident, line, lines};

/// Deepest array and object nesting a file may have. A valid `tasks.json` needs three.
pub(super) const MAX_JSON_DEPTH: usize = 6;
/// Most entries in one array or object.
pub(super) const MAX_JSON_ITEMS: usize = 4096;
/// Most failed attempts a task may record. The importer creates one attempt row per failure.
pub(super) const MAX_IMPORT_FAILS: u32 = 100;
/// Most lines of `progress.md` or `docs-backlog.md` the importer reads.
pub(super) const MAX_IMPORT_LINES: usize = 50_000;
/// Most `DEFER` lines one import stores.
pub(super) const MAX_IMPORT_DEFERS: usize = 2000;
/// Most characters of a slice role.
const MAX_ROLE_CHARS: usize = 500;
/// Longest field name an importer note repeats.
const MAX_FIELD_NAME_BYTES: usize = 32;

enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Other,
    Str(String),
    Arr(Vec<Self>),
    Obj(Vec<(String, Self)>),
}

#[derive(Clone, Copy)]
struct Strict {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Json;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a json value")
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Int(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Json, E> {
        Ok(i64::try_from(value).map_or(Json::Other, Json::Int))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Json, E> {
        Ok(Json::Other)
    }

    fn visit_str<E>(self, value: &str) -> Result<Json, E> {
        Ok(Json::Str(value.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("too deep"));
        }
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Self {
            depth: self.depth + 1,
        })? {
            if items.len() == MAX_JSON_ITEMS {
                return Err(A::Error::custom("too many entries"));
            }
            items.push(item);
        }
        Ok(Json::Arr(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("too deep"));
        }
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if entries.len() == MAX_JSON_ITEMS {
                return Err(A::Error::custom("too many entries"));
            }
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom("duplicate key"));
            }
            let value = map.next_value_seed(Self {
                depth: self.depth + 1,
            })?;
            entries.push((key, value));
        }
        Ok(Json::Obj(entries))
    }
}

fn read(text: &str, what: &'static str) -> Result<Json, WorkFault> {
    let mut de = serde_json::Deserializer::from_str(text);
    let value = Strict { depth: 0 }
        .deserialize(&mut de)
        .map_err(|_| WorkFault::Invalid(what))?;
    de.end().map_err(|_| WorkFault::Invalid(what))?;
    Ok(value)
}

/// One task of `tasks.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Task {
    pub(super) id: String,
    pub(super) title: String,
    pub(super) acceptance: String,
    pub(super) slices: Vec<String>,
    pub(super) depends: Vec<String>,
    pub(super) why: String,
    pub(super) passes: bool,
    pub(super) fails: u32,
    pub(super) blocked: bool,
}

/// One slice of `slices.json`. Paths are normalised and sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SliceDef {
    pub(super) name: String,
    pub(super) role: String,
    pub(super) paths: Vec<String>,
}

/// A parsed and validated `.ralph` graph.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Parsed {
    pub(super) tasks: Vec<Task>,
    pub(super) slices: Vec<SliceDef>,
    pub(super) mergeable: Vec<String>,
    pub(super) notes: Vec<String>,
}

fn string(value: Json, what: &'static str) -> Result<String, WorkFault> {
    match value {
        Json::Str(text) => Ok(text),
        _ => Err(WorkFault::Invalid(what)),
    }
}

fn strings(value: Json, max: usize, what: &'static str) -> Result<Vec<String>, WorkFault> {
    let Json::Arr(items) = value else {
        return Err(WorkFault::Invalid(what));
    };
    if items.len() > max {
        return Err(WorkFault::Invalid(what));
    }
    let mut out = Vec::new();
    for item in items {
        let text = string(item, what)?;
        if !ident(&text) || out.contains(&text) {
            return Err(WorkFault::Invalid(what));
        }
        out.push(text);
    }
    Ok(out)
}

struct Tally {
    unknown: BTreeSet<String>,
    no_slices: usize,
    stray_why: usize,
}

fn task(value: Json, tally: &mut Tally) -> Result<Task, WorkFault> {
    let Json::Obj(entries) = value else {
        return Err(WorkFault::Invalid("tasks.json: a task is not an object"));
    };
    let mut task = Task {
        id: String::new(),
        title: String::new(),
        acceptance: String::new(),
        slices: Vec::new(),
        depends: Vec::new(),
        why: String::new(),
        passes: false,
        fails: 0,
        blocked: false,
    };
    let (mut has_id, mut has_title, mut has_slices) = (false, false, false);
    for (name, value) in entries {
        match name.as_str() {
            "id" => {
                task.id = string(value, "tasks.json: invalid id")?;
                has_id = true;
            }
            "title" => {
                task.title = string(value, "tasks.json: invalid title")?;
                has_title = true;
            }
            "acceptance" => task.acceptance = string(value, "tasks.json: invalid acceptance")?,
            "slices" => {
                task.slices = strings(value, MAX_NODE_SLICES, "tasks.json: invalid slices")?;
                has_slices = true;
            }
            "depends" => {
                task.depends = strings(value, MAX_DEPENDS, "tasks.json: invalid depends")?;
            }
            "why" => task.why = string(value, "tasks.json: invalid why")?,
            "passes" => match value {
                Json::Bool(flag) => task.passes = flag,
                _ => return Err(WorkFault::Invalid("tasks.json: invalid passes")),
            },
            "fails" => match value {
                Json::Int(count) => {
                    task.fails = u32::try_from(count)
                        .ok()
                        .filter(|n| *n <= MAX_IMPORT_FAILS)
                        .ok_or(WorkFault::Invalid("tasks.json: invalid fails"))?;
                }
                _ => return Err(WorkFault::Invalid("tasks.json: invalid fails")),
            },
            "blocked" => match value {
                Json::Bool(flag) => task.blocked = flag,
                Json::Null => {}
                _ => return Err(WorkFault::Invalid("tasks.json: invalid blocked")),
            },
            other => {
                if tally.unknown.len() < MAX_JSON_ITEMS {
                    tally.unknown.insert(other.to_owned());
                }
            }
        }
    }
    if !has_id || !ident(&task.id) {
        return Err(WorkFault::Invalid("tasks.json: invalid id"));
    }
    if !has_title || !line(&task.title, MAX_TITLE_CHARS) {
        return Err(WorkFault::Invalid("tasks.json: invalid title"));
    }
    if !lines(&task.acceptance, MAX_BODY_BYTES) {
        return Err(WorkFault::Invalid("tasks.json: invalid acceptance"));
    }
    if !task.why.is_empty() && !line(&task.why, MAX_WHY_CHARS) {
        return Err(WorkFault::Invalid("tasks.json: invalid why"));
    }
    if task.depends.contains(&task.id) {
        return Err(WorkFault::Invalid("tasks.json: a task depends on itself"));
    }
    if !has_slices {
        tally.no_slices += 1;
    }
    if task.depends.is_empty() && !task.why.is_empty() {
        tally.stray_why += 1;
    }
    Ok(task)
}

fn slice_defs(value: Json) -> Result<Parsed, WorkFault> {
    let Json::Obj(entries) = value else {
        return Err(WorkFault::Invalid("slices.json: not an object"));
    };
    let mut parsed = Parsed::default();
    for (name, value) in entries {
        match name.as_str() {
            "slices" => parsed.slices = slices(value)?,
            "mergeable" => parsed.mergeable = paths(value, "slices.json: invalid mergeable")?,
            other => parsed.notes.push(format!(
                "slices.json: field {} is not stored",
                field_name(other)
            )),
        }
    }
    Ok(parsed)
}

fn slices(value: Json) -> Result<Vec<SliceDef>, WorkFault> {
    let Json::Obj(entries) = value else {
        return Err(WorkFault::Invalid("slices.json: invalid slices"));
    };
    if entries.len() > MAX_SLICES {
        return Err(WorkFault::Invalid("slices.json: too many slices"));
    }
    let mut out = BTreeMap::new();
    for (name, value) in entries {
        if !ident(&name) {
            return Err(WorkFault::Invalid("slices.json: invalid slice name"));
        }
        let Json::Obj(fields) = value else {
            return Err(WorkFault::Invalid("slices.json: invalid slice"));
        };
        let (mut slice_paths, mut role) = (Vec::new(), String::new());
        for (field, value) in fields {
            match field.as_str() {
                "paths" => slice_paths = paths(value, "slices.json: invalid paths")?,
                "role" => {
                    role = string(value, "slices.json: invalid role")?;
                    if !role.is_empty() && !line(&role, MAX_ROLE_CHARS) {
                        return Err(WorkFault::Invalid("slices.json: invalid role"));
                    }
                }
                _ => {}
            }
        }
        out.insert(
            name.clone(),
            SliceDef {
                name,
                role,
                paths: slice_paths,
            },
        );
    }
    Ok(out.into_values().collect())
}

fn paths(value: Json, what: &'static str) -> Result<Vec<String>, WorkFault> {
    let Json::Arr(items) = value else {
        return Err(WorkFault::Invalid(what));
    };
    let mut out = BTreeSet::new();
    for item in items {
        let raw = string(item, what)?;
        let path = RepoPath::new(&raw).map_err(|_| WorkFault::Invalid(what))?;
        out.insert(path.as_str().to_owned());
    }
    Ok(out.into_iter().collect())
}

fn field_name(name: &str) -> String {
    if name.len() <= MAX_FIELD_NAME_BYTES && ident(name) {
        name.to_owned()
    } else {
        "with an unprintable name".to_owned()
    }
}

/// The graph of a parsed file, as the graph module checks it.
pub(super) fn graph_of(parsed: &Parsed) -> Graph {
    Graph {
        nodes: parsed
            .tasks
            .iter()
            .map(|t| Node {
                id: t.id.clone(),
                depends: t.depends.clone(),
                why: t.why.clone(),
                slices: Some(t.slices.clone()),
                done: false,
            })
            .collect(),
        slices: parsed
            .slices
            .iter()
            .map(|s| (s.name.clone(), s.paths.clone()))
            .collect(),
        mergeable: parsed.mergeable.clone(),
    }
}

/// Parses and validates `tasks.json` and `slices.json`. An empty `slices_json` is an empty set.
///
/// # Errors
///
/// [`WorkFault::Invalid`] with a fixed message for JSON that is malformed, has a duplicate key,
/// is too deep or too wide, or has a field of the wrong type or a value that breaks a field
/// rule, and [`WorkFault::Graph`] for a duplicate id, an unknown dependency or slice, a
/// cycle, a bad or overlapping path or a bound.
pub(super) fn parse(tasks_json: &str, slices_json: &str) -> Result<Parsed, WorkFault> {
    let mut parsed = if slices_json.trim().is_empty() {
        Parsed::default()
    } else {
        slice_defs(read(slices_json, "slices.json: invalid JSON")?)?
    };
    let Json::Arr(items) = read(tasks_json, "tasks.json: invalid JSON")? else {
        return Err(WorkFault::Invalid("tasks.json: not an array"));
    };
    if items.len() > MAX_NODES {
        return Err(WorkFault::Invalid("tasks.json: too many tasks"));
    }
    let mut tally = Tally {
        unknown: BTreeSet::new(),
        no_slices: 0,
        stray_why: 0,
    };
    for item in items {
        parsed.tasks.push(task(item, &mut tally)?);
    }
    validate(&graph_of(&parsed)).map_err(|errors| {
        WorkFault::Graph(
            errors
                .into_iter()
                .next()
                .unwrap_or(fleet_core::graph::GraphError::Truncated),
        )
    })?;
    if !tally.unknown.is_empty() {
        let names: Vec<String> = tally.unknown.iter().map(|n| field_name(n)).collect();
        parsed.notes.push(format!(
            "tasks.json: fields not stored: {}",
            names.join(", ")
        ));
    }
    if tally.no_slices > 0 {
        parsed.notes.push(format!(
            "tasks.json: {} tasks have no slices key and own no slice here",
            tally.no_slices
        ));
    }
    if tally.stray_why > 0 {
        parsed.notes.push(format!(
            "tasks.json: {} tasks have a why but no depends; the why is not stored",
            tally.stray_why
        ));
    }
    Ok(parsed)
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if passes a reference"
)]
fn is_false(flag: &bool) -> bool {
    !*flag
}

#[derive(Serialize)]
struct OutTask<'a> {
    id: &'a str,
    title: &'a str,
    acceptance: &'a str,
    slices: &'a [String],
    depends: &'a [String],
    why: &'a str,
    passes: bool,
    fails: u32,
    #[serde(skip_serializing_if = "is_false")]
    blocked: bool,
}

#[derive(Serialize)]
struct OutSlice<'a> {
    paths: &'a [String],
    role: &'a str,
}

#[derive(Serialize)]
struct OutSlices<'a> {
    slices: BTreeMap<&'a str, OutSlice<'a>>,
    mergeable: &'a [String],
}

/// Renders `tasks.json` and `slices.json` in one canonical form: two-space indent, tasks in the
/// given order, slice names in byte order, one trailing newline.
///
/// # Errors
///
/// [`WorkFault::Invalid`] when a value cannot be written, which a validated input never causes.
pub(super) fn render(
    tasks: &[Task],
    slice_defs: &[SliceDef],
    mergeable: &[String],
) -> Result<(String, String), WorkFault> {
    let out: Vec<OutTask<'_>> = tasks
        .iter()
        .map(|t| OutTask {
            id: &t.id,
            title: &t.title,
            acceptance: &t.acceptance,
            slices: &t.slices,
            depends: &t.depends,
            why: &t.why,
            passes: t.passes,
            fails: t.fails,
            blocked: t.blocked,
        })
        .collect();
    let slices = OutSlices {
        slices: slice_defs
            .iter()
            .map(|s| {
                (
                    s.name.as_str(),
                    OutSlice {
                        paths: &s.paths,
                        role: &s.role,
                    },
                )
            })
            .collect(),
        mergeable,
    };
    let fail = |_| WorkFault::Invalid("export could not be written");
    let mut tasks_json = serde_json::to_string_pretty(&out).map_err(fail)?;
    tasks_json.push('\n');
    let mut slices_json = serde_json::to_string_pretty(&slices).map_err(fail)?;
    slices_json.push('\n');
    Ok((tasks_json, slices_json))
}

/// A `- DEFER [ID]: text` line of `docs-backlog.md`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DeferLine {
    pub(super) item: String,
    pub(super) text: String,
    pub(super) number: usize,
}

/// The `DEFER` lines and the other non-blank lines of the two text files.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Lines {
    pub(super) defers: Vec<DeferLine>,
    pub(super) unparsed: Vec<(&'static str, usize, String)>,
}

fn defer_of(text: &str) -> Option<(&str, &str)> {
    let rest = text.trim_start().strip_prefix("- DEFER [")?;
    let (id, tail) = rest.split_once("]:")?;
    let body = tail.trim();
    (ident(id) && !body.is_empty()).then_some((id, body))
}

/// Splits `progress.md` and `docs-backlog.md` into mapped `DEFER` lines and unparsed lines.
/// Every non-blank line of `progress.md` is unparsed.
///
/// # Errors
///
/// [`WorkFault::Invalid`] for more than [`MAX_IMPORT_LINES`] lines in a file or more than
/// [`MAX_IMPORT_DEFERS`] `DEFER` lines.
pub(super) fn split_lines(progress: &str, backlog: &str) -> Result<Lines, WorkFault> {
    let mut out = Lines::default();
    for (file, text) in [("progress.md", progress), ("docs-backlog.md", backlog)] {
        let mut count = 0;
        for (index, raw) in text.lines().take(MAX_IMPORT_LINES + 1).enumerate() {
            count += 1;
            if count > MAX_IMPORT_LINES {
                return Err(WorkFault::Invalid("too many lines"));
            }
            if raw.trim().is_empty() {
                continue;
            }
            match (file, defer_of(raw)) {
                ("docs-backlog.md", Some((id, body))) => {
                    if out.defers.len() == MAX_IMPORT_DEFERS {
                        return Err(WorkFault::Invalid("too many defers"));
                    }
                    out.defers.push(DeferLine {
                        item: id.to_owned(),
                        text: body.to_owned(),
                        number: index + 1,
                    });
                }
                _ => out.unparsed.push((file, index + 1, raw.to_owned())),
            }
        }
    }
    Ok(out)
}

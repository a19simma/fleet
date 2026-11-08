//! The transcript view: tool calls joined to their results, sub-agent work nested under its
//! Task call, and per-turn usage. Performs no IO.
//!
//! [`Assembler`] takes stored chunks one at a time and reports what changed. [`Transcript::build`]
//! is its batch form. Both stay inside [`ViewLimits`] whatever the input holds. The state
//! transitions are in the table on [`Assembler`].

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::{Cx, Entry, Limits, ToolId, Usage, parse_decoded, usage_of};
use crate::redact::Redactor;

/// Most items one view holds, counting nested ones. A line yields at most
/// [`MAX_ENTRIES_PER_LINE`](super::MAX_ENTRIES_PER_LINE) plus one entries, and each is checked
/// against this cap before it is kept, so a line never overshoots it.
pub const MAX_VIEW_ENTRIES: usize = 20_000;
/// Most bytes of text one view holds. One line can yield 257 entries of up to 16 KiB each.
pub const MAX_VIEW_BYTES: usize = 8 * 1024 * 1024;
/// Most parent pairs above an item. A child of a pair at this depth sits beside that pair.
pub const MAX_NEST_DEPTH: usize = 8;

/// Caps used by [`Assembler::with_limits`]. [`ViewLimits::DEFAULT`] holds the production caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ViewLimits {
    /// Item cap, also the cap on distinct message ids kept for usage.
    pub entries: usize,
    /// Text byte cap over all items.
    pub bytes: usize,
    /// Nesting cap. Values above [`MAX_NEST_DEPTH`] are lowered to it.
    pub depth: usize,
    /// Caps of the per-line parser.
    pub parse: Limits,
}

impl ViewLimits {
    /// The production caps.
    pub const DEFAULT: Self = Self {
        entries: MAX_VIEW_ENTRIES,
        bytes: MAX_VIEW_BYTES,
        depth: MAX_NEST_DEPTH,
        parse: Limits::DEFAULT,
    };
}

impl Default for ViewLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Where a tool call stands.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairStatus {
    /// No result yet and the job is not done.
    Pending,
    /// No result arrived and the job is done.
    NoResult,
    /// The result arrived.
    Done {
        /// Whether the tool reported an error.
        is_error: bool,
        /// The sanitised, capped output.
        output: String,
    },
}

/// A tool call joined to its result, with the work nested under it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Pair {
    /// The call id.
    pub id: ToolId,
    /// The sanitised tool name.
    pub name: String,
    /// A one-line summary.
    pub summary: String,
    /// The sanitised, capped compact JSON of the input.
    pub input: String,
    /// The result state.
    pub status: PairStatus,
    /// Items whose parent is this call, in arrival order.
    pub children: Vec<Item>,
}

/// One node of the view.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Item {
    /// Any entry except [`Entry::ToolCall`] and [`Entry::ToolResult`].
    Entry(Entry),
    /// A tool call and its result.
    Pair(Pair),
    /// A tool result whose call never arrived before it.
    Orphan {
        /// The id of the missing call.
        id: ToolId,
        /// Whether the tool reported an error.
        is_error: bool,
        /// The sanitised, capped output.
        output: String,
    },
}

/// Usage of one assistant message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnUsage {
    /// The message id, with the grammar of a [`ToolId`].
    pub message_id: ToolId,
    /// The usage of its first event.
    pub usage: Usage,
}

/// One change to a view, in the order the input arrived.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Update {
    /// A new item. `under` is the call it sits in, `None` for the top level.
    Appended {
        /// The id of the containing pair.
        under: Option<ToolId>,
        /// The item, with no children yet.
        item: Item,
    },
    /// A pending call got its result.
    Paired {
        /// The call id.
        id: ToolId,
        /// Whether the tool reported an error.
        is_error: bool,
        /// The sanitised, capped output.
        output: String,
    },
    /// A pending call is closed without a result because the job is done.
    NoResult {
        /// The call id.
        id: ToolId,
    },
    /// A message id was seen for the first time.
    Turn(TurnUsage),
    /// A result line set the run totals.
    Totals(Usage),
    /// A result arrived before its call, and now the call did. The orphan item with the id of
    /// `pair` becomes `pair` at the orphan's place. `pair` is [`PairStatus::Done`] with the
    /// orphan's output and has no children yet.
    Adopted {
        /// The adopted pair.
        pair: Pair,
    },
    /// An item was dropped because a cap was hit. Sent once. Later items are dropped too.
    Capped,
}

/// A built view.
#[derive(Debug, Clone, PartialEq)]
pub struct Transcript {
    items: Vec<Item>,
    turns: Vec<TurnUsage>,
    totals: Option<Usage>,
    capped: bool,
    turns_capped: bool,
    dropped: usize,
    done: bool,
}

impl Transcript {
    /// Builds a view from stored chunks, each with its `truncated` flag, with the production
    /// caps. `done` closes every call that has no result.
    pub fn build<'a>(
        chunks: impl IntoIterator<Item = (&'a str, bool)>,
        done: bool,
        redactor: Option<&Redactor>,
    ) -> Self {
        Self::build_with(chunks, done, redactor, &ViewLimits::DEFAULT)
    }

    /// Builds a view with explicit caps. It is [`Assembler`] fed every chunk.
    pub fn build_with<'a>(
        chunks: impl IntoIterator<Item = (&'a str, bool)>,
        done: bool,
        redactor: Option<&Redactor>,
        limits: &ViewLimits,
    ) -> Self {
        let mut assembler = Assembler::with_limits(redactor, limits);
        for (chunk, truncated) in chunks {
            assembler.push(chunk, truncated);
        }
        if done {
            assembler.finish();
        }
        assembler.snapshot()
    }

    /// The top-level items in arrival order.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Usage per message id, first event wins, in arrival order.
    pub fn turns(&self) -> &[TurnUsage] {
        &self.turns
    }

    /// The usage of the last result line, which is the run total.
    pub fn totals(&self) -> Option<Usage> {
        self.totals
    }

    /// Whether a cap cut the view.
    pub fn capped(&self) -> bool {
        self.capped
    }

    /// Whether the message-id cap cut the turns. No item is lost then.
    pub fn turns_capped(&self) -> bool {
        self.turns_capped
    }

    /// Items left out: a repeated call id, a second result for a call, a cap, or a line pushed
    /// after the job was done. After a cap, a line with no result counts one however many
    /// items it held.
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    /// Whether the job is done.
    pub fn done(&self) -> bool {
        self.done
    }
}

struct Node {
    item: Item,
    children: Vec<usize>,
    container: Option<usize>,
    depth: usize,
}

/// Builds a view chunk by chunk.
///
/// A call joins the result with its id. A call joins the pair that was opened first: a later
/// call with the same id is dropped, and so is a second result. A result with no earlier call
/// is [`Item::Orphan`] and is registered by id. A later call with that id adopts it: the orphan
/// item becomes the pair where the orphan sits, [`PairStatus::Done`] with the orphan's output,
/// and one [`Update::Adopted`] is sent. The call's own parent is ignored and nothing is
/// dropped. The pair keeps the orphan's place, not the place the call arrived at, so the
/// pair's position can be earlier than items that arrived before the call. An item nests under
/// the call named by its parent id only when that call arrived earlier, so a parent cycle, a
/// self-parent and an unknown parent all place the item at the top level. A child of a call at
/// [`MAX_NEST_DEPTH`] sits beside that call. A result stays in its call's place whatever
/// parent it names.
///
/// Usage is kept per message id, first event wins. The totals come from the last result line.
///
/// # Caps
///
/// A new item that does not fit the entry cap or the byte budget is dropped, counted in
/// [`Transcript::dropped`], and sets `capped` with one [`Update::Capped`]. Once capped, every
/// new item is dropped and counted, whatever its size. A call dropped by a cap is not
/// registered, so its result is dropped too and never becomes an orphan. Three things are
/// still read after a cap: a result for a call already in the view, a result line (for the
/// totals) and a message id (for the turns). A result for a call in the view still pairs
/// when its output fits the byte budget. When it does not fit, the pair becomes
/// [`PairStatus::Done`] with an empty output, and that is sent as [`Update::Paired`].
/// After a cap a line that carries no result and no `tool_result` block is not parsed beyond
/// its JSON value and counts as one dropped item, however many items it held.
/// A message id past the entry cap sets `turns_capped`, which is not `capped`: no item was
/// dropped and no [`Update::Capped`] is sent.
///
/// # Finish
///
/// [`Assembler::finish`] closes every pending call. After it, [`Assembler::push`] reads
/// nothing: each non-empty line of the chunk, or the one truncated chunk, is counted in
/// [`Transcript::dropped`] and no update is sent. A late result therefore never pairs.
///
/// # State transitions
///
/// "Over" means the item does not fit the entry cap or the byte budget. `cap` means the
/// view moves to Capped and sends [`Update::Capped`] once. Every cell with a dropped item
/// adds one to `dropped`.
///
/// | Event | Open | Capped (byte or entry) | Turn-capped | Finished |
/// | --- | --- | --- | --- | --- |
/// | call | `Appended` pair, Pending. Over: drop, `cap` | drop | as Open | line dropped |
/// | result, earlier call Pending | `Paired`. Output over: `Paired` with empty output, `cap` | `Paired` if output fits, else `Paired` with empty output | as Open | line dropped |
/// | result, no call | `Appended` orphan, registered. Over: drop, `cap` | drop | as Open | line dropped |
/// | late call, orphan registered | `Adopted`. Body over: drop call, `cap` | drop call, orphan stays | as Open | line dropped |
/// | duplicate call | drop | drop | drop | line dropped |
/// | duplicate result (call Done, or orphan) | drop | drop | drop | line dropped |
/// | message line (text, thinking, note, system, unknown) | `Appended`. Over: drop, `cap` | drop | as Open | line dropped |
/// | result line | `Totals`, then `Appended`. Over: drop, `cap` | `Totals`, item dropped | as Open | line dropped |
/// | `Truncated` | `Appended`. Over: drop, `cap` | drop | as Open | line dropped |
/// | push after finish | not applicable | not applicable | not applicable | lines counted in `dropped`, no update |
///
/// A new message id sends [`Update::Turn`] in every state but Finished. Past the entry cap
/// it sets `turns_capped`, sends nothing and leaves the other states unchanged.
///
/// The `Assembler` sends updates in input order. [`Assembler::snapshot`] clones the whole
/// view, so a renderer calls it when an update says something changed, not once per chunk.
pub struct Assembler<'a> {
    redactor: Option<&'a Redactor>,
    limits: ViewLimits,
    nodes: Vec<Node>,
    roots: Vec<usize>,
    pairs: HashMap<ToolId, usize>,
    orphans: HashMap<ToolId, usize>,
    turns: Vec<TurnUsage>,
    turn_ids: HashSet<ToolId>,
    totals: Option<Usage>,
    bytes: usize,
    capped: bool,
    turns_capped: bool,
    dropped: usize,
    done: bool,
}

impl<'a> Assembler<'a> {
    /// An empty view with the production caps.
    pub fn new(redactor: Option<&'a Redactor>) -> Self {
        Self::with_limits(redactor, &ViewLimits::DEFAULT)
    }

    /// An empty view with explicit caps.
    pub fn with_limits(redactor: Option<&'a Redactor>, limits: &ViewLimits) -> Self {
        let mut limits = *limits;
        limits.depth = limits.depth.min(MAX_NEST_DEPTH);
        Self {
            redactor,
            limits,
            nodes: Vec::new(),
            roots: Vec::new(),
            pairs: HashMap::new(),
            orphans: HashMap::new(),
            turns: Vec::new(),
            turn_ids: HashSet::new(),
            totals: None,
            bytes: 0,
            capped: false,
            turns_capped: false,
            dropped: 0,
            done: false,
        }
    }

    /// Reads one stored chunk and returns what changed.
    ///
    /// A chunk flagged `truncated` is one [`Entry::Truncated`] and is never parsed. After
    /// [`Self::finish`] nothing is read: the non-empty lines of the chunk, or the one truncated
    /// chunk, are counted as dropped and no update is returned.
    pub fn push(&mut self, chunk: &str, truncated: bool) -> Vec<Update> {
        let mut updates = Vec::new();
        if self.done {
            self.dropped += if truncated {
                1
            } else {
                chunk
                    .split('\n')
                    .filter(|raw| !raw.strip_suffix('\r').unwrap_or(raw).is_empty())
                    .count()
            };
            return updates;
        }
        if truncated {
            self.accept(Entry::Truncated, &mut updates);
            return updates;
        }
        for raw in chunk.split('\n') {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if !line.is_empty() {
                self.line(line, &mut updates);
            }
        }
        updates
    }

    fn line(&mut self, line: &str, updates: &mut Vec<Update>) {
        if line.len() > self.limits.parse.chunk_bytes {
            self.accept(Entry::Truncated, updates);
            return;
        }
        let (entries, turn) = {
            let cx = Cx::new(self.redactor, &self.limits.parse);
            let value = serde_json::from_str::<Value>(line).ok();
            let turn = value.as_ref().and_then(|v| turn_usage(v, &cx));
            if self.capped && !value.as_ref().is_some_and(carries_result) {
                (None, turn)
            } else {
                let mut entries = Vec::new();
                parse_decoded(line, value, &cx, &mut entries);
                (Some(entries), turn)
            }
        };
        match entries {
            Some(entries) => {
                for entry in entries {
                    self.accept(entry, updates);
                }
            }
            None => self.dropped += 1,
        }
        if let Some(turn) = turn {
            self.turn(turn, updates);
        }
    }

    /// Closes every pending call as [`PairStatus::NoResult`] and ends the view. A second call
    /// returns nothing because no call is pending.
    pub fn finish(&mut self) -> Vec<Update> {
        let mut updates = Vec::new();
        self.done = true;
        for node in &mut self.nodes {
            if let Item::Pair(pair) = &mut node.item
                && pair.status == PairStatus::Pending
            {
                pair.status = PairStatus::NoResult;
                updates.push(Update::NoResult {
                    id: pair.id.clone(),
                });
            }
        }
        updates
    }

    /// The view as it stands.
    pub fn snapshot(&self) -> Transcript {
        Transcript {
            items: self.roots.iter().filter_map(|&i| self.realize(i)).collect(),
            turns: self.turns.clone(),
            totals: self.totals,
            capped: self.capped,
            turns_capped: self.turns_capped,
            dropped: self.dropped,
            done: self.done,
        }
    }

    fn realize(&self, index: usize) -> Option<Item> {
        let node = self.nodes.get(index)?;
        let mut item = node.item.clone();
        if let Item::Pair(pair) = &mut item {
            pair.children = node
                .children
                .iter()
                .filter_map(|&c| self.realize(c))
                .collect();
        }
        Some(item)
    }

    fn accept(&mut self, entry: Entry, updates: &mut Vec<Update>) {
        match entry {
            Entry::ToolCall {
                id,
                name,
                summary,
                input,
                parent,
            } => {
                let pair = Pair {
                    id,
                    name,
                    summary,
                    input,
                    status: PairStatus::Pending,
                    children: Vec::new(),
                };
                self.call(pair, parent.as_ref(), updates);
            }
            Entry::ToolResult {
                id,
                is_error,
                output,
                parent,
            } => self.result(id, is_error, output, parent.as_ref(), updates),
            Entry::Result { usage, .. } => {
                self.totals = Some(usage);
                updates.push(Update::Totals(usage));
                self.insert(Item::Entry(entry), None, updates);
            }
            Entry::Message {
                subagent: ref parent,
                ..
            } => {
                let parent = parent.clone();
                self.insert(Item::Entry(entry), parent.as_ref(), updates);
            }
            Entry::Thinking { .. }
            | Entry::System { .. }
            | Entry::RateLimit { .. }
            | Entry::FleetNote { .. }
            | Entry::Truncated
            | Entry::Unknown { .. } => self.insert(Item::Entry(entry), None, updates),
        }
    }

    fn call(&mut self, pair: Pair, parent: Option<&ToolId>, updates: &mut Vec<Update>) {
        if self.capped || self.pairs.contains_key(&pair.id) {
            self.dropped += 1;
            return;
        }
        match self.orphans.get(&pair.id) {
            Some(&index) => self.adopt(index, pair, updates),
            None => self.insert(Item::Pair(pair), parent, updates),
        }
    }

    fn adopt(&mut self, index: usize, pair: Pair, updates: &mut Vec<Update>) {
        let extra = body_weight(&pair);
        if extra > self.limits.bytes.saturating_sub(self.bytes) {
            self.dropped += 1;
            self.cap(updates);
            return;
        }
        let Some(Node {
            item: Item::Orphan {
                is_error, output, ..
            },
            ..
        }) = self.nodes.get_mut(index)
        else {
            return;
        };
        let status = PairStatus::Done {
            is_error: *is_error,
            output: std::mem::take(output),
        };
        let pair = Pair { status, ..pair };
        if let Some(node) = self.nodes.get_mut(index) {
            node.item = Item::Pair(pair.clone());
        }
        self.bytes += extra;
        self.pairs.insert(pair.id.clone(), index);
        updates.push(Update::Adopted { pair });
    }

    fn result(
        &mut self,
        id: ToolId,
        is_error: bool,
        output: String,
        parent: Option<&ToolId>,
        updates: &mut Vec<Update>,
    ) {
        let Some(&index) = self.pairs.get(&id) else {
            if self.orphans.contains_key(&id) {
                self.dropped += 1;
                return;
            }
            self.insert(
                Item::Orphan {
                    id,
                    is_error,
                    output,
                },
                parent,
                updates,
            );
            return;
        };
        let room = self.limits.bytes.saturating_sub(self.bytes);
        let Some(Node {
            item: Item::Pair(pair),
            ..
        }) = self.nodes.get_mut(index)
        else {
            return;
        };
        if pair.status != PairStatus::Pending {
            self.dropped += 1;
            return;
        }
        let over = output.len() > room;
        let output = if over { String::new() } else { output };
        self.bytes += output.len();
        pair.status = PairStatus::Done {
            is_error,
            output: output.clone(),
        };
        updates.push(Update::Paired {
            id,
            is_error,
            output,
        });
        if over {
            self.cap(updates);
        }
    }

    fn cap(&mut self, updates: &mut Vec<Update>) {
        if !self.capped {
            self.capped = true;
            updates.push(Update::Capped);
        }
    }

    fn insert(&mut self, item: Item, parent: Option<&ToolId>, updates: &mut Vec<Update>) {
        let weight = weight(&item);
        if self.capped
            || self.nodes.len() >= self.limits.entries
            || weight > self.limits.bytes.saturating_sub(self.bytes)
        {
            self.dropped += 1;
            self.cap(updates);
            return;
        }
        let (container, depth) = self.place(parent);
        let under = container.and_then(|c| match &self.nodes.get(c)?.item {
            Item::Pair(pair) => Some(pair.id.clone()),
            Item::Entry(_) | Item::Orphan { .. } => None,
        });
        let index = self.nodes.len();
        match &item {
            Item::Pair(pair) => {
                self.pairs.insert(pair.id.clone(), index);
            }
            Item::Orphan { id, .. } => {
                self.orphans.insert(id.clone(), index);
            }
            Item::Entry(_) => {}
        }
        match container.and_then(|c| self.nodes.get_mut(c)) {
            Some(node) => node.children.push(index),
            None => self.roots.push(index),
        }
        updates.push(Update::Appended {
            under,
            item: item.clone(),
        });
        self.bytes += weight;
        self.nodes.push(Node {
            item,
            children: Vec::new(),
            container,
            depth,
        });
    }

    fn place(&self, parent: Option<&ToolId>) -> (Option<usize>, usize) {
        let Some((index, node)) = parent
            .and_then(|id| self.pairs.get(id))
            .and_then(|&i| Some((i, self.nodes.get(i)?)))
        else {
            return (None, 0);
        };
        if node.depth >= self.limits.depth {
            (node.container, node.depth)
        } else {
            (Some(index), node.depth + 1)
        }
    }

    fn turn(&mut self, turn: TurnUsage, updates: &mut Vec<Update>) {
        if self.turn_ids.contains(&turn.message_id) {
            return;
        }
        if self.turns.len() >= self.limits.entries {
            self.turns_capped = true;
            return;
        }
        self.turn_ids.insert(turn.message_id.clone());
        self.turns.push(turn.clone());
        updates.push(Update::Turn(turn));
    }
}

fn carries_result(value: &Value) -> bool {
    match value.get("type").and_then(Value::as_str) {
        Some("result") => true,
        Some("user" | "assistant") => value
            .pointer("/message/content")
            .and_then(Value::as_array)
            .is_some_and(|blocks| {
                blocks
                    .iter()
                    .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"))
            }),
        _ => false,
    }
}

fn turn_usage(value: &Value, cx: &Cx<'_>) -> Option<TurnUsage> {
    if value.get("type")?.as_str()? != "assistant" {
        return None;
    }
    let message = value.get("message")?;
    Some(TurnUsage {
        message_id: cx.tool_id(message.get("id")?.as_str()?)?,
        usage: usage_of(Some(message.get("usage")?)),
    })
}

fn body_weight(pair: &Pair) -> usize {
    pair.name.len() + pair.summary.len() + pair.input.len()
}

fn weight(item: &Item) -> usize {
    match item {
        Item::Pair(pair) => pair.id.as_str().len() + body_weight(pair),
        Item::Orphan { id, output, .. } => id.as_str().len() + output.len(),
        Item::Entry(entry) => match entry {
            Entry::Message { text, subagent, .. } => {
                text.len() + subagent.as_ref().map_or(0, |s| s.as_str().len())
            }
            Entry::Thinking { text } | Entry::FleetNote { text } => text.len(),
            Entry::ToolCall {
                id,
                name,
                summary,
                input,
                parent,
            } => {
                id.as_str().len()
                    + name.len()
                    + summary.len()
                    + input.len()
                    + parent.as_ref().map_or(0, |p| p.as_str().len())
            }
            Entry::ToolResult {
                id, output, parent, ..
            } => id.as_str().len() + output.len() + parent.as_ref().map_or(0, |p| p.as_str().len()),
            Entry::System { subtype, .. } => subtype.len(),
            Entry::RateLimit { status, .. } => status.len(),
            Entry::Result {
                terminal_reason, ..
            } => terminal_reason.as_ref().map_or(0, String::len),
            Entry::Truncated => 0,
            Entry::Unknown { kind, raw } => kind.len() + raw.len(),
        },
    }
}

//! The jobs pages: the signed-in user's job list and one job with its transcript.
//!
//! Reads go through the owner-scoped `*_for` store calls with the session's user id, so a
//! job of another user answers 404 exactly like an unknown id. The job page pages
//! `ReadTranscript` with `after_seq` until the job is done, a [`Ceilings`] limit stops it, or
//! nothing more is stored. It joins the chunks into a [`fleet_core::transcript`] view once
//! and renders one `li` per item with literal class names. Every stored string reaches the
//! markup as text, which escapes it, and no stored string reaches an attribute or a class.
//! `?raw=1` shows the stored text in one `pre` block.

use std::fmt::Write;
use std::sync::Arc;

use fleet_core::transcript::{Assembler, Entry, Item, Pair, PairStatus, Role, Usage};
use fleet_proto::v1::Job;
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        error::{not_found, see_other},
        page, path_param,
        request::uri,
    },
    view::{View, component, view},
};

use super::layout::{Nav, shell};
use super::pages::{auth, current, fail};
use super::passkeys::AuthError;
use crate::store::{MAX_TRANSCRIPT_LIMIT, Store, StoreError};

/// The most transcript text a job page renders, in bytes.
pub const MAX_RENDER_BYTES: usize = 256 * 1024;

/// The most transcript bytes a job page reads, the per-job ceiling of ADR-0022.
const MAX_READ_BYTES: usize = 4 * 1024 * 1024;

/// The most transcript rows a job page reads, the per-job ceiling of ADR-0022.
const MAX_READ_ROWS: usize = 50_000;

const LIST_LIMIT: u32 = 100;

const OPEN_ERROR_PAIRS: usize = 20;

pub(super) struct ConsoleSlot(pub Option<Arc<Store>>);

path_param!(job_id);

fn store(cx: &Cx) -> Result<&Store> {
    app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(|| not_found().into())
}

pub(super) fn when(ms: u64) -> String {
    fleet_core::stamp::utc_stamp(ms)
}

/// The limits that end paging early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ceilings {
    bytes: usize,
    rows: usize,
    render: usize,
}

impl Ceilings {
    const DEFAULT: Self = Self {
        bytes: MAX_READ_BYTES,
        rows: MAX_READ_ROWS,
        render: MAX_RENDER_BYTES,
    };
}

/// Counts what has been read and says whether the next chunk still fits.
#[derive(Debug)]
struct Pager {
    ceilings: Ceilings,
    after: u64,
    bytes: usize,
    rows: usize,
}

impl Pager {
    fn new(ceilings: Ceilings) -> Self {
        Self {
            ceilings,
            after: 0,
            bytes: 0,
            rows: 0,
        }
    }

    fn admit(&mut self, seq: u64, len: usize) -> bool {
        let bytes = self.bytes.saturating_add(len);
        if self.rows >= self.ceilings.rows
            || bytes > self.ceilings.bytes
            || bytes > self.ceilings.render
        {
            return false;
        }
        self.bytes = bytes;
        self.rows += 1;
        self.after = seq;
        true
    }
}

/// What a paged read left behind.
struct Read {
    cut: bool,
    ended: bool,
}

async fn read_all(
    store: &Store,
    owner: Option<i64>,
    id: &str,
    ceilings: Ceilings,
    mut sink: impl FnMut(&str, bool),
) -> Result<Read, StoreError> {
    let mut pager = Pager::new(ceilings);
    loop {
        let reply = store
            .read_transcript_for(owner, id, pager.after, MAX_TRANSCRIPT_LIMIT)
            .await?;
        let empty = reply.chunks.is_empty();
        for chunk in &reply.chunks {
            if !pager.admit(chunk.seq, chunk.text.len()) {
                return Ok(Read {
                    cut: true,
                    ended: false,
                });
            }
            sink(&chunk.text, chunk.truncated);
        }
        if reply.done || empty {
            return Ok(Read {
                cut: false,
                ended: reply.done,
            });
        }
    }
}

const INDENT: [&str; 5] = [
    "min-w-0",
    "ml-4 min-w-0",
    "ml-8 min-w-0",
    "ml-12 min-w-0",
    "ml-16 min-w-0",
];

const LI_PLAIN: &str = "tx-entry list-none min-w-0";
const LI_NOTE: &str = "tx-entry tx-note list-none min-w-0";
const LI_TOTAL: &str =
    "tx-entry tx-result-total list-none min-w-0 border border-base-300 bg-base-200 p-2";

const RULE_USER: &str = "min-w-0 break-words border-l-2 border-l-accent pl-2";
const RULE_ASSISTANT: &str = "min-w-0 break-words border-l-2 border-l-primary pl-2";
const RULE_NEUTRAL: &str = "min-w-0 break-words border-l-2 border-l-neutral pl-2";
const RULE_ERROR: &str = "min-w-0 break-words border-l-2 border-l-error pl-2";
const RULE_NOTE: &str =
    "min-w-0 break-words border-l-2 border-l-neutral pl-2 text-xs text-base-content/60";
const RULE_NONE: &str = "min-w-0 break-words";

const STATUS_OK: &str = "text-xs text-base-content/60";
const STATUS_ERROR: &str = "text-xs text-error";

fn indent(depth: usize) -> &'static str {
    INDENT.get(depth).copied().unwrap_or("ml-16 min-w-0")
}

struct Output {
    text: String,
    more: Vec<String>,
}

struct Stat {
    label: &'static str,
    value: String,
}

struct Total {
    badge: &'static str,
    label: String,
    stats: Vec<Stat>,
}

enum Body {
    Message { label: &'static str, text: String },
    Thinking { text: String },
    Tool(ToolBody),
    Orphan(Output),
    Meta { label: &'static str, text: String },
    System { subtype: String },
    Note { text: String },
    Unknown { kind: String, raw: String },
    Cut,
    Total(Total),
}

struct ToolBody {
    name: String,
    summary: String,
    glyph: &'static str,
    glyph_class: &'static str,
    input: String,
    result: Vec<Output>,
}

struct Row {
    id: String,
    kind: &'static str,
    role: Option<&'static str>,
    status: Option<&'static str>,
    li: &'static str,
    indent: &'static str,
    rule: &'static str,
    open: Option<&'static str>,
    body: Body,
}

fn split_more(output: &str) -> (&str, Option<u64>) {
    if let Some((head, tail)) = output.rsplit_once("\n[")
        && let Some(digits) = tail.strip_suffix(" bytes more]")
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && let Ok(more) = digits.parse::<u64>()
    {
        return (head, Some(more));
    }
    (output, None)
}

fn output_of(output: &str) -> Output {
    let (text, more) = split_more(output);
    Output {
        text: text.to_owned(),
        more: more
            .map(|n| format!("{n} bytes more not shown"))
            .into_iter()
            .collect(),
    }
}

fn duration(ms: u64) -> String {
    format!("{}.{} s", ms / 1000, ms % 1000 / 100)
}

fn total_of(
    is_error: bool,
    turns: u64,
    duration_ms: u64,
    cost: Option<f64>,
    usage: Usage,
    reason: Option<&str>,
    denials: u64,
) -> Total {
    let (badge, label) = match (is_error, reason) {
        (true, _) => ("badge badge-sm badge-error", "error".to_owned()),
        (false, None | Some("completed")) => ("badge badge-sm badge-success", "ok".to_owned()),
        (false, Some(other)) => ("badge badge-sm badge-ghost", other.to_owned()),
    };
    let mut stats = vec![
        Stat {
            label: "Turns",
            value: turns.to_string(),
        },
        Stat {
            label: "Duration",
            value: duration(duration_ms),
        },
    ];
    if let Some(cost) = cost.filter(|c| c.is_finite() && *c >= 0.0) {
        stats.push(Stat {
            label: "Cost",
            value: format!("${cost:.4}"),
        });
    }
    if usage != Usage::default() {
        stats.push(Stat {
            label: "Input",
            value: usage.input_tokens.to_string(),
        });
        stats.push(Stat {
            label: "Output",
            value: usage.output_tokens.to_string(),
        });
        if let Some(read) = usage.cache_read_input_tokens {
            stats.push(Stat {
                label: "Cache read",
                value: read.to_string(),
            });
        }
        if let Some(write) = usage.cache_creation_input_tokens {
            stats.push(Stat {
                label: "Cache write",
                value: write.to_string(),
            });
        }
    }
    stats.push(Stat {
        label: "Denials",
        value: denials.to_string(),
    });
    Total {
        badge,
        label,
        stats,
    }
}

struct Flatten {
    rows: Vec<Row>,
    opened_errors: usize,
}

impl Flatten {
    fn push(&mut self, depth: usize, shape: &Shape, body: Body) {
        let id = format!("tx-{}", self.rows.len());
        self.rows.push(Row {
            id,
            kind: shape.kind,
            role: shape.role,
            status: shape.status,
            li: shape.li,
            indent: indent(depth),
            rule: shape.rule,
            open: shape.open,
            body,
        });
    }

    fn items(&mut self, items: &[Item], depth: usize) {
        for item in items {
            match item {
                Item::Entry(entry) => self.entry(entry, depth),
                Item::Pair(pair) => self.pair(pair, depth),
                Item::Orphan {
                    is_error, output, ..
                } => {
                    let (status, rule) = if *is_error {
                        ("error", RULE_ERROR)
                    } else {
                        ("ok", RULE_NEUTRAL)
                    };
                    self.push(
                        depth,
                        &Shape::of("tool-result", RULE_NEUTRAL)
                            .status(status)
                            .rule(rule),
                        Body::Orphan(output_of(output)),
                    );
                }
                _ => self.push(
                    depth,
                    &Shape::of("unknown", RULE_NEUTRAL),
                    Body::Unknown {
                        kind: "?".to_owned(),
                        raw: String::new(),
                    },
                ),
            }
        }
    }

    fn pair(&mut self, pair: &Pair, depth: usize) {
        let (status, glyph, glyph_class, result, rule) = match &pair.status {
            PairStatus::Done {
                is_error: true,
                output,
            } => (
                "error",
                "\u{2717} error",
                STATUS_ERROR,
                vec![output_of(output)],
                RULE_ERROR,
            ),
            PairStatus::Done {
                is_error: false,
                output,
            } => (
                "ok",
                "\u{2713} ok",
                STATUS_OK,
                vec![output_of(output)],
                RULE_NEUTRAL,
            ),
            _ => (
                "pending",
                "\u{2026} no result",
                STATUS_OK,
                Vec::new(),
                RULE_NEUTRAL,
            ),
        };
        let open = (status == "error" && self.opened_errors < OPEN_ERROR_PAIRS).then(|| {
            self.opened_errors += 1;
            "open"
        });
        self.push(
            depth,
            &Shape::of("tool", rule).status(status).open(open),
            Body::Tool(ToolBody {
                name: pair.name.clone(),
                summary: pair.summary.clone(),
                glyph,
                glyph_class,
                input: pair.input.clone(),
                result,
            }),
        );
        self.items(&pair.children, depth + 1);
    }

    fn entry(&mut self, entry: &Entry, depth: usize) {
        match entry {
            Entry::Message { role, text, .. } => {
                let (label, rule) = match role {
                    Role::User => ("user", RULE_USER),
                    _ => ("assistant", RULE_ASSISTANT),
                };
                self.push(
                    depth,
                    &Shape::of("message", rule).role(label).open(Some("open")),
                    Body::Message {
                        label,
                        text: text.clone(),
                    },
                );
            }
            Entry::Thinking { text } => self.push(
                depth,
                &Shape::of("thinking", RULE_NEUTRAL),
                Body::Thinking { text: text.clone() },
            ),
            Entry::System { subtype, .. } => self.push(
                depth,
                &Shape::of("system", RULE_NEUTRAL),
                Body::System {
                    subtype: subtype.clone(),
                },
            ),
            Entry::RateLimit {
                status,
                utilization,
                resets_at,
            } => {
                let mut text = status.clone();
                if let Some(used) = utilization.filter(|u| u.is_finite()) {
                    let _ = write!(text, " utilization {used:.2}");
                }
                if let Some(at) = resets_at {
                    let _ = write!(text, " resets {}", when(at.saturating_mul(1000)));
                }
                self.push(
                    depth,
                    &Shape::of("rate-limit", RULE_NEUTRAL),
                    Body::Meta {
                        label: "rate limit",
                        text,
                    },
                );
            }
            Entry::Result {
                is_error,
                turns,
                duration_ms,
                cost_usd,
                usage,
                terminal_reason,
                denials,
            } => self.push(
                depth,
                &Shape::of("result", RULE_NONE)
                    .li(LI_TOTAL)
                    .open(Some("open")),
                Body::Total(total_of(
                    *is_error,
                    *turns,
                    *duration_ms,
                    *cost_usd,
                    *usage,
                    terminal_reason.as_deref(),
                    *denials,
                )),
            ),
            Entry::FleetNote { text } => self.push(
                depth,
                &Shape::of("fleet-note", RULE_NOTE).li(LI_NOTE),
                Body::Note { text: text.clone() },
            ),
            Entry::Truncated => self.push(depth, &Shape::of("truncated", RULE_NEUTRAL), Body::Cut),
            Entry::Unknown { kind, raw } => self.push(
                depth,
                &Shape::of("unknown", RULE_NEUTRAL),
                Body::Unknown {
                    kind: kind.clone(),
                    raw: raw.clone(),
                },
            ),
            _ => self.push(
                depth,
                &Shape::of("unknown", RULE_NEUTRAL),
                Body::Unknown {
                    kind: "?".to_owned(),
                    raw: String::new(),
                },
            ),
        }
    }
}

struct Shape {
    kind: &'static str,
    role: Option<&'static str>,
    status: Option<&'static str>,
    li: &'static str,
    rule: &'static str,
    open: Option<&'static str>,
}

impl Shape {
    fn of(kind: &'static str, rule: &'static str) -> Self {
        Self {
            kind,
            role: None,
            status: None,
            li: LI_PLAIN,
            rule,
            open: None,
        }
    }

    fn role(mut self, role: &'static str) -> Self {
        self.role = Some(role);
        self
    }

    fn status(mut self, status: &'static str) -> Self {
        self.status = Some(status);
        self
    }

    fn rule(mut self, rule: &'static str) -> Self {
        self.rule = rule;
        self
    }

    fn open(mut self, open: Option<&'static str>) -> Self {
        self.open = open;
        self
    }

    fn li(mut self, li: &'static str) -> Self {
        self.li = li;
        self
    }
}

fn flatten(items: &[Item]) -> Vec<Row> {
    let mut flat = Flatten {
        rows: Vec::new(),
        opened_errors: 0,
    };
    flat.items(items, 0);
    flat.rows
}

struct Transcript {
    rows: Vec<Row>,
    raw: String,
    cut: bool,
    cut_text: String,
    empty: Option<&'static str>,
}

const EMPTY_QUEUED: &str = "No transcript yet.";
const EMPTY_ENDED: &str = "This job wrote no transcript.";
const EMPTY_UNREADABLE: &str = "Transcript has no readable entries. Open raw.";

const UNKNOWN_CUT: &str = "transcript cut: the count of entries not shown is unknown.";

/// Says whether the page shows a cut cue and what it says.
///
/// The count is a minimum: [`Assembler`] counts a line it skips after a cap as one item, and it
/// also counts a repeated call id or a second result, each an entry the page does not show.
fn cut_of(read_cut: bool, capped: bool, dropped: usize) -> (bool, String) {
    let text = if capped && !read_cut {
        let noun = if dropped == 1 { "entry" } else { "entries" };
        format!("transcript cut: at least {dropped} {noun} not shown.")
    } else {
        UNKNOWN_CUT.to_owned()
    };
    (read_cut || capped, text)
}

async fn load(
    store: &Store,
    owner: Option<i64>,
    id: &str,
    raw: bool,
    ceilings: Ceilings,
) -> Result<Transcript, StoreError> {
    let mut text = String::new();
    let mut assembler = Assembler::new(None);
    let mut rows_read = 0_usize;
    let read = read_all(store, owner, id, ceilings, |chunk, truncated| {
        rows_read += 1;
        if raw {
            text.push_str(chunk);
        } else {
            assembler.push(chunk, truncated);
        }
    })
    .await?;
    if raw {
        return Ok(Transcript {
            rows: Vec::new(),
            raw: text,
            cut: read.cut,
            cut_text: UNKNOWN_CUT.to_owned(),
            empty: None,
        });
    }
    if read.ended {
        assembler.finish();
    }
    let view = assembler.snapshot();
    let rows = flatten(view.items());
    let (cut, cut_text) = cut_of(read.cut, view.capped(), view.dropped());
    let empty = if !rows.is_empty() {
        None
    } else if rows_read > 0 {
        Some(EMPTY_UNREADABLE)
    } else if read.ended {
        Some(EMPTY_ENDED)
    } else {
        Some(EMPTY_QUEUED)
    };
    Ok(Transcript {
        rows,
        raw: String::new(),
        cut,
        cut_text,
        empty,
    })
}

#[component]
async fn transcript_pane(transcript: Transcript, raw: bool, job_id: String) -> Result<impl View> {
    let raw_href = format!("/jobs/{job_id}?raw=1");
    let pretty_href = format!("/jobs/{job_id}");
    let count = transcript.rows.len();
    let empty = transcript.empty.unwrap_or_default();
    Ok(view! {
            <section class="min-w-0">
                <div id="tx-toolbar" class="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                    <h2 class="font-bold uppercase text-base-content/60">"Transcript"</h2>
                    if raw {
                        <a class="link link-hover" href=(pretty_href.as_str())>"Pretty view"</a>
                    } else {
                        <span class="text-base-content/60">(count)" entries"</span>
                        <a class="link link-hover" href=(raw_href.as_str())>"Raw"</a>
                        if transcript.cut {
                            <span class="text-warning">(transcript.cut_text.as_str())</span>
                            <a class="link link-hover" href=(raw_href.as_str())>"Open raw"</a>
                            <span class="text-warning">"for the full stream."</span>
                        }
                    }
                    <a class="link link-hover ml-auto" href="#tx-end">"Jump to end"</a>
                </div>
                if raw {
                    <pre id="transcript" class="overflow-auto border border-base-300 bg-base-300 p-2 text-xs" tabindex="0" role="region" aria-label="Raw transcript">(transcript.raw.as_str())</pre>
                    if transcript.cut {
                        <p id="cut" class="mt-1 text-xs text-warning">(transcript.cut_text.as_str())</p>
                    }
                } else {
                    if !empty.is_empty() {
                        <p id="empty" class="text-xs text-base-content/60">(empty)</p>
                    }
                    if count > 0 {
                        <ol id="transcript" class="tx-list flex flex-col gap-2" aria-label="Transcript entries">
                            for row in transcript.rows {
                                <li id=(row.id.as_str()) class=(row.li) data-kind=(row.kind) data-role=(row.role) data-status=(row.status)>
                                    <div class=(row.indent)>
                                        <div class=(row.rule)>
                                            entry_body(body: row.body, open: row.open)
                                        </div>
                                    </div>
                                </li>
                            }
                        </ol>
                    }
                    if transcript.cut {
                        <p id="cut" role="status" class="mt-2 text-xs text-warning">(transcript.cut_text.as_str())" "<a class="link link-hover" href=(raw_href.as_str())>"Open raw"</a>" for the full stream."</p>
                    }
                }
                <div id="tx-end" tabindex="-1"></div>
            </section>
    })
}

#[component]
async fn entry_body(body: Body, open: Option<&'static str>) -> Result<impl View> {
    Ok(view! {
        match body {
            Body::Message { label, text } => {
                <details class="min-w-0" open=(open)>
                    <summary class="flex min-h-8 cursor-pointer items-center gap-2 text-xs">
                        <span class="font-bold">(label)</span>
                    </summary>
                    <pre class="min-w-0 whitespace-pre-wrap break-words text-sm">(text)</pre>
                </details>
            }
            Body::Thinking { text } => {
                <details class="min-w-0">
                    <summary class="flex min-h-8 cursor-pointer items-center gap-2 text-xs text-base-content/60">
                        <span>"thinking"</span>
                    </summary>
                    <pre class="min-w-0 whitespace-pre-wrap break-words text-xs text-base-content/60">(text)</pre>
                </details>
            }
            Body::Tool(tool) => {
                <details class="min-w-0" open=(open)>
                    <summary class="flex min-h-8 cursor-pointer flex-wrap items-center gap-x-2 text-xs">
                        <span class="font-bold">(tool.name)</span>
                        <span class="min-w-0 break-all text-base-content/60">(tool.summary)</span>
                        <span class=(tool.glyph_class)>(tool.glyph)</span>
                    </summary>
                    <pre class="overflow-x-auto whitespace-pre bg-base-200 p-2 text-xs" tabindex="0" role="region" aria-label="Tool input">(tool.input)</pre>
                    for out in tool.result {
                        <div class="ml-3 mt-1 min-w-0 border-l-2 border-l-neutral pl-2">
                            <span class="text-xs text-base-content/60">"result"</span>
                            <pre class="overflow-x-auto whitespace-pre bg-base-200 p-2 text-xs" tabindex="0" role="region" aria-label="Tool output">(out.text)</pre>
                            for more in out.more {
                                <p class="text-xs text-warning">(more)</p>
                            }
                        </div>
                    }
                </details>
            }
            Body::Orphan(out) => {
                <details class="min-w-0" open=(open)>
                    <summary class="flex min-h-8 cursor-pointer items-center gap-2 text-xs">
                        <span class="font-bold">"Result without call"</span>
                    </summary>
                    <pre class="overflow-x-auto whitespace-pre bg-base-200 p-2 text-xs" tabindex="0" role="region" aria-label="Tool output">(out.text)</pre>
                    for more in out.more {
                        <p class="text-xs text-warning">(more)</p>
                    }
                </details>
            }
            Body::Meta { label, text } => {
                <details class="min-w-0">
                    <summary class="flex min-h-8 cursor-pointer items-center gap-2 text-xs text-base-content/60">
                        <span>(label)</span>
                    </summary>
                    <pre class="min-w-0 whitespace-pre-wrap break-words text-xs text-base-content/60">(text)</pre>
                </details>
            }
            Body::System { subtype } => {
                <details class="min-w-0">
                    <summary class="flex min-h-8 cursor-pointer items-center gap-2 text-xs text-base-content/60">
                        <span>"system"</span>
                        <span class="text-xs text-base-content/60">(subtype.as_str())</span>
                    </summary>
                    <pre class="min-w-0 whitespace-pre-wrap break-words text-xs text-base-content/60">(subtype.as_str())</pre>
                </details>
            }
            Body::Note { text } => {
                <span class="mr-2">"note"</span>
                <span class="whitespace-pre-wrap">(text)</span>
            }
            Body::Unknown { kind, raw } => {
                <details class="min-w-0">
                    <summary class="flex min-h-8 cursor-pointer items-center gap-2 text-xs text-base-content/60">
                        <span>"unknown"</span>
                        <span>(kind)</span>
                    </summary>
                    <pre class="overflow-x-auto whitespace-pre bg-base-200 p-2 text-xs" tabindex="0" role="region" aria-label="Unknown event">(raw)</pre>
                </details>
            }
            Body::Cut => {
                <p class="text-xs text-warning">"\u{26a0} line cut at source"</p>
            }
            Body::Total(total) => {
                <details class="min-w-0" open=(open)>
                    <summary class="flex min-h-8 cursor-pointer items-center gap-2 text-xs">
                        <span class="font-bold">"Result"</span>
                        <span class=(total.badge)>(total.label)</span>
                    </summary>
                    <dl class="grid grid-cols-[6rem_1fr] gap-y-1 text-xs tabular-nums">
                        for stat in total.stats {
                            <dt class="text-base-content/60">(stat.label)</dt>
                            <dd>(stat.value)</dd>
                        }
                    </dl>
                </details>
            }
        }
    })
}

struct JobRow {
    id: String,
    state: &'static str,
    repo: String,
    created: String,
}

fn row(job: &Job) -> JobRow {
    JobRow {
        id: job.job_id.clone(),
        state: job.state().as_str_name(),
        repo: job.repo.clone(),
        created: when(job.created_at_ms),
    }
}

fn badge_class(state: &str) -> &'static str {
    match state {
        "JOB_STATE_RUNNING" => "badge badge-sm badge-warning",
        "JOB_STATE_SUCCEEDED" => "badge badge-sm badge-success",
        "JOB_STATE_FAILED" | "JOB_STATE_LOST" => "badge badge-sm badge-error",
        _ => "badge badge-sm badge-ghost",
    }
}

fn internal(err: &StoreError) -> topcoat::Error {
    tracing::error!(error = %err, "jobs page store read failed");
    fail(AuthError::Internal)
}

fn wants_raw(cx: &Cx) -> bool {
    uri(cx)
        .query()
        .is_some_and(|query| query.split('&').any(|pair| pair == "raw=1"))
}

#[page("/jobs")]
async fn jobs_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let store = store(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let jobs = store
        .list_jobs_for(Some(session.user_id), None, LIST_LIMIT)
        .await
        .map_err(|err| internal(&err))?;
    let rows: Vec<JobRow> = jobs.iter().map(row).collect();
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet jobs", active: Nav::Jobs, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">"Jobs"</h1>
                    <a class="link link-hover ml-auto" href="/account">"Account"</a>
                </header>
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <thead>
                            <tr>
                                <th>"Job"</th>
                                <th>"State"</th>
                                <th>"Repo"</th>
                                <th>"Created"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                <tr>
                                    <td><a class="link link-primary" href=(format!("/jobs/{}", row.id))>(row.id.as_str())</a></td>
                                    <td><span class=(badge_class(row.state))>(row.state)</span></td>
                                    <td>(row.repo)</td>
                                    <td>(row.created)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            )
    })
}

#[page("/jobs/{job_id}")]
async fn job_page(cx: &Cx) -> Result<impl View> {
    let auth = auth(cx)?;
    let store = store(cx)?;
    let Some(session) = current(cx, auth).await? else {
        return Err(see_other("/login").into());
    };
    let id = path_param::<JobId>(cx);
    let owner = Some(session.user_id);
    let job = match store.get_job_with_summary_for(owner, id).await {
        Ok(job) => job,
        Err(StoreError::NotFound | StoreError::InvalidJob(_)) => return Err(not_found().into()),
        Err(err) => return Err(internal(&err)),
    };
    let raw = wants_raw(cx);
    let transcript = load(store, owner, id, raw, Ceilings::DEFAULT)
        .await
        .map_err(|err| internal(&err))?;
    let state = job.state().as_str_name();
    let created = when(job.created_at_ms);
    let branch = job.branch.clone().unwrap_or_default();
    let error = job.error.clone().unwrap_or_default();
    let pr_url = job.pr_url.clone().unwrap_or_default();
    let pr_link = pr_url.starts_with("https://");
    let csrf = String::from_utf8_lossy(session.csrf.expose()).into_owned();
    Ok(view! {
        shell(title: "fleet job", active: Nav::Jobs, user: session.username.as_str(), csrf: csrf.as_str(), mode: "",
                <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                    <span class="text-primary">"$"</span>
                    <h1 class="text-sm font-bold">(job.job_id.as_str())</h1>
                    <a class="link link-hover ml-auto" id="timing-link" href=(format!("/jobs/{}/timing", job.job_id))>"Timing"</a>
                    <a class="link link-hover" href="/jobs">"Jobs"</a>
                </header>
                <div class="grid gap-3 lg:grid-cols-[22rem_1fr]">
                    <section class="flex min-w-0 flex-col gap-3">
                        <dl class="grid grid-cols-[6rem_1fr] gap-y-1 border border-base-300 p-2 text-xs">
                            <dt class="text-base-content/60">"State"</dt>
                            <dd class="min-w-0 break-all"><span class=(badge_class(state))>(state)</span></dd>
                            <dt class="text-base-content/60">"Repo"</dt><dd class="min-w-0 break-all">(job.repo.as_str())</dd>
                            <dt class="text-base-content/60">"Base ref"</dt><dd class="min-w-0 break-all">(job.base_ref.as_str())</dd>
                            <dt class="text-base-content/60">"Created"</dt><dd class="min-w-0 break-all">(created)</dd>
                            <dt class="text-base-content/60">"Phase"</dt><dd class="min-w-0 break-all">(job.phase.as_str())</dd>
                            <dt class="text-base-content/60">"Progress"</dt><dd class="min-w-0 break-all">(job.progress.as_str())</dd>
                            <dt class="text-base-content/60">"Branch"</dt><dd class="min-w-0 break-all">(branch)</dd>
                            <dt class="text-base-content/60">"Error"</dt><dd class="min-w-0 break-all text-error">(error)</dd>
                            <dt class="text-base-content/60">"Pull request"</dt>
                            <dd class="min-w-0 break-all">
                                if pr_link {
                                    <a class="link link-primary" href=(pr_url.as_str())>(pr_url.as_str())</a>
                                } else {
                                    (pr_url.as_str())
                                }
                            </dd>
                        </dl>
                        <h2 class="text-xs font-bold uppercase text-base-content/60">"Prompt"</h2>
                        <pre id="prompt" class="overflow-auto whitespace-pre-wrap border border-base-300 bg-base-200 p-2 text-xs">(job.prompt.as_str())</pre>
                    </section>
                    transcript_pane(transcript: transcript, raw: raw, job_id: job.job_id.clone())
                </div>
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_core::transcript::{Assembler, Item, ViewLimits};

    const SMALL: Ceilings = Ceilings {
        bytes: 10,
        rows: 3,
        render: 100,
    };

    #[test]
    fn the_pager_stops_at_the_row_ceiling() {
        let mut pager = Pager::new(SMALL);
        assert!(pager.admit(1, 1));
        assert!(pager.admit(2, 1));
        assert!(pager.admit(3, 1));
        assert!(!pager.admit(4, 1));
        assert_eq!(pager.after, 3);
    }

    #[test]
    fn the_pager_stops_at_the_byte_ceiling_but_admits_an_exact_fit() {
        let mut pager = Pager::new(SMALL);
        assert!(pager.admit(1, 10));
        assert!(!pager.admit(2, 1));
        let mut over = Pager::new(SMALL);
        assert!(!over.admit(1, 11));
        assert_eq!(over.rows, 0);
    }

    #[test]
    fn the_pager_stops_at_the_render_ceiling() {
        let mut pager = Pager::new(Ceilings {
            bytes: 100,
            rows: 100,
            render: 5,
        });
        assert!(pager.admit(1, 5));
        assert!(!pager.admit(2, 1));
    }

    #[test]
    fn split_more_reads_only_a_trailing_marker() {
        assert_eq!(split_more("abc\n[12 bytes more]"), ("abc", Some(12)));
        assert_eq!(
            split_more("abc\n[ bytes more]"),
            ("abc\n[ bytes more]", None)
        );
        assert_eq!(
            split_more("abc\n[1x bytes more]"),
            ("abc\n[1x bytes more]", None)
        );
        assert_eq!(split_more("[3 bytes more]"), ("[3 bytes more]", None));
        assert_eq!(split_more("abc"), ("abc", None));
        assert_eq!(
            split_more("abc\n[+5 bytes more]"),
            ("abc\n[+5 bytes more]", None)
        );
    }

    #[test]
    fn a_capped_view_is_a_cut_even_when_the_read_was_whole() {
        assert!(!cut_of(false, false, 0).0);
        assert_eq!(
            cut_of(false, true, 7),
            (
                true,
                "transcript cut: at least 7 entries not shown.".to_owned()
            )
        );
        assert_eq!(cut_of(true, false, 0), (true, UNKNOWN_CUT.to_owned()));
    }

    #[test]
    fn one_hidden_entry_is_singular() {
        assert_eq!(
            cut_of(false, true, 1).1,
            "transcript cut: at least 1 entry not shown."
        );
        assert_eq!(
            cut_of(false, true, 2).1,
            "transcript cut: at least 2 entries not shown."
        );
    }

    #[test]
    fn a_line_of_several_items_after_the_cap_counts_one_so_the_cue_is_a_minimum() {
        let mut limits = ViewLimits::DEFAULT;
        limits.entries = 1;
        let mut asm = Assembler::with_limits(None, &limits);
        let call = |ids: &[&str]| {
            let blocks: Vec<_> = ids
                .iter()
                .map(|id| {
                    serde_json::json!({"type": "tool_use", "id": id, "name": "Bash",
                        "input": {"command": "x"}})
                })
                .collect();
            serde_json::json!({"type": "assistant", "message": {"id": "m", "role": "assistant",
                "content": blocks}, "parent_tool_use_id": null})
            .to_string()
        };
        asm.push(&call(&["a"]), false);
        asm.push(&call(&["b", "c", "d"]), false);
        asm.push(&call(&["e", "f", "g"]), false);
        let view = asm.snapshot();
        assert!(view.capped());
        assert_eq!(view.items().len(), 1);
        assert_eq!(view.dropped(), 4);
        assert_eq!(
            cut_of(false, view.capped(), view.dropped()).1,
            "transcript cut: at least 4 entries not shown."
        );
    }

    #[test]
    fn an_unfinished_read_never_states_a_count() {
        assert_eq!(cut_of(true, true, 7), (true, UNKNOWN_CUT.to_owned()));
    }

    #[test]
    fn indent_steps_to_a_ceiling() {
        assert_eq!(indent(0), "min-w-0");
        assert_eq!(indent(1), "ml-4 min-w-0");
        assert_eq!(indent(4), "ml-16 min-w-0");
        assert_eq!(indent(99), "ml-16 min-w-0");
    }

    fn assembled(lines: usize, error: bool) -> Vec<Item> {
        let mut asm = Assembler::new(None);
        for n in 0..lines {
            let call = serde_json::json!({"type": "assistant", "message": {"id": format!("m{n}"),
                "role": "assistant", "content": [{"type": "tool_use", "id": format!("t{n}"),
                "name": "Bash", "input": {"command": "x"}}]}, "parent_tool_use_id": null});
            let done = serde_json::json!({"type": "user", "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": format!("t{n}"), "content": "o",
                 "is_error": error}]}, "parent_tool_use_id": null});
            asm.push(&call.to_string(), false);
            asm.push(&done.to_string(), false);
        }
        asm.finish();
        asm.snapshot().items().to_vec()
    }

    #[test]
    fn only_the_first_twenty_error_pairs_open() {
        let rows = flatten(&assembled(25, true));
        let open = rows.iter().filter(|row| row.open.is_some()).count();
        assert_eq!(open, OPEN_ERROR_PAIRS);
    }

    #[test]
    fn ok_pairs_stay_closed() {
        let rows = flatten(&assembled(5, false));
        assert!(rows.iter().all(|row| row.open.is_none()));
    }

    #[test]
    fn twenty_thousand_entries_flatten_quickly_with_index_ids() {
        let started = std::time::Instant::now();
        let rows = flatten(&assembled(20_000, false));
        assert_eq!(rows.len(), 20_000);
        assert_eq!(rows[19_999].id, "tx-19999");
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
    }
}

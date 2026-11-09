//! The work tracker pages: projects, board, dependency graph, slice locks, item timeline and
//! defers by vertical (ADR-0064).
//!
//! Every route needs a session and reads through the owner-scoped store calls with the
//! session's user id, so a project of another user, an unknown project and a name that fails
//! validation all answer the same 404. The slice-lock view reads `work_slice_lease` with a
//! statement that joins `work_project` on the same user id.
//!
//! Every stored string is untrusted. [`line`] and [`block`] run it through
//! [`fleet_core::text`], which drops control characters, line and paragraph separators and
//! bidi overrides and cuts at [`LINE_CHARS`] or [`BLOCK_BYTES`]. Topcoat then escapes the text
//! and attribute values it renders. A stored name reaches a link only through [`slug`], which
//! percent-encodes every byte outside the unreserved set, so no stored value can start a
//! scheme or break an attribute.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fleet_core::Redactor;
use fleet_core::graph::{MAX_MERGEABLE, MAX_SLICES, MAX_TOTAL_PATHS};
use fleet_core::text::{Cap, is_hostile, sanitise_lines, sanitise_text};
use fleet_proto::v1::{
    GetWorkItemReply, GetWorkItemRequest, ListWorkDefersRequest, ListWorkItemsRequest, WorkAttempt,
    WorkDefer, WorkDeferState, WorkEvent, WorkItem, WorkItemState, WorkVerdict,
};
use sqlx::Row;
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        error::{not_found, see_other},
        page, path_param,
    },
    view::{View, component, view},
};

use super::jobs::{ConsoleSlot, when};
use super::layout::{Nav, shell};
use super::pages::{auth, current, fail};
use super::passkeys::AuthError;
use crate::store::{Store, StoreError, WorkFault};

/// The most characters one single-line field shows before it ends in `...`.
const LINE_CHARS: usize = 200;

/// The most bytes one multi-line field shows before a truncation marker follows it.
const BLOCK_BYTES: usize = 4096;

/// The longest project name or item key the pages look up, in characters.
const MAX_NAME_CHARS: usize = 128;

const PROJECT_ROW: &str = "SELECT id FROM work_project WHERE user_id = $1 AND name = $2";

const LOCKS: &str = "\
SELECT s.name, i.key AS item_key, a.id AS attempt_id, a.holder, \
(extract(epoch FROM a.expires_at) * 1000)::bigint AS expires_ms \
FROM work_slice s \
LEFT JOIN work_slice_lease l ON l.slice_id = s.id AND l.project_id = s.project_id \
LEFT JOIN work_attempt a ON a.id = l.attempt_id AND a.project_id = l.project_id \
LEFT JOIN work_item i ON i.id = a.item_id AND i.project_id = a.project_id \
WHERE s.project_id = $1 ORDER BY s.name LIMIT $2";

const SLICE_PATHS: &str = "\
SELECT s.name, p.path FROM work_slice_path p JOIN work_slice s ON s.id = p.slice_id \
WHERE s.project_id = $1 ORDER BY s.name, p.path LIMIT $2";

const MERGEABLE_PATHS: &str =
    "SELECT path FROM work_mergeable_path WHERE project_id = $1 ORDER BY path LIMIT $2";

path_param!(project_name);
path_param!(item_name);

const TABS: [(&str, &str, &str); 4] = [
    ("board", "", "Board"),
    ("graph", "/graph", "Graph"),
    ("locks", "/locks", "Locks"),
    ("defers", "/defers", "Defers"),
];

/// A stored string as one clean line of at most [`LINE_CHARS`] characters.
fn line(text: &str) -> String {
    let clean = sanitise_text(&Redactor::default(), text, Cap::Chars(LINE_CHARS));
    if clean.cut {
        format!("{}...", clean.text)
    } else {
        clean.text
    }
}

/// A stored string as clean text that keeps newline and tab, cut at [`BLOCK_BYTES`].
fn block(text: &str) -> (String, bool) {
    let clean = sanitise_lines(&Redactor::default(), text, Cap::Bytes(BLOCK_BYTES));
    (clean.text, clean.cut)
}

/// Percent-encodes every byte outside the unreserved set of RFC 3986.
fn slug(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn project_url(project: &str) -> String {
    format!("/work/{}", slug(project))
}

fn item_url(project: &str, item: &str) -> String {
    format!("/work/{}/items/{}", slug(project), slug(item))
}

fn checked(name: &str) -> Result<&str> {
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(is_hostile) {
        Err(not_found().into())
    } else {
        Ok(name)
    }
}

fn internal(err: &dyn std::fmt::Display) -> topcoat::Error {
    tracing::error!(error = %err, "work page read failed");
    fail(AuthError::Internal)
}

fn read_error(err: StoreError) -> topcoat::Error {
    match err {
        StoreError::Work(
            WorkFault::ProjectNotFound | WorkFault::ItemNotFound | WorkFault::Invalid(_),
        ) => not_found().into(),
        other => internal(&other),
    }
}

struct Viewer<'a> {
    store: &'a Store,
    user_id: i64,
    username: String,
    csrf: String,
}

async fn viewer(cx: &Cx) -> Result<Viewer<'_>> {
    let store = app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(not_found)?;
    let Some(session) = current(cx, auth(cx)?).await? else {
        return Err(see_other("/login").into());
    };
    Ok(Viewer {
        store,
        user_id: session.user_id,
        username: session.username.clone(),
        csrf: String::from_utf8_lossy(session.csrf.expose()).into_owned(),
    })
}

async fn project_id(who: &Viewer<'_>, name: &str) -> Result<i64> {
    sqlx::query_scalar(PROJECT_ROW)
        .bind(who.user_id)
        .bind(name)
        .fetch_optional(who.store.pool())
        .await
        .map_err(|err| internal(&err))?
        .ok_or_else(|| not_found().into())
}

fn item_state(item: &WorkItem) -> &'static str {
    match WorkItemState::try_from(item.state) {
        Ok(WorkItemState::Open) => "open",
        Ok(WorkItemState::Blocked) => "blocked",
        Ok(WorkItemState::Cancelled) => "cancelled",
        _ => "unknown",
    }
}

fn column_of(item: &WorkItem) -> &'static str {
    match item_state(item) {
        "cancelled" => "cancelled",
        "blocked" => "blocked",
        _ if item.passes > 0 => "done",
        _ if item.held => "held",
        _ if item.ready => "ready",
        _ => "waiting",
    }
}

fn verdict_name(verdict: Option<i32>) -> &'static str {
    match verdict.map(WorkVerdict::try_from) {
        None => "open",
        Some(Ok(WorkVerdict::Pass)) => "pass",
        Some(Ok(WorkVerdict::Fail)) => "fail",
        Some(Ok(WorkVerdict::Lost)) => "lost",
        Some(_) => "unknown",
    }
}

fn defer_state(defer: &WorkDefer) -> &'static str {
    match WorkDeferState::try_from(defer.state) {
        Ok(WorkDeferState::Open) => "open",
        Ok(WorkDeferState::Promoted) => "promoted",
        Ok(WorkDeferState::Dropped) => "dropped",
        _ => "unknown",
    }
}

fn state_badge(state: &str) -> &'static str {
    match state {
        "open" | "pass" => "badge badge-sm badge-success",
        "blocked" | "fail" | "lost" => "badge badge-sm badge-error",
        "promoted" => "badge badge-sm badge-info",
        _ => "badge badge-sm badge-ghost",
    }
}

#[component]
async fn project_head(name: String, slug: String, active: &'static str) -> Result<impl View> {
    let tabs: Vec<(String, &'static str, (), bool)> = TABS
        .iter()
        .map(|(id, suffix, label)| (format!("/work/{slug}{suffix}"), *label, (), *id == active))
        .collect();
    Ok(view! {
        <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
            <span class="text-primary">"$"</span>
            <h1 class="text-sm font-bold break-all">(name.as_str())</h1>
            <a class="link link-hover ml-auto" href="/work">"All projects"</a>
        </header>
        <nav class="mb-3 flex flex-wrap gap-3 text-xs" aria-label="Project">
            for tab in tabs {
                if tab.3 {
                    <a class="link font-bold" href=(tab.0.as_str()) aria-current="page">(tab.1)</a>
                } else {
                    <a class="link link-hover" href=(tab.0.as_str())>(tab.1)</a>
                }
            }
        </nav>
    })
}

struct ProjectRow {
    name: String,
    url: String,
    repo: String,
    slices: usize,
    created: String,
}

#[page("/work")]
async fn projects_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let reply = who
        .store
        .list_work_projects(who.user_id)
        .await
        .map_err(read_error)?;
    let rows: Vec<ProjectRow> = reply
        .projects
        .iter()
        .map(|project| ProjectRow {
            name: line(&project.name),
            url: project_url(&project.name),
            repo: project.repo.as_deref().map(line).unwrap_or_default(),
            slices: project.slices.len(),
            created: when(project.created_at_ms),
        })
        .collect();
    Ok(view! {
        shell(title: "fleet work", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                <span class="text-primary">"$"</span>
                <h1 class="text-sm font-bold">"Work projects"</h1>
            </header>
            if rows.is_empty() {
                <p id="no-projects" class="text-xs text-base-content/60">"No work projects."</p>
            } else {
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <caption class="sr-only">"Work projects"</caption>
                        <thead>
                            <tr>
                                <th scope="col">"Project"</th>
                                <th scope="col">"Repository"</th>
                                <th scope="col">"Slices"</th>
                                <th scope="col">"Created"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                <tr>
                                    <th scope="row" class="break-all"><a class="link link-primary" href=(row.url.as_str())>(row.name.as_str())</a></th>
                                    <td class="break-all">(row.repo.as_str())</td>
                                    <td>(row.slices)</td>
                                    <td>(row.created.as_str())</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        )
    })
}

struct Card {
    url: String,
    key: String,
    title: String,
    passes: u32,
    fails: u32,
}

struct Column {
    id: &'static str,
    label: &'static str,
    heading: String,
    cards: Vec<Card>,
}

const COLUMNS: [(&str, &str); 6] = [
    ("ready", "Ready"),
    ("held", "Held"),
    ("waiting", "Waiting"),
    ("done", "Done"),
    ("blocked", "Blocked"),
    ("cancelled", "Cancelled"),
];

fn columns(project: &str, items: &[WorkItem]) -> Vec<Column> {
    COLUMNS
        .iter()
        .map(|(id, label)| Column {
            id,
            label,
            heading: format!("col-{id}"),
            cards: items
                .iter()
                .filter(|item| column_of(item) == *id)
                .map(|item| Card {
                    url: item_url(project, &item.key),
                    key: line(&item.key),
                    title: line(&item.title),
                    passes: item.passes,
                    fails: item.fails,
                })
                .collect(),
        })
        .collect()
}

async fn items_of(who: &Viewer<'_>, project: &str) -> Result<Vec<WorkItem>> {
    let request = ListWorkItemsRequest {
        project: project.to_owned(),
        state: None,
        ready_only: false,
    };
    Ok(who
        .store
        .list_work_items(who.user_id, &request)
        .await
        .map_err(read_error)?
        .items)
}

#[page("/work/{project_name}")]
async fn board_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let columns = columns(project, &items_of(&who, project).await?);
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet work board", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "board")
            for column in columns {
                <section class="mb-4" data-section=(column.id) aria-labelledby=(column.heading.as_str())>
                    <h2 id=(column.heading.as_str()) class="mb-1 text-xs font-bold uppercase text-base-content/60">(column.label) " (" (column.cards.len()) ")"</h2>
                    if column.cards.is_empty() {
                        <p class="text-xs text-base-content/60">"No items."</p>
                    } else {
                        <ul class="text-xs">
                            for card in column.cards {
                                <li class="mb-1 break-all">
                                    <a class="link link-primary" href=(card.url.as_str())>(card.key.as_str())</a>
                                    " " (card.title.as_str())
                                    " " <span class="text-base-content/60">"pass " (card.passes) " fail " (card.fails)</span>
                                </li>
                            }
                        </ul>
                    }
                </section>
            }
        )
    })
}

struct Edge {
    key: String,
    mark: String,
    url: String,
    title: String,
    state: &'static str,
    deps: Vec<(String, String, String)>,
    needed_by: Vec<(String, String)>,
}

fn edges(project: &str, items: &[WorkItem]) -> Vec<Edge> {
    items
        .iter()
        .map(|item| Edge {
            key: line(&item.key),
            mark: slug(&item.key),
            url: item_url(project, &item.key),
            title: line(&item.title),
            state: item_state(item),
            deps: item
                .deps
                .iter()
                .map(|dep| {
                    (
                        line(&dep.depends_on),
                        item_url(project, &dep.depends_on),
                        line(&dep.why),
                    )
                })
                .collect(),
            needed_by: items
                .iter()
                .filter(|other| other.deps.iter().any(|dep| dep.depends_on == item.key))
                .map(|other| (line(&other.key), item_url(project, &other.key)))
                .collect(),
        })
        .collect()
}

#[page("/work/{project_name}/graph")]
async fn graph_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let edges = edges(project, &items_of(&who, project).await?);
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet work graph", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "graph")
            if edges.is_empty() {
                <p class="text-xs text-base-content/60">"No items."</p>
            } else {
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <caption class="sr-only">"Dependencies between items"</caption>
                        <thead>
                            <tr>
                                <th scope="col">"Item"</th>
                                <th scope="col">"Title"</th>
                                <th scope="col">"State"</th>
                                <th scope="col">"Depends on"</th>
                                <th scope="col">"Needed by"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for edge in edges {
                                <tr data-item=(edge.mark.as_str())>
                                    <th scope="row" class="break-all"><a class="link link-primary" href=(edge.url.as_str())>(edge.key.as_str())</a></th>
                                    <td class="break-all">(edge.title.as_str())</td>
                                    <td><span class=(state_badge(edge.state))>(edge.state)</span></td>
                                    <td>
                                        <ul>
                                            for dep in edge.deps {
                                                <li class="break-all"><a class="link" href=(dep.1.as_str())>(dep.0.as_str())</a> " " (dep.2.as_str())</li>
                                            }
                                        </ul>
                                    </td>
                                    <td>
                                        <ul>
                                            for other in edge.needed_by {
                                                <li class="break-all"><a class="link" href=(other.1.as_str())>(other.0.as_str())</a></li>
                                            }
                                        </ul>
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        )
    })
}

struct Lock {
    slice: String,
    mark: String,
    paths: Vec<String>,
    holder: Option<Holder>,
}

struct Holder {
    item: String,
    url: String,
    attempt: u64,
    by: String,
    expires: String,
}

async fn locks_of(who: &Viewer<'_>, project: &str) -> Result<(Vec<Lock>, Vec<String>)> {
    let id = project_id(who, project).await?;
    let pool = who.store.pool();
    let slices = i64::try_from(MAX_SLICES).unwrap_or(i64::MAX);
    let paths = i64::try_from(MAX_TOTAL_PATHS).unwrap_or(i64::MAX);
    let merge = i64::try_from(MAX_MERGEABLE).unwrap_or(i64::MAX);
    let mut by_slice: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in sqlx::query(SLICE_PATHS)
        .bind(id)
        .bind(paths)
        .fetch_all(pool)
        .await
        .map_err(|err| internal(&err))?
    {
        let name: String = row.try_get("name").map_err(|err| internal(&err))?;
        let path: String = row.try_get("path").map_err(|err| internal(&err))?;
        by_slice.entry(name).or_default().push(line(&path));
    }
    let mut locks = Vec::new();
    for row in sqlx::query(LOCKS)
        .bind(id)
        .bind(slices)
        .fetch_all(pool)
        .await
        .map_err(|err| internal(&err))?
    {
        let name: String = row.try_get("name").map_err(|err| internal(&err))?;
        let item: Option<String> = row.try_get("item_key").map_err(|err| internal(&err))?;
        let attempt: Option<i64> = row.try_get("attempt_id").map_err(|err| internal(&err))?;
        let by: Option<String> = row.try_get("holder").map_err(|err| internal(&err))?;
        let expires: Option<i64> = row.try_get("expires_ms").map_err(|err| internal(&err))?;
        let holder = match (item, attempt, by, expires) {
            (Some(item), Some(attempt), Some(by), Some(expires)) => Some(Holder {
                url: item_url(project, &item),
                item: line(&item),
                attempt: u64::try_from(attempt).map_err(|err| internal(&err))?,
                by: line(&by),
                expires: when(u64::try_from(expires).map_err(|err| internal(&err))?),
            }),
            _ => None,
        };
        locks.push(Lock {
            paths: by_slice.remove(&name).unwrap_or_default(),
            slice: line(&name),
            mark: slug(&name),
            holder,
        });
    }
    let mergeable = sqlx::query_scalar::<_, String>(MERGEABLE_PATHS)
        .bind(id)
        .bind(merge)
        .fetch_all(pool)
        .await
        .map_err(|err| internal(&err))?
        .iter()
        .map(|path| line(path))
        .collect();
    Ok((locks, mergeable))
}

#[page("/work/{project_name}/locks")]
async fn locks_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let (locks, mergeable) = locks_of(&who, project).await?;
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet work locks", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "locks")
            if locks.is_empty() {
                <p class="text-xs text-base-content/60">"No slices."</p>
            } else {
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <caption class="sr-only">"Slice leases"</caption>
                        <thead>
                            <tr>
                                <th scope="col">"Slice"</th>
                                <th scope="col">"Paths"</th>
                                <th scope="col">"Lease"</th>
                                <th scope="col">"Item"</th>
                                <th scope="col">"Holder"</th>
                                <th scope="col">"Attempt"</th>
                                <th scope="col">"Expires"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for lock in locks {
                                <tr data-slice=(lock.mark.as_str())>
                                    <th scope="row" class="break-all">(lock.slice.as_str())</th>
                                    <td>
                                        <ul>
                                            for path in lock.paths {
                                                <li class="break-all">(path.as_str())</li>
                                            }
                                        </ul>
                                    </td>
                                    if let Some(holder) = lock.holder {
                                        <td><span class="badge badge-sm badge-warning">"held"</span></td>
                                        <td class="break-all"><a class="link link-primary" href=(holder.url.as_str())>(holder.item.as_str())</a></td>
                                        <td class="break-all">(holder.by.as_str())</td>
                                        <td>(holder.attempt)</td>
                                        <td>(holder.expires.as_str())</td>
                                    } else {
                                        <td><span class="badge badge-sm badge-ghost">"free"</span></td>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                    }
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
            <h2 class="mb-1 mt-4 text-xs font-bold uppercase text-base-content/60">"Mergeable paths"</h2>
            if mergeable.is_empty() {
                <p class="text-xs text-base-content/60">"No mergeable paths."</p>
            } else {
                <ul class="text-xs">
                    for path in mergeable {
                        <li class="break-all">(path.as_str())</li>
                    }
                </ul>
            }
        )
    })
}

struct Text {
    text: String,
    cut: bool,
}

fn text_of(raw: &str) -> Text {
    let (text, cut) = block(raw);
    Text { text, cut }
}

struct AttemptRow {
    id: u64,
    holder: String,
    verdict: &'static str,
    claimed: String,
    expires: String,
    closed: String,
    note: Text,
    evidence: Text,
}

struct EventRow {
    id: u64,
    kind: String,
    actor: String,
    at: String,
    attempt: String,
    note: Text,
}

fn attempt_row(attempt: &WorkAttempt) -> AttemptRow {
    AttemptRow {
        id: attempt.id,
        holder: line(&attempt.holder),
        verdict: verdict_name(attempt.verdict),
        claimed: when(attempt.claimed_at_ms),
        expires: when(attempt.expires_at_ms),
        closed: attempt.closed_at_ms.map(when).unwrap_or_default(),
        note: text_of(&attempt.note),
        evidence: text_of(&attempt.evidence_tail),
    }
}

fn event_row(event: &WorkEvent) -> EventRow {
    EventRow {
        id: event.id,
        kind: line(&event.kind),
        actor: line(&event.actor),
        at: when(event.at_ms),
        attempt: event
            .attempt_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        note: text_of(&event.note),
    }
}

struct ItemView {
    title: String,
    state: &'static str,
    passes: u32,
    fails: u32,
    body: Text,
    slices: Vec<String>,
    deps: Vec<(String, String, String)>,
    attempts: Vec<AttemptRow>,
    events: Vec<EventRow>,
}

fn item_view(project: &str, reply: &GetWorkItemReply) -> Result<ItemView> {
    let item = reply.item.as_ref().ok_or_else(|| internal(&"empty item"))?;
    Ok(ItemView {
        title: line(&item.title),
        state: item_state(item),
        passes: item.passes,
        fails: item.fails,
        body: text_of(&item.body),
        slices: item.slices.iter().map(|slice| line(slice)).collect(),
        deps: item
            .deps
            .iter()
            .map(|dep| {
                (
                    line(&dep.depends_on),
                    item_url(project, &dep.depends_on),
                    line(&dep.why),
                )
            })
            .collect(),
        attempts: reply.attempts.iter().map(attempt_row).collect(),
        events: reply.events.iter().map(event_row).collect(),
    })
}

#[component]
async fn cell_text(text: Text) -> Result<impl View> {
    Ok(view! {
        <pre class="max-h-48 overflow-auto whitespace-pre-wrap text-xs">(text.text.as_str())</pre>
        if text.cut {
            <p class="text-xs text-base-content/60" data-truncated="">"[truncated]"</p>
        }
    })
}

#[component]
async fn attempts_section(attempts: Vec<AttemptRow>) -> Result<impl View> {
    Ok(view! {
        <section class="mb-3" aria-labelledby="item-attempts">
            <h3 id="item-attempts" class="mb-1 text-xs font-bold uppercase text-base-content/60">"Attempts"</h3>
            if attempts.is_empty() {
                <p class="text-xs text-base-content/60">"No attempts."</p>
            } else {
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <caption class="sr-only">"Attempts, oldest first"</caption>
                        <thead>
                            <tr>
                                <th scope="col">"Attempt"</th>
                                <th scope="col">"Holder"</th>
                                <th scope="col">"Verdict"</th>
                                <th scope="col">"Claimed"</th>
                                <th scope="col">"Expires"</th>
                                <th scope="col">"Closed"</th>
                                <th scope="col">"Note"</th>
                                <th scope="col">"Evidence"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for attempt in attempts {
                                <tr data-attempt=(attempt.id)>
                                    <th scope="row">(attempt.id)</th>
                                    <td class="break-all">(attempt.holder.as_str())</td>
                                    <td><span class=(state_badge(attempt.verdict))>(attempt.verdict)</span></td>
                                    <td>(attempt.claimed.as_str())</td>
                                    <td>(attempt.expires.as_str())</td>
                                    <td>(attempt.closed.as_str())</td>
                                    <td>cell_text(text: attempt.note)</td>
                                    <td>cell_text(text: attempt.evidence)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
    })
}

#[component]
async fn events_section(events: Vec<EventRow>) -> Result<impl View> {
    Ok(view! {
        <section class="mb-3" aria-labelledby="item-events">
            <h3 id="item-events" class="mb-1 text-xs font-bold uppercase text-base-content/60">"Events"</h3>
            if events.is_empty() {
                <p class="text-xs text-base-content/60">"No events."</p>
            } else {
                <ol class="text-xs">
                    for event in events {
                        <li class="mb-2" data-event=(event.id)>
                            <span>(event.at.as_str())</span>
                            " " <span class="badge badge-sm badge-ghost">(event.kind.as_str())</span>
                            " " <span class="break-all">(event.actor.as_str())</span>
                            if !event.attempt.is_empty() {
                                " attempt " (event.attempt.as_str())
                            }
                            cell_text(text: event.note)
                        </li>
                    }
                </ol>
            }
        </section>
    })
}

#[page("/work/{project_name}/items/{item_name}")]
async fn item_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let key = checked(path_param::<ItemName>(cx))?;
    let request = GetWorkItemRequest {
        project: project.to_owned(),
        item_key: key.to_owned(),
    };
    let reply = who
        .store
        .get_work_item(who.user_id, &request)
        .await
        .map_err(read_error)?;
    let item = item_view(project, &reply)?;
    let (name, slug, key_text) = (line(project), slug(project), line(key));
    Ok(view! {
        shell(title: "fleet work item", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "")
            <h2 class="mb-1 text-sm font-bold break-all">(key_text.as_str())</h2>
            <p class="mb-2 text-xs break-all">(item.title.as_str())</p>
            <p class="mb-2 text-xs">
                <span class=(state_badge(item.state))>(item.state)</span>
                " pass " (item.passes) " fail " (item.fails)
            </p>
            <section class="mb-3" aria-labelledby="item-body">
                <h3 id="item-body" class="mb-1 text-xs font-bold uppercase text-base-content/60">"Description"</h3>
                cell_text(text: item.body)
            </section>
            <section class="mb-3" aria-labelledby="item-slices">
                <h3 id="item-slices" class="mb-1 text-xs font-bold uppercase text-base-content/60">"Slices"</h3>
                <ul class="text-xs">
                    for slice in item.slices {
                        <li class="break-all">(slice.as_str())</li>
                    }
                </ul>
            </section>
            <section class="mb-3" aria-labelledby="item-deps">
                <h3 id="item-deps" class="mb-1 text-xs font-bold uppercase text-base-content/60">"Depends on"</h3>
                <ul class="text-xs">
                    for dep in item.deps {
                        <li class="break-all"><a class="link" href=(dep.1.as_str())>(dep.0.as_str())</a> " " (dep.2.as_str())</li>
                    }
                </ul>
            </section>
            attempts_section(attempts: item.attempts)
            events_section(events: item.events)
        )
    })
}

struct DeferRow {
    id: u64,
    title: String,
    reason: Text,
    state: &'static str,
    item: Option<(String, String)>,
    promoted: Option<(String, String)>,
    created: String,
}

struct Vertical {
    name: String,
    section: String,
    rows: Vec<DeferRow>,
}

fn verticals(project: &str, defers: &[WorkDefer]) -> Vec<Vertical> {
    let link = |key: &Option<String>| key.as_ref().map(|key| (line(key), item_url(project, key)));
    let mut groups: BTreeMap<String, Vec<DeferRow>> = BTreeMap::new();
    for defer in defers {
        groups
            .entry(line(&defer.vertical))
            .or_default()
            .push(DeferRow {
                id: defer.id,
                title: line(&defer.title),
                reason: text_of(&defer.reason),
                state: defer_state(defer),
                item: link(&defer.item_key),
                promoted: link(&defer.promoted_item_key),
                created: when(defer.created_at_ms),
            });
    }
    groups
        .into_iter()
        .map(|(name, rows)| Vertical {
            section: format!("vertical-{}", slug(&name)),
            name,
            rows,
        })
        .collect()
}

#[page("/work/{project_name}/defers")]
async fn defers_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let request = ListWorkDefersRequest {
        project: project.to_owned(),
        vertical: None,
        state: None,
    };
    let (groups, too_many) = match who.store.list_work_defers(who.user_id, &request).await {
        Ok(reply) => (verticals(project, &reply.defers), false),
        Err(StoreError::Work(WorkFault::Precondition(_))) => (Vec::new(), true),
        Err(err) => return Err(read_error(err)),
    };
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet work defers", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "defers")
            if too_many {
                <p id="too-many" class="text-xs">"Too many defers to list."</p>
            } else if groups.is_empty() {
                <p class="text-xs text-base-content/60">"No defers."</p>
            }
            for group in groups {
                <section class="mb-4" data-section=(group.section.as_str())>
                    <h2 class="mb-1 text-xs font-bold uppercase text-base-content/60 break-all">(group.name.as_str())</h2>
                    <div class="overflow-x-auto">
                        <table class="table table-zebra table-xs">
                            <caption class="sr-only">"Defers of one vertical"</caption>
                            <thead>
                                <tr>
                                    <th scope="col">"Defer"</th>
                                    <th scope="col">"Title"</th>
                                    <th scope="col">"State"</th>
                                    <th scope="col">"Reason"</th>
                                    <th scope="col">"Item"</th>
                                    <th scope="col">"Promoted to"</th>
                                    <th scope="col">"Created"</th>
                                </tr>
                            </thead>
                            <tbody>
                                for row in group.rows {
                                    <tr data-defer=(row.id)>
                                        <th scope="row">(row.id)</th>
                                        <td class="break-all">(row.title.as_str())</td>
                                        <td><span class=(state_badge(row.state))>(row.state)</span></td>
                                        <td>cell_text(text: row.reason)</td>
                                        <td class="break-all">
                                            if let Some(item) = row.item {
                                                <a class="link" href=(item.1.as_str())>(item.0.as_str())</a>
                                            }
                                        </td>
                                        <td class="break-all">
                                            if let Some(item) = row.promoted {
                                                <a class="link" href=(item.1.as_str())>(item.0.as_str())</a>
                                            }
                                        </td>
                                        <td>(row.created.as_str())</td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
                </section>
            }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE: [&str; 9] = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "a\r\nb",
        "a\u{85}b",
        "a\u{2028}b\u{2029}c",
        "a\u{202e}b",
        "a\0b",
        "a\u{7}b\u{1b}[31m",
    ];

    #[test]
    fn line_and_block_drop_every_hostile_character() {
        for raw in HOSTILE {
            for clean in [line(raw), block(raw).0] {
                assert!(
                    !clean.chars().any(|c| is_hostile(c) && c != '\n'),
                    "{raw:?} gave {clean:?}"
                );
            }
        }
    }

    #[test]
    fn line_keeps_one_line_and_block_keeps_newlines() {
        assert_eq!(line("a\nb\tc"), "abc");
        assert_eq!(block("a\r\nb\tc").0, "a\nb\tc");
    }

    #[test]
    fn line_cuts_at_the_char_cap_with_a_marker() {
        let long = "x".repeat(LINE_CHARS + 1);
        assert_eq!(line(&long), format!("{}...", "x".repeat(LINE_CHARS)));
        assert_eq!(line(&"x".repeat(LINE_CHARS)), "x".repeat(LINE_CHARS));
    }

    #[test]
    fn block_cuts_at_the_byte_cap_and_says_so() {
        let (text, cut) = block(&"y".repeat(BLOCK_BYTES + 1));
        assert!(cut);
        assert_eq!(text.len(), BLOCK_BYTES);
        assert!(!block(&"y".repeat(BLOCK_BYTES)).1);
    }

    #[test]
    fn slug_encodes_everything_outside_the_unreserved_set() {
        assert_eq!(slug("a-b.c_d~E9"), "a-b.c_d~E9");
        assert_eq!(slug("a b/c?d#e%f"), "a%20b%2Fc%3Fd%23e%25f");
        assert_eq!(slug("javascript:alert(1)"), "javascript%3Aalert%281%29");
        assert_eq!(slug("\u{e9}"), "%C3%A9");
    }

    #[test]
    fn checked_refuses_empty_long_and_hostile_names() {
        for bad in [
            "",
            "a\0b",
            "a\rb",
            "a\u{202e}b",
            &"x".repeat(MAX_NAME_CHARS + 1),
        ] {
            assert!(checked(bad).is_err(), "{bad:?}");
        }
        assert!(checked("plain name").is_ok());
        assert!(checked(&"x".repeat(MAX_NAME_CHARS)).is_ok());
    }
}

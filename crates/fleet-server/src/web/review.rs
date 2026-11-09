//! The retro, improvement, pitfall and suggested-edit pages (ADR-0065, ADR-0066): retro list
//! and detail with improvements by disposition, a verify view of what blocks closing a retro,
//! project and user-level pitfall lists, the edit list and the diff review page with accept and
//! reject.
//!
//! Every route needs a session and reads through the owner-scoped store calls with the
//! session's user id, so a foreign, an unknown and an invalid project, retro or edit id all
//! answer the same 404. Stored text is cleaned by [`super::work::line`] and
//! [`super::work::block`] and escaped by Topcoat, and a stored key reaches a link only through
//! [`super::work::slug`].
//!
//! Every list shows at most [`ROW_CAP`] rows and says so with `data-rows-truncated`. A diff
//! shows at most [`DIFF_LINES`] lines and [`DIFF_BYTES`] bytes and says so with
//! `data-diff-truncated`.
//!
//! The decide route is a session POST that checks the CSRF token and then calls
//! [`Store::decide_edit`] as the session's user. A Client or Box token carries no session, so
//! the route refuses it, and the store refuses the bootstrap user. A stale edit shows its
//! accept button disabled and the store refuses the accept too.

use std::collections::HashMap;

use fleet_core::EventId;
use fleet_core::Redactor;
use fleet_core::text::{Cap, sanitise_lines};
use fleet_proto::v1::{
    DecideEditRequest, EditDecision, EditKind, EditState, Improvement, ImprovementDisposition,
    ImprovementKind, ListEditsRequest, ListImprovementsRequest, ListPitfallsRequest,
    ListRetrosRequest, Pitfall, Retro, RetroState, SuggestedEdit,
};
use topcoat::{
    Result,
    context::{Cx, app_context},
    router::{
        content::Form,
        error::{SeeOther, bad_request, forbidden, not_found, see_other},
        page, path_param,
        request::uri,
        route,
    },
    view::{View, component, view},
};

use super::jobs::{ConsoleSlot, when};
use super::layout::{Nav, shell};
use super::pages::{auth, csrf_matches, signed_in};
use super::work::{
    Text, Viewer, cell_text, checked, internal, item_url, line, project_head, project_url, slug,
    state_badge, text_of, viewer,
};
use crate::store::{REASON_DECIDED, REASON_DOES_NOT_APPLY, REASON_STALE, StoreError, WorkFault};

/// The most rows one list page renders before a truncation marker follows it.
const ROW_CAP: usize = 200;

/// The most diff lines the review page renders.
const DIFF_LINES: usize = 400;

/// The most diff bytes the review page renders.
const DIFF_BYTES: usize = 16384;

path_param!(project_name);
path_param!(retro_id);
path_param!(edit_id);

/// Parses a path id: digits only, at least 1 and at most `i64::MAX`.
fn row_id(raw: &str) -> Result<u64> {
    match raw.parse::<u64>() {
        Ok(id)
            if id >= 1 && i64::try_from(id).is_ok() && raw.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Ok(id)
        }
        _ => Err(not_found().into()),
    }
}

fn read_error(err: StoreError) -> topcoat::Error {
    match err {
        StoreError::Work(
            WorkFault::ProjectNotFound
            | WorkFault::RetroNotFound
            | WorkFault::EditNotFound
            | WorkFault::Invalid(_),
        ) => not_found().into(),
        other => internal(&other),
    }
}

fn capped<T>(mut rows: Vec<T>) -> (Vec<T>, bool) {
    let cut = rows.len() > ROW_CAP;
    rows.truncate(ROW_CAP);
    (rows, cut)
}

#[component]
async fn rows_marker(cut: bool) -> Result<impl View> {
    Ok(view! {
        if cut {
            <p class="text-xs text-base-content/60" data-rows-truncated="">"[more rows not shown]"</p>
        }
    })
}

#[component]
async fn too_many() -> Result<impl View> {
    Ok(view! {
        <p id="too-many" class="text-xs">"Too many rows to list."</p>
    })
}

fn retro_state(retro: &Retro) -> &'static str {
    match RetroState::try_from(retro.state) {
        Ok(RetroState::Open) => "open",
        Ok(RetroState::Closed) => "closed",
        _ => "unknown",
    }
}

fn improvement_kind(kind: i32) -> &'static str {
    match ImprovementKind::try_from(kind) {
        Ok(ImprovementKind::Process) => "process",
        Ok(ImprovementKind::Tooling) => "tooling",
        Ok(ImprovementKind::Docs) => "docs",
        Ok(ImprovementKind::Test) => "test",
        Ok(ImprovementKind::Pitfall) => "pitfall",
        Ok(ImprovementKind::Other) => "other",
        _ => "unknown",
    }
}

fn disposition_name(disposition: Option<i32>) -> &'static str {
    match disposition.map(ImprovementDisposition::try_from) {
        None => "undecided",
        Some(Ok(ImprovementDisposition::Accepted)) => "accepted",
        Some(Ok(ImprovementDisposition::Rejected)) => "rejected",
        Some(Ok(ImprovementDisposition::Deferred)) => "deferred",
        Some(Ok(ImprovementDisposition::Applied)) => "applied",
        Some(_) => "unknown",
    }
}

fn edit_kind(edit: &SuggestedEdit) -> &'static str {
    match EditKind::try_from(edit.kind) {
        Ok(EditKind::SliceOp) => "slice_op",
        Ok(EditKind::Pitfall) => "pitfall",
        Ok(EditKind::FilePatch) => "file_patch",
        _ => "unknown",
    }
}

fn edit_state(edit: &SuggestedEdit) -> &'static str {
    match EditState::try_from(edit.state) {
        Ok(EditState::Pending) => "pending",
        Ok(EditState::Accepted) => "accepted",
        Ok(EditState::Rejected) => "rejected",
        Ok(EditState::Stale) => "stale",
        _ => "unknown",
    }
}

fn edit_badge(state: &str) -> &'static str {
    match state {
        "accepted" => "badge badge-sm badge-success",
        "stale" => "badge badge-sm badge-warning",
        "rejected" => "badge badge-sm badge-error",
        _ => "badge badge-sm badge-ghost",
    }
}

fn edit_url(project: &str, id: u64) -> String {
    format!("{}/edits/{id}", project_url(project))
}

fn retro_url(project: &str, id: u64) -> String {
    format!("{}/retros/{id}", project_url(project))
}

struct RetroRow {
    id: u64,
    url: String,
    title: String,
    state: &'static str,
    from: Option<(String, String)>,
    to: Option<(String, String)>,
    opened: String,
    closed: String,
}

fn retro_row(project: &str, retro: &Retro) -> RetroRow {
    let link = |key: &Option<String>| key.as_ref().map(|key| (line(key), item_url(project, key)));
    RetroRow {
        id: retro.id,
        url: retro_url(project, retro.id),
        title: line(&retro.title),
        state: retro_state(retro),
        from: link(&retro.span_from_item_key),
        to: link(&retro.span_to_item_key),
        opened: when(retro.opened_at_ms),
        closed: retro.closed_at_ms.map(when).unwrap_or_default(),
    }
}

async fn retros_of(who: &Viewer<'_>, project: &str) -> Result<Option<Vec<Retro>>> {
    let request = ListRetrosRequest {
        project: project.to_owned(),
        state: None,
    };
    match who.store.list_retros(who.user_id, &request).await {
        Ok(reply) => Ok(Some(reply.retros)),
        Err(StoreError::Work(WorkFault::Precondition(_))) => Ok(None),
        Err(err) => Err(read_error(err)),
    }
}

async fn find_retro(who: &Viewer<'_>, project: &str, id: u64) -> Result<Retro> {
    for state in [None, Some(RetroState::Open), Some(RetroState::Closed)] {
        let request = ListRetrosRequest {
            project: project.to_owned(),
            state: state.map(Into::into),
        };
        match who.store.list_retros(who.user_id, &request).await {
            Ok(reply) => {
                return reply
                    .retros
                    .into_iter()
                    .find(|retro| retro.id == id)
                    .ok_or_else(|| not_found().into());
            }
            Err(StoreError::Work(WorkFault::Precondition(_))) => {}
            Err(err) => return Err(read_error(err)),
        }
    }
    Err(not_found().into())
}

#[page("/work/{project_name}/retros")]
async fn retros_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let listed = retros_of(&who, project).await?;
    let overflow = listed.is_none();
    let (retros, cut) = capped(listed.unwrap_or_default());
    let rows: Vec<RetroRow> = retros
        .iter()
        .map(|retro| retro_row(project, retro))
        .collect();
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet retros", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "retros")
            if overflow {
                too_many()
            } else if rows.is_empty() {
                <p class="text-xs text-base-content/60">"No retros."</p>
            } else {
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <caption class="sr-only">"Retros"</caption>
                        <thead>
                            <tr>
                                <th scope="col">"Retro"</th>
                                <th scope="col">"State"</th>
                                <th scope="col">"From"</th>
                                <th scope="col">"To"</th>
                                <th scope="col">"Opened"</th>
                                <th scope="col">"Closed"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                <tr data-retro=(row.id)>
                                    <th scope="row" class="break-all"><a class="link link-primary" href=(row.url.as_str())>(row.title.as_str())</a></th>
                                    <td><span class=(state_badge(if row.state == "open" { "open" } else { "closed" }))>(row.state)</span></td>
                                    <td class="break-all">
                                        if let Some(item) = row.from {
                                            <a class="link" href=(item.1.as_str())>(item.0.as_str())</a>
                                        }
                                    </td>
                                    <td class="break-all">
                                        if let Some(item) = row.to {
                                            <a class="link" href=(item.1.as_str())>(item.0.as_str())</a>
                                        }
                                    </td>
                                    <td>(row.opened.as_str())</td>
                                    <td>(row.closed.as_str())</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
                rows_marker(cut: cut)
            }
        )
    })
}

struct ImprovementRow {
    vertical: String,
    title: String,
    kind: &'static str,
    occurrences: u32,
    item: Option<(String, String)>,
    reason: Text,
    body: Text,
}

struct Group {
    name: &'static str,
    section: String,
    rows: Vec<ImprovementRow>,
}

const DISPOSITIONS: [(&str, &str); 5] = [
    ("undecided", "Undecided"),
    ("accepted", "Accepted"),
    ("rejected", "Rejected"),
    ("deferred", "Deferred"),
    ("applied", "Applied"),
];

fn improvement_row(project: &str, improvement: &Improvement) -> ImprovementRow {
    ImprovementRow {
        vertical: line(&improvement.vertical),
        title: line(&improvement.title),
        kind: improvement_kind(improvement.kind),
        occurrences: improvement.occurrences,
        item: improvement
            .item_key
            .as_ref()
            .map(|key| (line(key), item_url(project, key))),
        reason: text_of(
            improvement
                .disposition_reason
                .as_deref()
                .unwrap_or_default(),
        ),
        body: text_of(&improvement.body),
    }
}

fn groups(project: &str, improvements: &[Improvement]) -> Vec<Group> {
    DISPOSITIONS
        .iter()
        .map(|(id, label)| Group {
            name: label,
            section: format!("disp-{id}"),
            rows: improvements
                .iter()
                .filter(|improvement| disposition_name(improvement.disposition) == *id)
                .map(|improvement| improvement_row(project, improvement))
                .collect(),
        })
        .collect()
}

async fn improvements_of(
    who: &Viewer<'_>,
    project: &str,
    retro: u64,
    undecided: bool,
) -> Result<Option<Vec<Improvement>>> {
    let request = ListImprovementsRequest {
        project: project.to_owned(),
        vertical: None,
        retro_id: Some(retro),
        undecided: undecided.then_some(true),
    };
    match who.store.list_improvements(who.user_id, &request).await {
        Ok(reply) => Ok(Some(reply.improvements)),
        Err(StoreError::Work(WorkFault::Precondition(_))) => Ok(None),
        Err(err) => Err(read_error(err)),
    }
}

#[page("/work/{project_name}/retros/{retro_id}")]
async fn retro_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let id = row_id(path_param::<RetroId>(cx))?;
    let retro = find_retro(&who, project, id).await?;
    let listed = improvements_of(&who, project, id, false).await?;
    let too_many_rows = listed.is_none();
    let (improvements, cut) = capped(listed.unwrap_or_default());
    let groups = groups(project, &improvements);
    let head = retro_row(project, &retro);
    let verify = format!("{}/verify", head.url);
    let all = format!("{}/retros", project_url(project));
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet retro", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "retros")
            <h2 class="mb-1 text-sm font-bold break-all">(head.title.as_str())</h2>
            <p class="mb-2 text-xs">
                <span class=(state_badge(if head.state == "open" { "open" } else { "closed" }))>(head.state)</span>
                " opened " (head.opened.as_str())
                " " <a class="link" href=(verify.as_str())>"Verify review"</a>
                " " <a class="link" href=(all.as_str())>"All retros"</a>
            </p>
            <p class="mb-2 text-xs break-all">
                "span "
                if let Some(item) = head.from {
                    <a class="link" href=(item.1.as_str())>(item.0.as_str())</a>
                }
                " to "
                if let Some(item) = head.to {
                    <a class="link" href=(item.1.as_str())>(item.0.as_str())</a>
                }
            </p>
            if too_many_rows {
                too_many()
            }
            for group in groups {
                <section class="mb-4" data-section=(group.section.as_str())>
                    <h3 class="mb-1 text-xs font-bold uppercase text-base-content/60">(group.name) " (" (group.rows.len()) ")"</h3>
                    if group.rows.is_empty() {
                        <p class="text-xs text-base-content/60">"None."</p>
                    } else {
                        <div class="overflow-x-auto">
                            <table class="table table-zebra table-xs">
                                <caption class="sr-only">"Improvements"</caption>
                                <thead>
                                    <tr>
                                        <th scope="col">"Improvement"</th>
                                        <th scope="col">"Vertical"</th>
                                        <th scope="col">"Kind"</th>
                                        <th scope="col">"Count"</th>
                                        <th scope="col">"Item"</th>
                                        <th scope="col">"Reason"</th>
                                        <th scope="col">"Body"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    for row in group.rows {
                                        <tr>
                                            <th scope="row" class="break-all">(row.title.as_str())</th>
                                            <td class="break-all">(row.vertical.as_str())</td>
                                            <td>(row.kind)</td>
                                            <td>(row.occurrences)</td>
                                            <td class="break-all">
                                                if let Some(item) = row.item {
                                                    <a class="link" href=(item.1.as_str())>(item.0.as_str())</a>
                                                }
                                            </td>
                                            <td>cell_text(text: row.reason)</td>
                                            <td>cell_text(text: row.body)</td>
                                        </tr>
                                    }
                                </tbody>
                            </table>
                        </div>
                    }
                </section>
            }
            rows_marker(cut: cut)
        )
    })
}

#[page("/work/{project_name}/retros/{retro_id}/verify")]
async fn verify_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let id = row_id(path_param::<RetroId>(cx))?;
    let retro = find_retro(&who, project, id).await?;
    let listed = improvements_of(&who, project, id, true).await?;
    let too_many_rows = listed.is_none();
    let open = retro_state(&retro) == "open";
    let (undecided, cut) = capped(listed.unwrap_or_default());
    let rows: Vec<ImprovementRow> = undecided
        .iter()
        .map(|improvement| improvement_row(project, improvement))
        .collect();
    let verdict = if !open {
        "closed"
    } else if rows.is_empty() && !too_many_rows {
        "ready"
    } else {
        "blocked"
    };
    let head = retro_row(project, &retro);
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet retro verify", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "retros")
            <h2 class="mb-1 text-sm font-bold break-all">"Verify review: " (head.title.as_str())</h2>
            <p class="mb-2 text-xs" data-verify=(verdict)>
                if verdict == "closed" {
                    "This retro is closed."
                } else if verdict == "ready" {
                    "Every improvement has a disposition. The retro can close."
                } else {
                    "The retro cannot close while these improvements have no disposition."
                }
            </p>
            if too_many_rows {
                too_many()
            }
            if !rows.is_empty() {
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <caption class="sr-only">"Improvements without a disposition"</caption>
                        <thead>
                            <tr>
                                <th scope="col">"Improvement"</th>
                                <th scope="col">"Vertical"</th>
                                <th scope="col">"Kind"</th>
                                <th scope="col">"Count"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                <tr>
                                    <th scope="row" class="break-all">(row.title.as_str())</th>
                                    <td class="break-all">(row.vertical.as_str())</td>
                                    <td>(row.kind)</td>
                                    <td>(row.occurrences)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
                rows_marker(cut: cut)
            }
            <p class="mt-3 text-xs"><a class="link" href=(head.url.as_str())>"Back to the retro"</a></p>
        )
    })
}

struct PitfallRow {
    symptom: String,
    cause: String,
    fix: String,
    hits: u32,
    last: String,
}

fn pitfall_rows(pitfalls: Vec<Pitfall>) -> (Vec<PitfallRow>, bool) {
    let (pitfalls, cut) = capped(pitfalls);
    let rows = pitfalls
        .iter()
        .map(|pitfall| PitfallRow {
            symptom: line(&pitfall.symptom),
            cause: line(&pitfall.cause),
            fix: line(&pitfall.fix),
            hits: pitfall.hits,
            last: pitfall.last_hit_at_ms.map(when).unwrap_or_default(),
        })
        .collect();
    (rows, cut)
}

async fn pitfalls_of(
    who: &Viewer<'_>,
    project: Option<&str>,
) -> Result<Option<(Vec<PitfallRow>, bool)>> {
    let request = ListPitfallsRequest {
        project: project.map(str::to_owned),
    };
    match who.store.list_pitfalls(who.user_id, &request).await {
        Ok(reply) => Ok(Some(pitfall_rows(reply.pitfalls))),
        Err(StoreError::Work(WorkFault::Precondition(_))) => Ok(None),
        Err(err) => Err(read_error(err)),
    }
}

#[component]
async fn pitfall_table(rows: Vec<PitfallRow>, cut: bool, overflow: bool) -> Result<impl View> {
    Ok(view! {
        if overflow {
            too_many()
        } else if rows.is_empty() {
            <p class="text-xs text-base-content/60">"No pitfalls."</p>
        } else {
            <div class="overflow-x-auto">
                <table class="table table-zebra table-xs">
                    <caption class="sr-only">"Pitfalls, most hit first"</caption>
                    <thead>
                        <tr>
                            <th scope="col">"Symptom"</th>
                            <th scope="col">"Cause"</th>
                            <th scope="col">"Fix"</th>
                            <th scope="col">"Hits"</th>
                            <th scope="col">"Last hit"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for row in rows {
                            <tr>
                                <th scope="row" class="break-all">(row.symptom.as_str())</th>
                                <td class="break-all">(row.cause.as_str())</td>
                                <td class="break-all">(row.fix.as_str())</td>
                                <td>(row.hits)</td>
                                <td>(row.last.as_str())</td>
                            </tr>
                        }
                    </tbody>
                </table>
            </div>
            rows_marker(cut: cut)
        }
    })
}

#[page("/work/{project_name}/pitfalls")]
async fn project_pitfalls_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let listed = pitfalls_of(&who, Some(project)).await?;
    let too_many_rows = listed.is_none();
    let (rows, cut) = listed.unwrap_or_default();
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet pitfalls", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "pitfalls")
            <p class="mb-2 text-xs"><a class="link" href="/pitfalls">"Your user-level pitfalls"</a></p>
            pitfall_table(rows: rows, cut: cut, overflow: too_many_rows)
        )
    })
}

#[page("/pitfalls")]
async fn user_pitfalls_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let listed = pitfalls_of(&who, None).await?;
    let too_many_rows = listed.is_none();
    let (rows, cut) = listed.unwrap_or_default();
    Ok(view! {
        shell(title: "fleet pitfalls", active: Nav::Pitfalls, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            <header class="mb-3 flex min-w-0 flex-wrap items-center gap-3 border-b border-base-300 pb-2 text-xs">
                <span class="text-primary">"$"</span>
                <h1 class="text-sm font-bold">"Pitfalls"</h1>
            </header>
            pitfall_table(rows: rows, cut: cut, overflow: too_many_rows)
        )
    })
}

struct EditRow {
    id: u64,
    url: String,
    kind: &'static str,
    state: &'static str,
    target: String,
    filed_by: String,
    created: String,
}

fn edit_row(project: &str, edit: &SuggestedEdit) -> EditRow {
    EditRow {
        id: edit.id,
        url: edit_url(project, edit.id),
        kind: edit_kind(edit),
        state: edit_state(edit),
        target: line(&edit.target),
        filed_by: line(&edit.filed_by),
        created: when(edit.created_at_ms),
    }
}

#[page("/work/{project_name}/edits")]
async fn edits_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let request = ListEditsRequest {
        project: project.to_owned(),
        state: None,
    };
    let mut edits = who
        .store
        .list_edits(who.user_id, &request)
        .await
        .map_err(read_error)?
        .edits;
    edits.reverse();
    let (edits, cut) = capped(edits);
    let rows: Vec<EditRow> = edits.iter().map(|edit| edit_row(project, edit)).collect();
    let (name, slug) = (line(project), slug(project));
    Ok(view! {
        shell(title: "fleet suggested edits", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "edits")
            if rows.is_empty() {
                <p class="text-xs text-base-content/60">"No suggested edits."</p>
            } else {
                <div class="overflow-x-auto">
                    <table class="table table-zebra table-xs">
                        <caption class="sr-only">"Suggested edits, newest first"</caption>
                        <thead>
                            <tr>
                                <th scope="col">"Edit"</th>
                                <th scope="col">"Kind"</th>
                                <th scope="col">"State"</th>
                                <th scope="col">"Target"</th>
                                <th scope="col">"Filed by"</th>
                                <th scope="col">"Filed"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                <tr data-edit=(row.id)>
                                    <th scope="row"><a class="link link-primary" href=(row.url.as_str())>(row.id)</a></th>
                                    <td>(row.kind)</td>
                                    <td><span class=(edit_badge(row.state))>(row.state)</span></td>
                                    <td class="break-all">(row.target.as_str())</td>
                                    <td class="break-all">(row.filed_by.as_str())</td>
                                    <td>(row.created.as_str())</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
                rows_marker(cut: cut)
            }
        )
    })
}

/// The payload as clean text of at most [`DIFF_LINES`] lines and [`DIFF_BYTES`] bytes, each
/// line ended by a newline, and whether anything was cut.
fn diff_text(payload: &str) -> (String, bool) {
    let clean = sanitise_lines(&Redactor::default(), payload, Cap::Bytes(DIFF_BYTES));
    let mut out = String::new();
    let mut cut = clean.cut;
    for (shown, text) in clean.text.lines().enumerate() {
        if shown == DIFF_LINES {
            cut = true;
            break;
        }
        out.push_str(text);
        out.push('\n');
    }
    (out, cut)
}

fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "accepted" => "Edit accepted.",
        "rejected" => "Edit rejected.",
        "stale" => "The target changed since the edit was filed, so it cannot be accepted.",
        "decided" => "The edit was already decided.",
        "does_not_apply" => "The edit does not apply to the current graph. It stays pending.",
        "not_interactive" => "Only a signed-in person can decide an edit.",
        _ => return None,
    })
}

fn notice_code(cx: &Cx) -> Option<&str> {
    uri(cx)
        .query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix("notice="))
}

#[page("/work/{project_name}/edits/{edit_id}")]
async fn edit_page(cx: &Cx) -> Result<impl View> {
    let who = viewer(cx).await?;
    let project = checked(path_param::<ProjectName>(cx))?;
    let id = row_id(path_param::<EditId>(cx))?;
    let request = fleet_proto::v1::GetEditRequest {
        project: project.to_owned(),
        id,
    };
    let edit = who
        .store
        .get_edit(who.user_id, &request)
        .await
        .map_err(read_error)?;
    let head = edit_row(project, &edit);
    let (diff, cut) = diff_text(&edit.payload);
    let hash = line(&edit.base_hash);
    let notice = notice_code(cx).and_then(notice_text);
    let pending = head.state == "pending";
    let stale = head.state == "stale";
    let list = format!("{}/edits", project_url(project));
    let (name, slug) = (line(project), slug(project));
    let raw_project = slug.clone();
    let id_text = id.to_string();
    Ok(view! {
        shell(title: "fleet edit review", active: Nav::Work, user: who.username.as_str(), csrf: who.csrf.as_str(), mode: "",
            project_head(name: name, slug: slug, active: "edits")
            <h2 class="mb-1 text-sm font-bold">"Edit " (head.id)</h2>
            if let Some(text) = notice {
                <p id="notice" class="mb-2 border border-base-300 bg-base-200 p-2 text-xs">(text)</p>
            }
            <p class="mb-2 text-xs break-all">
                <span class=(edit_badge(head.state))>(head.state)</span>
                " " (head.kind)
                " target " (head.target.as_str())
                " filed by " (head.filed_by.as_str())
                " " (head.created.as_str())
            </p>
            <p class="mb-2 text-xs break-all">"base " (hash.as_str())</p>
            <section class="mb-3" aria-labelledby="edit-diff">
                <h3 id="edit-diff" class="mb-1 text-xs font-bold uppercase text-base-content/60">"Diff"</h3>
                <pre class="max-h-96 overflow-auto whitespace-pre text-xs" data-diff="">(diff.as_str())</pre>
                if cut {
                    <p class="text-xs text-base-content/60" data-diff-truncated="">"[diff truncated]"</p>
                }
            </section>
            if pending || stale {
                <form class="flex gap-2" method="post" action="/edits/decide">
                    <input type="hidden" name="csrf" value=(who.csrf.as_str())>
                    <input type="hidden" name="project" value=(raw_project.as_str())>
                    <input type="hidden" name="id" value=(id_text.as_str())>
                    if stale {
                        <button class="btn btn-sm btn-success" type="submit" name="decision" value="accept" data-action="accept" disabled="">"Accept"</button>
                    } else {
                        <button class="btn btn-sm btn-success" type="submit" name="decision" value="accept" data-action="accept">"Accept"</button>
                    }
                    <button class="btn btn-sm btn-outline btn-error" type="submit" name="decision" value="reject" data-action="reject">"Reject"</button>
                </form>
            }
            <p class="mt-3 text-xs"><a class="link" href=(list.as_str())>"All edits"</a></p>
        )
    })
}

fn back(project: &str, id: u64, code: &str) -> SeeOther {
    see_other(format!("{}?notice={code}", edit_url(project, id)))
}

#[route(POST "/edits/decide")]
async fn decide(cx: &Cx, Form(form): Form<HashMap<String, String>>) -> Result<SeeOther> {
    let store = app_context::<ConsoleSlot>(cx)
        .0
        .as_deref()
        .ok_or_else(not_found)?;
    let session = signed_in(cx, auth(cx)?).await?;
    if !csrf_matches(&session, form.get("csrf").map(String::as_str)) {
        return Err(forbidden().into());
    }
    let project = checked(form.get("project").map_or("", String::as_str))?;
    let id = row_id(form.get("id").map_or("", String::as_str))?;
    let decision = match form.get("decision").map(String::as_str) {
        Some("accept") => EditDecision::Accept,
        Some("reject") => EditDecision::Reject,
        _ => return Err(bad_request("the decision is unknown").into()),
    };
    let request = DecideEditRequest {
        key: EventId::generate().to_string(),
        project: project.to_owned(),
        id,
        decision: decision.into(),
    };
    match store.decide_edit(session.user_id, &request).await {
        Ok(_) => Err(back(
            project,
            id,
            if decision == EditDecision::Accept {
                "accepted"
            } else {
                "rejected"
            },
        )
        .into()),
        Err(StoreError::Work(WorkFault::NotInteractive)) => {
            Err(back(project, id, "not_interactive").into())
        }
        Err(StoreError::Work(WorkFault::Precondition(reason))) => {
            let code = match reason {
                REASON_STALE => "stale",
                REASON_DECIDED => "decided",
                REASON_DOES_NOT_APPLY => "does_not_apply",
                _ => return Err(internal(&reason)),
            };
            Err(back(project, id, code).into())
        }
        Err(err) => Err(read_error(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_id_takes_digits_from_one_to_i64_max_only() {
        for good in ["1", "42", "9223372036854775807"] {
            assert!(row_id(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            "1 ",
            "abc",
            "9223372036854775808",
            "1\0",
            "01a",
        ] {
            assert!(row_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn capped_cuts_one_over_the_cap_and_keeps_an_exact_fit() {
        assert!(!capped(vec![0; ROW_CAP]).1);
        let (rows, cut) = capped(vec![0; ROW_CAP + 1]);
        assert!(cut);
        assert_eq!(rows.len(), ROW_CAP);
    }

    #[test]
    fn diff_text_cuts_at_the_line_and_byte_caps() {
        let exact = "+x\n".repeat(DIFF_LINES);
        assert!(!diff_text(&exact).1);
        let over = format!("{exact}+extra\n");
        let (text, cut) = diff_text(&over);
        assert!(cut);
        assert_eq!(text.lines().count(), DIFF_LINES);
        assert!(diff_text(&"z".repeat(DIFF_BYTES + 1)).1);
        assert!(!diff_text(&"z".repeat(DIFF_BYTES)).1);
    }

    #[test]
    fn diff_text_drops_hostile_characters_but_keeps_newline_and_tab() {
        let (text, _) = diff_text("a\r\nb\tc\u{85}\u{2028}\u{202e}\0d\n");
        assert_eq!(text, "a\nb\tcd\n");
    }
}

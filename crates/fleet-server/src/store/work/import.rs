//! Import of a `.ralph` directory into a Work project, and export back to the two graph files.
//!
//! An import takes `FOR UPDATE` on the project row before it reads anything, plans against the
//! committed graph, validates the merged graph with [`fleet_core::graph`] and writes in the same
//! transaction. Without `apply` the transaction ends in a rollback after the plan, so a dry-run
//! and a real import report the same counts.
//!
//! Re-import rules, all keyed on the item key:
//!
//! - A key the project lacks is created, with a `passes` attempt for a true `passes` and one
//!   `fail` attempt per `fails`.
//! - A key the project has keeps its stored title, body, slices and dependencies, because the
//!   server copy is the source of truth after the first import. A difference is counted and
//!   noted, never written.
//! - Attempt state only rises. A true `passes` on an item with no pass adds one, and a `fails`
//!   above the stored count adds the difference. A lower value in the file removes nothing.
//! - A slice or mergeable path the project lacks is added. A slice the project has keeps its
//!   paths.
//! - A `DEFER` line of `docs-backlog.md` becomes a defer in the vertical `ralph` unless one with
//!   the same title and reason exists. Every other line of the two text files is returned as
//!   unparsed, cut to [`MAX_REPORT_LINE_CHARS`] after redaction, at most [`MAX_UNPARSED_REPORTED`]
//!   of them.

use std::collections::{BTreeSet, HashMap, HashSet};

use fleet_core::Redactor;
use fleet_core::graph::Node;
use fleet_core::text::{Cap, sanitise_text};
use fleet_proto::v1::{
    ExportWorkReply, ExportWorkRequest, ImportWorkReply, ImportWorkRequest, WorkItem, WorkItemState,
};
use fleet_proto::{
    MAX_EXPORT_TASKS_BYTES, MAX_IMPORT_SLICES_BYTES, MAX_IMPORT_TASKS_BYTES, MAX_IMPORT_TEXT_BYTES,
};
use sqlx::{PgConnection, Postgres, Transaction};

use super::defer::insert_defer;
use super::load::{Snapshot, load_slices};
use super::ralph::{self, DeferLine, Parsed, SliceDef, Task};
use super::write::{check, replace_slices};
use super::{
    MAX_REASON_CHARS, MAX_TITLE_CHARS, WorkFault, actor, find_project, insert_event, lock_project,
};
use crate::store::{Store, StoreError};

/// Most notes an import reply carries.
pub(super) const MAX_NOTES: usize = 50;
/// Most unparsed lines an import reply carries. The rest are counted.
pub(super) const MAX_UNPARSED_REPORTED: usize = 100;
/// Longest unparsed or note line in a reply, in characters.
pub(super) const MAX_REPORT_LINE_CHARS: usize = 200;
/// Vertical every imported defer carries.
pub(super) const IMPORT_VERTICAL: &str = "ralph";

const INSERT_ITEM: &str = "\
INSERT INTO work_item (project_id, key, title, body, state) VALUES ($1, $2, $3, $4, $5) \
RETURNING id";
const INSERT_MEMBERS: &str = "\
INSERT INTO work_item_slice (project_id, item_id, slice_id) \
SELECT $1, $2, s.id FROM work_slice s WHERE s.project_id = $1 AND s.name = ANY($3)";
const INSERT_DEP: &str = "\
INSERT INTO work_dep (project_id, item_id, depends_on_id, why) \
SELECT $1, $2, i.id, $4 FROM work_item i WHERE i.project_id = $1 AND i.key = $3";
const INSERT_ATTEMPTS: &str = "\
INSERT INTO work_attempt (project_id, item_id, holder, expires_at, verdict, closed_at, note) \
SELECT $1, $2, 'import', now(), $3, now(), 'imported from .ralph' \
FROM generate_series(1, $4::int)";
const SET_ROLE: &str = "UPDATE work_slice SET role = $3 WHERE project_id = $1 AND name = $2";
const INSERT_MERGEABLE: &str = "\
INSERT INTO work_mergeable_path (project_id, path) SELECT $1, unnest($2::text[]) \
ON CONFLICT DO NOTHING";
const EXISTING_DEFERS: &str = "\
SELECT title, reason FROM work_defer \
WHERE project_id = $1 AND vertical = $2 AND title = ANY($3)";
const ROLES: &str = "SELECT name, role FROM work_slice WHERE project_id = $1";

#[derive(Default)]
struct Plan<'a> {
    create: Vec<&'a Task>,
    raise: Vec<(i64, bool, u32)>,
    new_slices: Vec<&'a SliceDef>,
    new_mergeable: Vec<String>,
    unchanged: u32,
    differing: u32,
    notes: Vec<String>,
}

fn count(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

fn same_content(view: &WorkItem, task: &Task) -> bool {
    let acceptance = &task.acceptance;
    let mut slices = task.slices.clone();
    slices.sort();
    let mut depends: Vec<&str> = task.depends.iter().map(String::as_str).collect();
    depends.sort_unstable();
    view.title == task.title
        && view.body == *acceptance
        && view.slices == slices
        && view.deps.len() == depends.len()
        && view
            .deps
            .iter()
            .zip(depends)
            .all(|(dep, key)| dep.depends_on == key && dep.why == task.why)
}

fn plan<'a>(snapshot: &Snapshot, parsed: &'a Parsed) -> Result<Plan<'a>, StoreError> {
    let views: HashMap<String, WorkItem> = snapshot
        .views()?
        .into_iter()
        .map(|view| (view.key.clone(), view))
        .collect();
    let mut plan = Plan::default();
    for task in &parsed.tasks {
        let Some(view) = views.get(&task.id) else {
            plan.create.push(task);
            continue;
        };
        let item_id = snapshot.item(&task.id)?.id;
        let add_pass = task.passes && view.passes == 0;
        let add_fails = task.fails.saturating_sub(view.fails);
        let differs = !same_content(view, task);
        if add_pass || add_fails > 0 {
            plan.raise.push((item_id, add_pass, add_fails));
        }
        if differs {
            plan.differing += 1;
            plan.notes.push(format!(
                "{}: differs from the file, server copy kept",
                task.id
            ));
        }
        if !differs && !add_pass && add_fails == 0 {
            plan.unchanged += 1;
        }
    }
    for slice in &parsed.slices {
        match snapshot.slices.get(&slice.name) {
            None => plan.new_slices.push(slice),
            Some(paths) if *paths != slice.paths => plan.notes.push(format!(
                "slice {}: differs from the file, server copy kept",
                slice.name
            )),
            Some(_) => {}
        }
    }
    plan.new_mergeable = parsed
        .mergeable
        .iter()
        .filter(|path| !snapshot.mergeable.contains(path))
        .cloned()
        .collect();
    let mut proposed = snapshot.graph();
    for slice in &plan.new_slices {
        proposed
            .slices
            .insert(slice.name.clone(), slice.paths.clone());
    }
    proposed
        .mergeable
        .extend(plan.new_mergeable.iter().cloned());
    for task in &plan.create {
        proposed.nodes.push(Node {
            id: task.id.clone(),
            depends: task.depends.clone(),
            why: "edge".to_owned(),
            slices: Some(task.slices.clone()),
            done: false,
        });
    }
    check(&proposed)?;
    Ok(plan)
}

async fn write_items(
    tx: &mut Transaction<'static, Postgres>,
    project_id: i64,
    user_id: i64,
    plan: &Plan<'_>,
    ids: &mut HashMap<String, i64>,
) -> Result<(), StoreError> {
    for task in &plan.create {
        let state = if task.blocked { "blocked" } else { "open" };
        let item_id: i64 = sqlx::query_scalar(INSERT_ITEM)
            .bind(project_id)
            .bind(&task.id)
            .bind(&task.title)
            .bind(&task.acceptance)
            .bind(state)
            .fetch_one(&mut **tx)
            .await?;
        sqlx::query(INSERT_MEMBERS)
            .bind(project_id)
            .bind(item_id)
            .bind(&task.slices)
            .execute(&mut **tx)
            .await?;
        insert_event(
            tx,
            project_id,
            Some(item_id),
            None,
            "imported",
            &actor(user_id),
            "item imported",
        )
        .await?;
        add_attempts(tx, project_id, item_id, task.passes, task.fails).await?;
        ids.insert(task.id.clone(), item_id);
    }
    for task in &plan.create {
        let Some(&item_id) = ids.get(&task.id) else {
            continue;
        };
        for dep in &task.depends {
            sqlx::query(INSERT_DEP)
                .bind(project_id)
                .bind(item_id)
                .bind(dep)
                .bind(&task.why)
                .execute(&mut **tx)
                .await?;
        }
    }
    for &(item_id, pass, fails) in &plan.raise {
        add_attempts(tx, project_id, item_id, pass, fails).await?;
        insert_event(
            tx,
            project_id,
            Some(item_id),
            None,
            "imported",
            &actor(user_id),
            "attempts raised",
        )
        .await?;
    }
    Ok(())
}

async fn add_attempts(
    tx: &mut Transaction<'static, Postgres>,
    project_id: i64,
    item_id: i64,
    pass: bool,
    fails: u32,
) -> Result<(), StoreError> {
    for (verdict, n) in [
        ("pass", i32::from(pass)),
        ("fail", i32::try_from(fails).unwrap_or(i32::MAX)),
    ] {
        if n > 0 {
            sqlx::query(INSERT_ATTEMPTS)
                .bind(project_id)
                .bind(item_id)
                .bind(verdict)
                .bind(n)
                .execute(&mut **tx)
                .await?;
        }
    }
    Ok(())
}

async fn write_slices(
    tx: &mut Transaction<'static, Postgres>,
    project_id: i64,
    snapshot: &Snapshot,
    plan: &Plan<'_>,
) -> Result<(), StoreError> {
    if !plan.new_slices.is_empty() {
        let mut wanted: Vec<(String, BTreeSet<String>)> = snapshot
            .slices
            .iter()
            .map(|(name, paths)| (name.clone(), paths.iter().cloned().collect()))
            .collect();
        for slice in &plan.new_slices {
            wanted.push((slice.name.clone(), slice.paths.iter().cloned().collect()));
        }
        replace_slices(tx, project_id, snapshot, &wanted).await?;
        for slice in &plan.new_slices {
            sqlx::query(SET_ROLE)
                .bind(project_id)
                .bind(&slice.name)
                .bind(&slice.role)
                .execute(&mut **tx)
                .await?;
        }
    }
    if !plan.new_mergeable.is_empty() {
        sqlx::query(INSERT_MERGEABLE)
            .bind(project_id)
            .bind(&plan.new_mergeable)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

struct Defer {
    item: String,
    title: String,
    reason: String,
}

fn defer_texts(redactor: &Redactor, line: &DeferLine) -> Option<Defer> {
    let title = sanitise_text(redactor, &line.text, Cap::Chars(MAX_TITLE_CHARS)).text;
    let reason = sanitise_text(redactor, &line.text, Cap::Chars(MAX_REASON_CHARS)).text;
    (!title.trim().is_empty()).then(|| Defer {
        item: line.item.clone(),
        title: title.trim().to_owned(),
        reason,
    })
}

async fn new_defers(
    conn: &mut PgConnection,
    project_id: i64,
    candidates: Vec<Defer>,
) -> Result<Vec<Defer>, StoreError> {
    let titles: Vec<String> = candidates.iter().map(|d| d.title.clone()).collect();
    let rows: Vec<(String, String)> = sqlx::query_as(EXISTING_DEFERS)
        .bind(project_id)
        .bind(IMPORT_VERTICAL)
        .bind(&titles)
        .fetch_all(&mut *conn)
        .await?;
    let mut seen: HashSet<(String, String)> = rows.into_iter().collect();
    Ok(candidates
        .into_iter()
        .filter(|d| seen.insert((d.title.clone(), d.reason.clone())))
        .collect())
}

fn report_line(redactor: &Redactor, text: &str) -> String {
    sanitise_text(redactor, text, Cap::Chars(MAX_REPORT_LINE_CHARS)).text
}

fn check_sizes(request: &ImportWorkRequest) -> Result<(), WorkFault> {
    if request.tasks_json.len() > MAX_IMPORT_TASKS_BYTES
        || request.slices_json.len() > MAX_IMPORT_SLICES_BYTES
        || request.progress_md.len() > MAX_IMPORT_TEXT_BYTES
        || request.backlog_md.len() > MAX_IMPORT_TEXT_BYTES
    {
        return Err(WorkFault::Invalid("import file is too large"));
    }
    Ok(())
}

impl Store {
    /// Imports a `.ralph` directory into the project, or reports what it would do.
    ///
    /// The project row is locked before any read. Without `request.apply` nothing is written.
    /// The re-import rules are in the module docs.
    ///
    /// # Errors
    ///
    /// [`WorkFault::Invalid`] or [`WorkFault::Graph`] for a file that breaks a rule or an import
    /// whose merged graph is invalid, and [`WorkFault::ProjectNotFound`] for an unknown project.
    pub async fn import_work(
        &self,
        user_id: i64,
        request: &ImportWorkRequest,
        redactor: &Redactor,
    ) -> Result<ImportWorkReply, StoreError> {
        check_sizes(request)?;
        let parsed = ralph::parse(&request.tasks_json, &request.slices_json)?;
        let text = ralph::split_lines(&request.progress_md, &request.backlog_md)?;
        let mut tx = self.pool.begin().await?;
        let project_id = lock_project(&mut tx, user_id, &request.project).await?;
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let plan = plan(&snapshot, &parsed)?;
        let mut unparsed: Vec<String> = Vec::new();
        let mut candidates = Vec::new();
        for line in &text.defers {
            match defer_texts(redactor, line) {
                Some(defer) => candidates.push(defer),
                None => unparsed.push(format!("docs-backlog.md:{}: {}", line.number, line.text)),
            }
        }
        let defers = new_defers(&mut tx, project_id, candidates).await?;
        if request.apply {
            let mut ids: HashMap<String, i64> = snapshot
                .items
                .iter()
                .map(|item| (item.key.clone(), item.id))
                .collect();
            write_slices(&mut tx, project_id, &snapshot, &plan).await?;
            write_items(&mut tx, project_id, user_id, &plan, &mut ids).await?;
            for defer in &defers {
                let item = ids.get(&defer.item).copied();
                insert_defer(
                    &mut tx,
                    project_id,
                    item,
                    None,
                    (&defer.title, &defer.reason, IMPORT_VERTICAL),
                )
                .await?;
            }
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        unparsed.extend(
            text.unparsed
                .iter()
                .map(|(file, number, raw)| format!("{file}:{number}: {raw}")),
        );
        let dropped = unparsed.len().saturating_sub(MAX_UNPARSED_REPORTED);
        let mut notes: Vec<String> = parsed.notes.iter().chain(&plan.notes).cloned().collect();
        let more_notes = notes.len().saturating_sub(MAX_NOTES);
        notes.truncate(MAX_NOTES);
        if more_notes > 0 {
            notes.push(format!("{more_notes} more notes dropped"));
        }
        Ok(ImportWorkReply {
            applied: request.apply,
            items_created: count(plan.create.len()),
            items_unchanged: plan.unchanged,
            items_raised: count(plan.raise.len()),
            items_differing: plan.differing,
            slices_created: count(plan.new_slices.len()),
            mergeable_created: count(plan.new_mergeable.len()),
            defers_created: count(defers.len()),
            notes: notes.iter().map(|n| report_line(redactor, n)).collect(),
            unparsed: unparsed
                .iter()
                .take(MAX_UNPARSED_REPORTED)
                .map(|n| report_line(redactor, n))
                .collect(),
            unparsed_dropped: count(dropped),
        })
    }

    /// Renders the project as `tasks.json` and `slices.json` text from one consistent read.
    ///
    /// A task depending on several items repeats the `why` of its first dependency, a blocked or
    /// cancelled item is written `blocked`, and a task with a pass attempt has `passes` true.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] for an unknown project and [`WorkFault::Precondition`]
    /// when `tasks_json` would pass `MAX_EXPORT_TASKS_BYTES`.
    pub async fn export_work(
        &self,
        user_id: i64,
        request: &ExportWorkRequest,
    ) -> Result<ExportWorkReply, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let (slices, mergeable) = load_slices(&mut tx, project_id).await?;
        let roles: HashMap<String, String> = sqlx::query_as(ROLES)
            .bind(project_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
        tx.rollback().await?;
        let tasks: Vec<Task> = snapshot
            .views()?
            .into_iter()
            .map(|view| Task {
                id: view.key,
                title: view.title,
                acceptance: view.body,
                slices: view.slices,
                depends: view.deps.iter().map(|d| d.depends_on.clone()).collect(),
                why: view.deps.first().map(|d| d.why.clone()).unwrap_or_default(),
                passes: view.passes > 0,
                fails: view.fails,
                blocked: view.state != WorkItemState::Open as i32,
            })
            .collect();
        let defs: Vec<SliceDef> = slices
            .into_iter()
            .map(|(name, paths)| SliceDef {
                role: roles.get(&name).cloned().unwrap_or_default(),
                name,
                paths,
            })
            .collect();
        let (tasks_json, slices_json) = ralph::render(&tasks, &defs, &mergeable)?;
        if tasks_json.len() > MAX_EXPORT_TASKS_BYTES {
            return Err(WorkFault::Precondition("export is too large").into());
        }
        Ok(ExportWorkReply {
            tasks_json,
            slices_json,
        })
    }
}

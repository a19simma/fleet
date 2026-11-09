//! Reads of the work graph: the snapshot a write checks, the item views and the read RPCs.

use std::collections::{BTreeMap, HashMap, HashSet};

use fleet_core::graph::{self, Graph, Node};
use fleet_proto::v1::{
    GetWorkItemReply, GetWorkItemRequest, ListWorkItemsReply, ListWorkItemsRequest,
    ListWorkProjectsReply, WorkAttempt, WorkDep, WorkEvent, WorkItem, WorkItemState, WorkProject,
    WorkSlice, WorkVerdict,
};
use sqlx::{PgConnection, Row};

use super::{
    MAX_DETAIL_ROWS, MAX_LIST_PROJECTS, WorkFault, find_project, item_key, project_name, unsigned,
};
use crate::store::{Store, StoreError};

const PROJECTS: &str = "\
SELECT p.id, p.name, (extract(epoch FROM p.created_at) * 1000)::bigint AS created_ms, \
r.host || '/' || r.path AS repo \
FROM work_project p LEFT JOIN user_repos r ON r.id = p.repo_id \
WHERE p.user_id = $1 ORDER BY p.name LIMIT $2";

const ITEMS: &str = "\
SELECT id, key, title, body, state, \
(extract(epoch FROM created_at) * 1000)::bigint AS created_ms, \
(extract(epoch FROM updated_at) * 1000)::bigint AS updated_ms \
FROM work_item WHERE project_id = $1 ORDER BY id";

const SLICES: &str = "\
SELECT s.name, p.path FROM work_slice s LEFT JOIN work_slice_path p ON p.slice_id = s.id \
WHERE s.project_id = $1 ORDER BY s.name, p.path";

const MERGEABLE: &str = "SELECT path FROM work_mergeable_path WHERE project_id = $1 ORDER BY path";

const MEMBERS: &str = "\
SELECT m.item_id, s.name FROM work_item_slice m \
JOIN work_slice s ON s.id = m.slice_id AND s.project_id = m.project_id \
WHERE m.project_id = $1 ORDER BY s.name";

const DEPS: &str = "\
SELECT item_id, depends_on_id, why FROM work_dep WHERE project_id = $1 \
ORDER BY item_id, depends_on_id";

const COUNTS: &str = "\
SELECT item_id, count(*) FILTER (WHERE verdict = 'pass') AS passes, \
count(*) FILTER (WHERE verdict = 'fail') AS fails, bool_or(verdict IS NULL) AS held \
FROM work_attempt WHERE project_id = $1 GROUP BY item_id";

const ATTEMPTS: &str = "\
SELECT id, holder, verdict, note, evidence, \
(extract(epoch FROM claimed_at) * 1000)::bigint AS claimed_ms, \
(extract(epoch FROM expires_at) * 1000)::bigint AS expires_ms, \
(extract(epoch FROM closed_at) * 1000)::bigint AS closed_ms \
FROM (SELECT * FROM work_attempt WHERE project_id = $1 AND item_id = $2 \
ORDER BY id DESC LIMIT $3) latest ORDER BY id";

const EVENTS: &str = "\
SELECT id, attempt_id, kind, actor, note, (extract(epoch FROM at) * 1000)::bigint AS at_ms \
FROM (SELECT * FROM work_event WHERE project_id = $1 AND item_id = $2 \
ORDER BY id DESC LIMIT $3) latest ORDER BY id";

pub(super) struct ItemRow {
    pub(super) id: i64,
    pub(super) key: String,
    title: String,
    body: String,
    pub(super) state: String,
    created_ms: i64,
    updated_ms: i64,
}

pub(super) struct DepRow {
    pub(super) item_id: i64,
    pub(super) depends_on_id: i64,
    pub(super) why: String,
}

/// The graph of one project as of one read.
pub(super) struct Snapshot {
    pub(super) items: Vec<ItemRow>,
    pub(super) slices: BTreeMap<String, Vec<String>>,
    pub(super) mergeable: Vec<String>,
    members: HashMap<i64, Vec<String>>,
    pub(super) deps: Vec<DepRow>,
    counts: HashMap<i64, (i64, i64, bool)>,
}

impl Snapshot {
    pub(super) async fn load(conn: &mut PgConnection, project_id: i64) -> Result<Self, StoreError> {
        let mut items = Vec::new();
        for row in sqlx::query(ITEMS)
            .bind(project_id)
            .fetch_all(&mut *conn)
            .await?
        {
            items.push(ItemRow {
                id: row.try_get("id")?,
                key: row.try_get("key")?,
                title: row.try_get("title")?,
                body: row.try_get("body")?,
                state: row.try_get("state")?,
                created_ms: row.try_get("created_ms")?,
                updated_ms: row.try_get("updated_ms")?,
            });
        }
        let (slices, mergeable) = load_slices(conn, project_id).await?;
        let mut members: HashMap<i64, Vec<String>> = HashMap::new();
        for row in sqlx::query(MEMBERS)
            .bind(project_id)
            .fetch_all(&mut *conn)
            .await?
        {
            members
                .entry(row.try_get("item_id")?)
                .or_default()
                .push(row.try_get("name")?);
        }
        let mut deps = Vec::new();
        for row in sqlx::query(DEPS)
            .bind(project_id)
            .fetch_all(&mut *conn)
            .await?
        {
            deps.push(DepRow {
                item_id: row.try_get("item_id")?,
                depends_on_id: row.try_get("depends_on_id")?,
                why: row.try_get("why")?,
            });
        }
        let mut counts = HashMap::new();
        for row in sqlx::query(COUNTS)
            .bind(project_id)
            .fetch_all(&mut *conn)
            .await?
        {
            counts.insert(
                row.try_get("item_id")?,
                (
                    row.try_get("passes")?,
                    row.try_get("fails")?,
                    row.try_get("held")?,
                ),
            );
        }
        Ok(Self {
            items,
            slices,
            mergeable,
            members,
            deps,
            counts,
        })
    }

    pub(super) fn item(&self, key: &str) -> Result<&ItemRow, WorkFault> {
        self.items
            .iter()
            .find(|item| item.key == key)
            .ok_or(WorkFault::ItemNotFound)
    }

    fn key_of(&self, id: i64) -> Option<&str> {
        self.items
            .iter()
            .find(|item| item.id == id)
            .map(|item| item.key.as_str())
    }

    pub(super) fn counts_of(&self, id: i64) -> (i64, i64, bool) {
        self.counts.get(&id).copied().unwrap_or((0, 0, false))
    }

    /// The graph as stored. An item with no slice owns none.
    pub(super) fn graph(&self) -> Graph {
        let nodes = self
            .items
            .iter()
            .map(|item| Node {
                id: item.key.clone(),
                depends: self
                    .deps
                    .iter()
                    .filter(|dep| dep.item_id == item.id)
                    .filter_map(|dep| self.key_of(dep.depends_on_id).map(str::to_owned))
                    .collect(),
                why: "edge".to_owned(),
                slices: Some(self.members.get(&item.id).cloned().unwrap_or_default()),
                done: self.counts_of(item.id).0 > 0,
            })
            .collect();
        Graph {
            nodes,
            slices: self.slices.clone(),
            mergeable: self.mergeable.clone(),
        }
    }

    pub(super) fn is_ready(&self, key: &str) -> bool {
        self.ready_keys().contains(key)
    }

    fn ready_keys(&self) -> HashSet<String> {
        let graph = self.graph();
        let held: Vec<&str> = self
            .items
            .iter()
            .filter(|item| self.counts_of(item.id).2)
            .map(|item| item.key.as_str())
            .collect();
        let states: HashMap<&str, &str> = self
            .items
            .iter()
            .map(|item| (item.key.as_str(), item.state.as_str()))
            .collect();
        graph::ready(&graph, &held)
            .into_iter()
            .filter(|key| states.get(key) == Some(&"open"))
            .map(str::to_owned)
            .collect()
    }

    pub(super) fn views(&self) -> Result<Vec<WorkItem>, StoreError> {
        let ready = self.ready_keys();
        self.items
            .iter()
            .map(|item| self.view(item, ready.contains(&item.key)))
            .collect()
    }

    pub(super) fn view_of(&self, key: &str) -> Result<WorkItem, StoreError> {
        let item = self.item(key)?;
        self.view(item, self.ready_keys().contains(key))
    }

    fn view(&self, item: &ItemRow, ready: bool) -> Result<WorkItem, StoreError> {
        let (passes, fails, held) = self.counts_of(item.id);
        let mut deps: Vec<WorkDep> = self
            .deps
            .iter()
            .filter(|dep| dep.item_id == item.id)
            .filter_map(|dep| {
                self.key_of(dep.depends_on_id).map(|key| WorkDep {
                    depends_on: key.to_owned(),
                    why: dep.why.clone(),
                })
            })
            .collect();
        deps.sort_by(|a, b| a.depends_on.cmp(&b.depends_on));
        Ok(WorkItem {
            key: item.key.clone(),
            title: item.title.clone(),
            body: item.body.clone(),
            state: state_of(&item.state)? as i32,
            slices: self.members.get(&item.id).cloned().unwrap_or_default(),
            deps,
            passes: u32::try_from(passes).map_err(|_| StoreError::OutOfRange("work passes"))?,
            fails: u32::try_from(fails).map_err(|_| StoreError::OutOfRange("work fails"))?,
            ready,
            held,
            created_at_ms: unsigned(item.created_ms)?,
            updated_at_ms: unsigned(item.updated_ms)?,
        })
    }
}

fn state_of(text: &str) -> Result<WorkItemState, StoreError> {
    match text {
        "open" => Ok(WorkItemState::Open),
        "blocked" => Ok(WorkItemState::Blocked),
        "cancelled" => Ok(WorkItemState::Cancelled),
        _ => Err(StoreError::OutOfRange("work item state")),
    }
}

pub(super) fn verdict_of(text: &str) -> Result<WorkVerdict, StoreError> {
    match text {
        "pass" => Ok(WorkVerdict::Pass),
        "fail" => Ok(WorkVerdict::Fail),
        "lost" => Ok(WorkVerdict::Lost),
        _ => Err(StoreError::OutOfRange("work verdict")),
    }
}

async fn load_slices(
    conn: &mut PgConnection,
    project_id: i64,
) -> Result<(BTreeMap<String, Vec<String>>, Vec<String>), StoreError> {
    let mut slices: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in sqlx::query(SLICES)
        .bind(project_id)
        .fetch_all(&mut *conn)
        .await?
    {
        let paths = slices.entry(row.try_get("name")?).or_default();
        if let Some(path) = row.try_get::<Option<String>, _>("path")? {
            paths.push(path);
        }
    }
    let mergeable = sqlx::query_scalar(MERGEABLE)
        .bind(project_id)
        .fetch_all(&mut *conn)
        .await?;
    Ok((slices, mergeable))
}

pub(super) async fn project_view(
    conn: &mut PgConnection,
    project_id: i64,
    name: String,
    repo: Option<String>,
    created_ms: i64,
) -> Result<WorkProject, StoreError> {
    let (slices, mergeable) = load_slices(conn, project_id).await?;
    Ok(WorkProject {
        name,
        repo,
        slices: slices
            .into_iter()
            .map(|(name, paths)| WorkSlice { name, paths })
            .collect(),
        mergeable,
        created_at_ms: unsigned(created_ms)?,
    })
}

impl Store {
    /// Lists the projects of `user_id` by name, at most 1000.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] when a query fails.
    pub async fn list_work_projects(
        &self,
        user_id: i64,
    ) -> Result<ListWorkProjectsReply, StoreError> {
        let mut tx = self.begin_read().await?;
        let rows = sqlx::query(PROJECTS)
            .bind(user_id)
            .bind(MAX_LIST_PROJECTS)
            .fetch_all(&mut *tx)
            .await?;
        let mut projects = Vec::with_capacity(rows.len());
        for row in rows {
            projects.push(
                project_view(
                    &mut tx,
                    row.try_get("id")?,
                    row.try_get("name")?,
                    row.try_get("repo")?,
                    row.try_get("created_ms")?,
                )
                .await?,
            );
        }
        Ok(ListWorkProjectsReply { projects })
    }

    /// Lists the items of a project of `user_id` with their computed `ready` flag.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] for an unknown or foreign project and
    /// [`WorkFault::Invalid`] for an unspecified or unknown state filter.
    pub async fn list_work_items(
        &self,
        user_id: i64,
        request: &ListWorkItemsRequest,
    ) -> Result<ListWorkItemsReply, StoreError> {
        let wanted = match request.state {
            None => None,
            Some(raw) => match WorkItemState::try_from(raw) {
                Ok(WorkItemState::Unspecified) | Err(_) => {
                    return Err(WorkFault::Invalid("invalid state filter").into());
                }
                Ok(state) => Some(state as i32),
            },
        };
        let mut tx = self.begin_read().await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let items = snapshot
            .views()?
            .into_iter()
            .filter(|item| wanted.is_none_or(|state| item.state == state))
            .filter(|item| !request.ready_only || item.ready)
            .collect();
        Ok(ListWorkItemsReply { items })
    }

    /// Reads one item with its latest 200 attempts and 200 events.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] or [`WorkFault::ItemNotFound`].
    pub async fn get_work_item(
        &self,
        user_id: i64,
        request: &GetWorkItemRequest,
    ) -> Result<GetWorkItemReply, StoreError> {
        item_key(&request.item_key)?;
        project_name(&request.project)?;
        let mut tx = self.begin_read().await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let item = snapshot.item(&request.item_key)?;
        let view = snapshot.view_of(&request.item_key)?;
        let mut attempts = Vec::new();
        for row in sqlx::query(ATTEMPTS)
            .bind(project_id)
            .bind(item.id)
            .bind(MAX_DETAIL_ROWS)
            .fetch_all(&mut *tx)
            .await?
        {
            let verdict: Option<String> = row.try_get("verdict")?;
            let closed: Option<i64> = row.try_get("closed_ms")?;
            attempts.push(WorkAttempt {
                id: unsigned(row.try_get("id")?)?,
                item_key: item.key.clone(),
                holder: row.try_get("holder")?,
                claimed_at_ms: unsigned(row.try_get("claimed_ms")?)?,
                expires_at_ms: unsigned(row.try_get("expires_ms")?)?,
                verdict: verdict
                    .as_deref()
                    .map(verdict_of)
                    .transpose()?
                    .map(|v| v as i32),
                note: row
                    .try_get::<Option<String>, _>("note")?
                    .unwrap_or_default(),
                evidence_tail: row
                    .try_get::<Option<String>, _>("evidence")?
                    .unwrap_or_default(),
                closed_at_ms: closed.map(unsigned).transpose()?,
            });
        }
        let mut events = Vec::new();
        for row in sqlx::query(EVENTS)
            .bind(project_id)
            .bind(item.id)
            .bind(MAX_DETAIL_ROWS)
            .fetch_all(&mut *tx)
            .await?
        {
            let attempt: Option<i64> = row.try_get("attempt_id")?;
            events.push(WorkEvent {
                id: unsigned(row.try_get("id")?)?,
                item_key: Some(item.key.clone()),
                attempt_id: attempt.map(unsigned).transpose()?,
                kind: row.try_get("kind")?,
                actor: row.try_get("actor")?,
                note: row.try_get("note")?,
                at_ms: unsigned(row.try_get("at_ms")?)?,
            });
        }
        Ok(GetWorkItemReply {
            item: Some(view),
            attempts,
            events,
        })
    }
}

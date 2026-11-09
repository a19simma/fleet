//! Writes of the work graph. Each takes the project row lock before it reads the graph.

use std::collections::BTreeSet;

use fleet_core::graph::{
    GraphError, MAX_DEPENDS, MAX_MERGEABLE, MAX_NODE_SLICES, MAX_SLICES, Node, RepoPath, validate,
};
use fleet_core::repo::RepoRef;
use fleet_proto::v1::{
    AddWorkDepRequest, AddWorkItemRequest, CancelWorkRequest, CreateWorkProjectRequest,
    RemoveWorkDepRequest, SetWorkSlicesRequest, UnblockWorkRequest, WorkItem, WorkProject,
};
use sqlx::{Postgres, Row, Transaction};
use tonic_prost::prost::Message;

use super::load::{Snapshot, project_view};
use super::{
    MAX_BODY_BYTES, MAX_REASON_BYTES, MAX_TITLE_CHARS, MAX_WHY_CHARS, WorkFault, actor, client_key,
    digest, ident, insert_event, item_key, line, lines, lock_project, project_name, remember,
    replay,
};
use crate::store::{Store, StoreError};

const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE";

const FIND_CREATE_KEY: &str = "\
SELECT k.request_digest, k.response FROM work_request_key k \
JOIN work_project p ON p.id = k.project_id \
WHERE p.user_id = $1 AND k.key = $2 AND k.rpc = 'CreateWorkProject'";

const NAME_TAKEN: &str = "SELECT 1 FROM work_project WHERE user_id = $1 AND name = $2";

const FIND_REPO: &str = "SELECT id FROM user_repos WHERE user_id = $1 AND host = $2 AND path = $3";

const INSERT_PROJECT: &str = "\
INSERT INTO work_project (user_id, name, repo_id) VALUES ($1, $2, $3) \
RETURNING id, (extract(epoch FROM created_at) * 1000)::bigint AS created_ms";

const PROJECT_ROW: &str = "\
SELECT p.name, (extract(epoch FROM p.created_at) * 1000)::bigint AS created_ms, \
r.host || '/' || r.path AS repo \
FROM work_project p LEFT JOIN user_repos r ON r.id = p.repo_id WHERE p.id = $1";

const LEASED_SLICES: &str = "\
SELECT s.name FROM work_slice_lease l \
JOIN work_slice s ON s.id = l.slice_id AND s.project_id = l.project_id \
WHERE l.project_id = $1";

const DELETE_SLICES: &str = "DELETE FROM work_slice WHERE project_id = $1 AND name <> ALL($2)";
const SLICE_ID: &str = "SELECT id FROM work_slice WHERE project_id = $1 AND name = $2";
const INSERT_SLICE: &str = "INSERT INTO work_slice (project_id, name) VALUES ($1, $2) RETURNING id";
const DELETE_SLICE_PATHS: &str = "DELETE FROM work_slice_path WHERE slice_id = $1";
const INSERT_SLICE_PATHS: &str =
    "INSERT INTO work_slice_path (slice_id, path) SELECT $1, unnest($2::text[])";
const DELETE_MERGEABLE: &str = "DELETE FROM work_mergeable_path WHERE project_id = $1";
const INSERT_MERGEABLE: &str =
    "INSERT INTO work_mergeable_path (project_id, path) SELECT $1, unnest($2::text[])";

const INSERT_ITEM: &str = "\
INSERT INTO work_item (project_id, key, title, body) VALUES ($1, $2, $3, $4) RETURNING id";
const INSERT_MEMBERS: &str = "\
INSERT INTO work_item_slice (project_id, item_id, slice_id) \
SELECT $1, $2, s.id FROM work_slice s WHERE s.project_id = $1 AND s.name = ANY($3)";
const INSERT_DEP: &str = "\
INSERT INTO work_dep (project_id, item_id, depends_on_id, why) \
SELECT $1, $2, i.id, $4 FROM work_item i WHERE i.project_id = $1 AND i.key = $3";
const DELETE_DEP: &str = "\
DELETE FROM work_dep WHERE project_id = $1 AND item_id = $2 AND depends_on_id = $3";
const TOUCH_ITEM: &str = "\
UPDATE work_item SET updated_at = now() WHERE id = $2 AND project_id = $1";
const SET_STATE: &str = "\
UPDATE work_item SET state = $3, updated_at = now() WHERE id = $2 AND project_id = $1";

const FREE_LEASES: &str = "\
DELETE FROM work_slice_lease WHERE project_id = $1 AND attempt_id IN (\
SELECT id FROM work_attempt WHERE project_id = $1 AND item_id = $2 AND verdict IS NULL)";
const CLOSE_ATTEMPTS: &str = "\
UPDATE work_attempt SET verdict = 'lost', closed_at = now(), note = $3 \
WHERE project_id = $1 AND item_id = $2 AND verdict IS NULL RETURNING id";

pub(super) enum Started<R> {
    Replayed(R),
    Fresh(Transaction<'static, Postgres>, i64),
}

pub(super) fn keyless<M: Clone>(request: &M, clear: impl FnOnce(&mut M)) -> M {
    let mut copy = request.clone();
    clear(&mut copy);
    copy
}

pub(super) fn check(graph: &fleet_core::graph::Graph) -> Result<(), StoreError> {
    validate(graph).map_err(|errors| {
        let first = errors.into_iter().next().unwrap_or(GraphError::Truncated);
        StoreError::from(WorkFault::Graph(first))
    })
}

fn unique<'a>(names: impl Iterator<Item = &'a str>, what: &'static str) -> Result<(), WorkFault> {
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(WorkFault::Invalid(what));
        }
    }
    Ok(())
}

fn normalised(raw: &[String]) -> Result<BTreeSet<String>, WorkFault> {
    raw.iter()
        .map(|path| {
            RepoPath::new(path)
                .map(|p| p.as_str().to_owned())
                .map_err(|_| WorkFault::Invalid("invalid path"))
        })
        .collect()
}

impl Store {
    pub(super) async fn begin_graph_write<R: Message + Default>(
        &self,
        user_id: i64,
        project: &str,
        key: &str,
        rpc: &str,
        request_digest: &[u8],
    ) -> Result<Started<R>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let project_id = lock_project(&mut tx, user_id, project).await?;
        let replayed = replay(&mut tx, project_id, key, rpc, request_digest).await?;
        Ok(replayed.map_or_else(|| Started::Fresh(tx, project_id), Started::Replayed))
    }

    pub(super) async fn finish_graph_write<R: Message>(
        mut tx: Transaction<'static, Postgres>,
        project_id: i64,
        key: &str,
        rpc: &str,
        request_digest: &[u8],
        reply: &R,
    ) -> Result<(), StoreError> {
        remember(&mut tx, project_id, key, rpc, request_digest, reply).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Creates a project for `user_id`, or returns the project an earlier call with the same key
    /// and request created.
    ///
    /// The key is looked up over every project of the user, so a retry finds the project by key
    /// and a second name under the same key is [`StoreError::KeyConflict`].
    ///
    /// # Errors
    ///
    /// [`WorkFault::Invalid`] for a bad name or repository, [`WorkFault::Exists`] when the name
    /// is taken under another key and [`WorkFault::RepoNotRegistered`] when the repository is
    /// not in the registry of `user_id`.
    pub async fn create_work_project(
        &self,
        user_id: i64,
        request: &CreateWorkProjectRequest,
    ) -> Result<WorkProject, StoreError> {
        const RPC: &str = "CreateWorkProject";
        let key = client_key(&request.key)?;
        let name = project_name(&request.name)?;
        let located = match request.repo.as_deref() {
            None => None,
            Some(raw) => {
                Some(RepoRef::locate(raw).map_err(|_| WorkFault::Invalid("invalid repository"))?)
            }
        };
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let mut tx = self.pool.begin().await?;
        let user: Option<i64> = sqlx::query_scalar(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if user.is_none() {
            return Err(WorkFault::ProjectNotFound.into());
        }
        let earlier: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(FIND_CREATE_KEY)
            .bind(user_id)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some((stored_digest, response)) = earlier {
            if stored_digest != request_digest {
                return Err(StoreError::KeyConflict);
            }
            return WorkProject::decode(response.as_slice())
                .map_err(|_| StoreError::OutOfRange("work response"));
        }
        let taken = sqlx::query(NAME_TAKEN)
            .bind(user_id)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
        if taken.is_some() {
            return Err(WorkFault::Exists("work project name already used").into());
        }
        let repo_id: Option<i64> = match &located {
            None => None,
            Some((host, path)) => Some(
                sqlx::query_scalar(FIND_REPO)
                    .bind(user_id)
                    .bind(host)
                    .bind(path)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(WorkFault::RepoNotRegistered)?,
            ),
        };
        let row = sqlx::query(INSERT_PROJECT)
            .bind(user_id)
            .bind(name)
            .bind(repo_id)
            .fetch_one(&mut *tx)
            .await?;
        let project_id: i64 = row.try_get("id")?;
        insert_event(
            &mut tx,
            project_id,
            None,
            None,
            "created",
            &actor(user_id),
            "project created",
        )
        .await?;
        let repo = located.map(|(host, path)| format!("{host}/{path}"));
        let reply = project_view(
            &mut tx,
            project_id,
            name.to_owned(),
            repo,
            row.try_get("created_ms")?,
        )
        .await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Replaces the slice set and the mergeable set of a project.
    ///
    /// A slice keeps its row when its name stays. The new sets must pass
    /// [`fleet_core::graph::validate`] together with the stored items, so a slice an item still
    /// names cannot be dropped, and a leased slice keeps its paths.
    ///
    /// # Errors
    ///
    /// [`WorkFault::Graph`] for an overlap, a bad path, a missing slice or a bound,
    /// [`WorkFault::Precondition`] for a leased slice whose paths change.
    pub async fn set_work_slices(
        &self,
        user_id: i64,
        request: &SetWorkSlicesRequest,
    ) -> Result<WorkProject, StoreError> {
        const RPC: &str = "SetWorkSlices";
        let key = client_key(&request.key)?;
        if request.slices.len() > MAX_SLICES || request.mergeable.len() > MAX_MERGEABLE {
            return Err(WorkFault::Invalid("too many slices or mergeable paths").into());
        }
        if request.slices.iter().any(|slice| !ident(&slice.name)) {
            return Err(WorkFault::Invalid("invalid slice name").into());
        }
        unique(
            request.slices.iter().map(|slice| slice.name.as_str()),
            "duplicate slice name",
        )?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let mut proposed = snapshot.graph();
        proposed.slices = request
            .slices
            .iter()
            .map(|slice| (slice.name.clone(), slice.paths.clone()))
            .collect();
        proposed.mergeable.clone_from(&request.mergeable);
        check(&proposed)?;
        let mut wanted = Vec::new();
        for slice in &request.slices {
            wanted.push((slice.name.clone(), normalised(&slice.paths)?));
        }
        replace_slices(&mut tx, project_id, &snapshot, &wanted).await?;
        let mergeable: Vec<String> = normalised(&request.mergeable)?.into_iter().collect();
        sqlx::query(DELETE_MERGEABLE)
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(INSERT_MERGEABLE)
            .bind(project_id)
            .bind(&mergeable)
            .execute(&mut *tx)
            .await?;
        insert_event(
            &mut tx,
            project_id,
            None,
            None,
            "updated",
            &actor(user_id),
            "slices set",
        )
        .await?;
        let row = sqlx::query(PROJECT_ROW)
            .bind(project_id)
            .fetch_one(&mut *tx)
            .await?;
        let reply = project_view(
            &mut tx,
            project_id,
            row.try_get("name")?,
            row.try_get("repo")?,
            row.try_get("created_ms")?,
        )
        .await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Adds an item with its slices and dependencies.
    ///
    /// # Errors
    ///
    /// [`WorkFault::Invalid`] for a bad field, [`WorkFault::Exists`] for a taken item key and
    /// [`WorkFault::Graph`] for an unknown slice or dependency, a cycle or a bound.
    pub async fn add_work_item(
        &self,
        user_id: i64,
        request: &AddWorkItemRequest,
    ) -> Result<WorkItem, StoreError> {
        const RPC: &str = "AddWorkItem";
        let key = client_key(&request.key)?;
        let new_key = item_key(&request.item_key)?;
        if !line(&request.title, MAX_TITLE_CHARS) {
            return Err(WorkFault::Invalid("invalid title").into());
        }
        if !lines(&request.body, MAX_BODY_BYTES) {
            return Err(WorkFault::Invalid("invalid body").into());
        }
        if request.slices.len() > MAX_NODE_SLICES || request.slices.iter().any(|s| !ident(s)) {
            return Err(WorkFault::Invalid("invalid slices").into());
        }
        unique(request.slices.iter().map(String::as_str), "duplicate slice")?;
        if request.deps.len() > MAX_DEPENDS
            || request
                .deps
                .iter()
                .any(|dep| !ident(&dep.depends_on) || !line(&dep.why, MAX_WHY_CHARS))
        {
            return Err(WorkFault::Invalid("invalid dependencies").into());
        }
        unique(
            request.deps.iter().map(|dep| dep.depends_on.as_str()),
            "duplicate dependency",
        )?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        if snapshot.items.iter().any(|item| item.key == new_key) {
            return Err(WorkFault::Exists("work item key already used").into());
        }
        let mut proposed = snapshot.graph();
        proposed.nodes.push(Node {
            id: new_key.to_owned(),
            depends: request.deps.iter().map(|d| d.depends_on.clone()).collect(),
            why: "edge".to_owned(),
            slices: Some(request.slices.clone()),
            done: false,
        });
        check(&proposed)?;
        let item_id: i64 = sqlx::query_scalar(INSERT_ITEM)
            .bind(project_id)
            .bind(new_key)
            .bind(&request.title)
            .bind(&request.body)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query(INSERT_MEMBERS)
            .bind(project_id)
            .bind(item_id)
            .bind(&request.slices)
            .execute(&mut *tx)
            .await?;
        for dep in &request.deps {
            sqlx::query(INSERT_DEP)
                .bind(project_id)
                .bind(item_id)
                .bind(&dep.depends_on)
                .bind(&dep.why)
                .execute(&mut *tx)
                .await?;
        }
        insert_event(
            &mut tx,
            project_id,
            Some(item_id),
            None,
            "created",
            &actor(user_id),
            "item created",
        )
        .await?;
        let reply = Snapshot::load(&mut tx, project_id)
            .await?
            .view_of(new_key)?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Adds one dependency edge.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ItemNotFound`], [`WorkFault::Exists`] for an edge already there and
    /// [`WorkFault::Graph`] for a cycle or a bound.
    pub async fn add_work_dep(
        &self,
        user_id: i64,
        request: &AddWorkDepRequest,
    ) -> Result<WorkItem, StoreError> {
        const RPC: &str = "AddWorkDep";
        let key = client_key(&request.key)?;
        let name = item_key(&request.item_key)?;
        let dep = request
            .dep
            .as_ref()
            .ok_or(WorkFault::Invalid("missing dependency"))?;
        if !ident(&dep.depends_on) || !line(&dep.why, MAX_WHY_CHARS) {
            return Err(WorkFault::Invalid("invalid dependency").into());
        }
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let item = snapshot.item(name)?;
        let target = snapshot.item(&dep.depends_on)?;
        if snapshot
            .deps
            .iter()
            .any(|d| d.item_id == item.id && d.depends_on_id == target.id)
        {
            return Err(WorkFault::Exists("dependency already exists").into());
        }
        let mut proposed = snapshot.graph();
        if let Some(node) = proposed.nodes.iter_mut().find(|n| n.id == name) {
            node.depends.push(dep.depends_on.clone());
        }
        check(&proposed)?;
        let item_id = item.id;
        sqlx::query(INSERT_DEP)
            .bind(project_id)
            .bind(item_id)
            .bind(&dep.depends_on)
            .bind(&dep.why)
            .execute(&mut *tx)
            .await?;
        sqlx::query(TOUCH_ITEM)
            .bind(project_id)
            .bind(item_id)
            .execute(&mut *tx)
            .await?;
        insert_event(
            &mut tx,
            project_id,
            Some(item_id),
            None,
            "dep_added",
            &actor(user_id),
            &dep.why,
        )
        .await?;
        let reply = Snapshot::load(&mut tx, project_id).await?.view_of(name)?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Removes one dependency edge.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ItemNotFound`] and [`WorkFault::DepNotFound`].
    pub async fn remove_work_dep(
        &self,
        user_id: i64,
        request: &RemoveWorkDepRequest,
    ) -> Result<WorkItem, StoreError> {
        const RPC: &str = "RemoveWorkDep";
        let key = client_key(&request.key)?;
        let name = item_key(&request.item_key)?;
        if !ident(&request.depends_on) {
            return Err(WorkFault::Invalid("invalid dependency").into());
        }
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let item_id = snapshot.item(name)?.id;
        let target_id = snapshot.item(&request.depends_on)?.id;
        let removed = sqlx::query(DELETE_DEP)
            .bind(project_id)
            .bind(item_id)
            .bind(target_id)
            .execute(&mut *tx)
            .await?;
        if removed.rows_affected() == 0 {
            return Err(WorkFault::DepNotFound.into());
        }
        sqlx::query(TOUCH_ITEM)
            .bind(project_id)
            .bind(item_id)
            .execute(&mut *tx)
            .await?;
        insert_event(
            &mut tx,
            project_id,
            Some(item_id),
            None,
            "dep_removed",
            &actor(user_id),
            "dependency removed",
        )
        .await?;
        let reply = Snapshot::load(&mut tx, project_id).await?.view_of(name)?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Cancels an item and closes the attempt that holds it, if any, as lost.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ItemNotFound`] and [`WorkFault::Precondition`] for an item already
    /// cancelled.
    pub async fn cancel_work(
        &self,
        user_id: i64,
        request: &CancelWorkRequest,
    ) -> Result<WorkItem, StoreError> {
        const RPC: &str = "CancelWork";
        let key = client_key(&request.key)?;
        let name = item_key(&request.item_key)?;
        let reason = reason(&request.reason)?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let item = snapshot.item(name)?;
        if item.state == "cancelled" {
            return Err(WorkFault::Precondition("work item is already cancelled").into());
        }
        let item_id = item.id;
        let who = actor(user_id);
        free_item(&mut tx, project_id, item_id, &who, "closed by cancel").await?;
        sqlx::query(SET_STATE)
            .bind(project_id)
            .bind(item_id)
            .bind("cancelled")
            .execute(&mut *tx)
            .await?;
        insert_event(
            &mut tx,
            project_id,
            Some(item_id),
            None,
            "cancelled",
            &who,
            reason,
        )
        .await?;
        let reply = Snapshot::load(&mut tx, project_id).await?.view_of(name)?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Clears a block and frees the slices an attempt holds on an item, closing that attempt as
    /// lost.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ItemNotFound`], and [`WorkFault::Precondition`] for a cancelled item or an
    /// item that is neither blocked nor held.
    pub async fn unblock_work(
        &self,
        user_id: i64,
        request: &UnblockWorkRequest,
    ) -> Result<WorkItem, StoreError> {
        const RPC: &str = "UnblockWork";
        let key = client_key(&request.key)?;
        let name = item_key(&request.item_key)?;
        let reason = reason(&request.reason)?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let item = snapshot.item(name)?;
        if item.state == "cancelled" {
            return Err(WorkFault::Precondition("work item is cancelled").into());
        }
        let blocked = item.state == "blocked";
        let item_id = item.id;
        let who = actor(user_id);
        let freed = free_item(&mut tx, project_id, item_id, &who, "closed by unblock").await?;
        if !blocked && freed == 0 {
            return Err(WorkFault::Precondition("work item is not blocked or held").into());
        }
        sqlx::query(SET_STATE)
            .bind(project_id)
            .bind(item_id)
            .bind("open")
            .execute(&mut *tx)
            .await?;
        insert_event(
            &mut tx,
            project_id,
            Some(item_id),
            None,
            "unblocked",
            &who,
            reason,
        )
        .await?;
        let reply = Snapshot::load(&mut tx, project_id).await?.view_of(name)?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }
}

/// Makes the stored slices equal `wanted`. A leased slice must keep its paths.
pub(super) async fn replace_slices(
    tx: &mut Transaction<'static, Postgres>,
    project_id: i64,
    snapshot: &Snapshot,
    wanted: &[(String, BTreeSet<String>)],
) -> Result<(), StoreError> {
    let leased: Vec<String> = sqlx::query_scalar(LEASED_SLICES)
        .bind(project_id)
        .fetch_all(&mut **tx)
        .await?;
    for name in &leased {
        let before: BTreeSet<String> = snapshot
            .slices
            .get(name)
            .map(|paths| paths.iter().cloned().collect())
            .unwrap_or_default();
        let kept = wanted
            .iter()
            .any(|(n, paths)| n == name && *paths == before);
        if !kept {
            return Err(WorkFault::Precondition("slice is leased").into());
        }
    }
    let names: Vec<String> = wanted.iter().map(|(name, _)| name.clone()).collect();
    sqlx::query(DELETE_SLICES)
        .bind(project_id)
        .bind(&names)
        .execute(&mut **tx)
        .await?;
    store_slices(tx, project_id, snapshot, wanted).await
}

async fn store_slices(
    tx: &mut Transaction<'static, Postgres>,
    project_id: i64,
    snapshot: &Snapshot,
    wanted: &[(String, BTreeSet<String>)],
) -> Result<(), StoreError> {
    for (name, paths) in wanted {
        let existing: Option<i64> = sqlx::query_scalar(SLICE_ID)
            .bind(project_id)
            .bind(name)
            .fetch_optional(&mut **tx)
            .await?;
        let slice_id = match existing {
            Some(id) => {
                let before: BTreeSet<String> = snapshot
                    .slices
                    .get(name)
                    .map(|p| p.iter().cloned().collect())
                    .unwrap_or_default();
                if before == *paths {
                    continue;
                }
                sqlx::query(DELETE_SLICE_PATHS)
                    .bind(id)
                    .execute(&mut **tx)
                    .await?;
                id
            }
            None => {
                sqlx::query_scalar(INSERT_SLICE)
                    .bind(project_id)
                    .bind(name)
                    .fetch_one(&mut **tx)
                    .await?
            }
        };
        let list: Vec<String> = paths.iter().cloned().collect();
        sqlx::query(INSERT_SLICE_PATHS)
            .bind(slice_id)
            .bind(&list)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

pub(super) fn reason(text: &str) -> Result<&str, WorkFault> {
    if text.trim().is_empty() || !lines(text, MAX_REASON_BYTES) {
        return Err(WorkFault::Invalid("invalid reason"));
    }
    Ok(text)
}

async fn free_item(
    tx: &mut Transaction<'static, Postgres>,
    project_id: i64,
    item_id: i64,
    who: &str,
    note: &str,
) -> Result<usize, StoreError> {
    sqlx::query(FREE_LEASES)
        .bind(project_id)
        .bind(item_id)
        .execute(&mut **tx)
        .await?;
    let closed: Vec<i64> = sqlx::query_scalar(CLOSE_ATTEMPTS)
        .bind(project_id)
        .bind(item_id)
        .bind(note)
        .fetch_all(&mut **tx)
        .await?;
    for attempt in &closed {
        insert_event(
            tx,
            project_id,
            Some(item_id),
            Some(*attempt),
            "lost",
            who,
            note,
        )
        .await?;
    }
    Ok(closed.len())
}

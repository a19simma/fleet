//! Defers: work found during an attempt and left out of scope.

use fleet_core::graph::Node;
use fleet_proto::v1::{
    ListWorkDefersReply, ListWorkDefersRequest, RecordWorkDeferRequest, ResolveWorkDeferRequest,
    WorkDefer, WorkDeferState,
};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use super::load::Snapshot;
use super::write::{Started, check, keyless, reason};
use super::{
    MAX_LIST_DEFERS, MAX_TITLE_CHARS, WorkFault, actor, client_key, digest, find_project,
    insert_event, item_key, line, project_name, unsigned,
};
use crate::store::{Store, StoreError};

const INSERT_DEFER: &str = "\
INSERT INTO work_defer (project_id, item_id, attempt_id, title, reason, vertical) \
SELECT $1, $2, $3, $4, $5, $6 \
WHERE ($2::bigint IS NULL OR EXISTS (\
SELECT 1 FROM work_item WHERE id = $2 AND project_id = $1)) \
AND ($3::bigint IS NULL OR EXISTS (\
SELECT 1 FROM work_attempt WHERE id = $3 AND project_id = $1)) \
RETURNING id";

const SET_RESOLUTION: &str = "\
UPDATE work_defer SET state = $3, promoted_item_id = $4 \
WHERE id = $1 AND project_id = $2 \
AND ($4::bigint IS NULL OR EXISTS (\
SELECT 1 FROM work_item WHERE id = $4 AND project_id = $2))";

const LOCK_DEFER: &str = "\
SELECT state, title, reason, item_id, attempt_id FROM work_defer \
WHERE id = $1 AND project_id = $2 FOR UPDATE";

const ITEM_ID: &str = "SELECT id FROM work_item WHERE project_id = $1 AND key = $2";

const INSERT_ITEM: &str = "\
INSERT INTO work_item (project_id, key, title, body) VALUES ($1, $2, $3, $4) RETURNING id";

const ONE_DEFER: &str = "\
SELECT d.id, i.key AS item_key, d.attempt_id, d.title, d.reason, d.vertical, d.state, \
p.key AS promoted_key, (extract(epoch FROM d.created_at) * 1000)::bigint AS created_ms \
FROM work_defer d \
LEFT JOIN work_item i ON i.id = d.item_id AND i.project_id = d.project_id \
LEFT JOIN work_item p ON p.id = d.promoted_item_id AND p.project_id = d.project_id \
WHERE d.id = $1 AND d.project_id = $2";

const LIST_DEFERS: &str = "\
SELECT d.id, i.key AS item_key, d.attempt_id, d.title, d.reason, d.vertical, d.state, \
p.key AS promoted_key, (extract(epoch FROM d.created_at) * 1000)::bigint AS created_ms \
FROM work_defer d \
LEFT JOIN work_item i ON i.id = d.item_id AND i.project_id = d.project_id \
LEFT JOIN work_item p ON p.id = d.promoted_item_id AND p.project_id = d.project_id \
WHERE d.project_id = $1 AND ($2::text IS NULL OR d.vertical = $2) \
AND ($3::text IS NULL OR d.state = $3) ORDER BY d.id LIMIT $4";

/// Inserts a defer of `project_id`. A reference to an item or attempt of another project
/// writes nothing and returns [`WorkFault::CrossProject`].
pub(super) async fn insert_defer(
    conn: &mut PgConnection,
    project_id: i64,
    item_id: Option<i64>,
    attempt_id: Option<i64>,
    text: (&str, &str, &str),
) -> Result<i64, StoreError> {
    sqlx::query_scalar(INSERT_DEFER)
        .bind(project_id)
        .bind(item_id)
        .bind(attempt_id)
        .bind(text.0)
        .bind(text.1)
        .bind(text.2)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| WorkFault::CrossProject.into())
}

/// Marks a defer of `project_id` promoted to `promoted` or dropped. A promoted item of another
/// project writes nothing and returns [`WorkFault::CrossProject`].
pub(super) async fn set_resolution(
    conn: &mut PgConnection,
    project_id: i64,
    defer_id: i64,
    promoted: Option<i64>,
) -> Result<(), StoreError> {
    let state = if promoted.is_some() {
        "promoted"
    } else {
        "dropped"
    };
    let done = sqlx::query(SET_RESOLUTION)
        .bind(defer_id)
        .bind(project_id)
        .bind(state)
        .bind(promoted)
        .execute(&mut *conn)
        .await?;
    if done.rows_affected() == 0 {
        return Err(WorkFault::CrossProject.into());
    }
    Ok(())
}

fn state_name(state: WorkDeferState) -> &'static str {
    match state {
        WorkDeferState::Open => "open",
        WorkDeferState::Promoted => "promoted",
        WorkDeferState::Dropped => "dropped",
        WorkDeferState::Unspecified => "",
    }
}

fn state_of(text: &str) -> Result<WorkDeferState, StoreError> {
    match text {
        "open" => Ok(WorkDeferState::Open),
        "promoted" => Ok(WorkDeferState::Promoted),
        "dropped" => Ok(WorkDeferState::Dropped),
        _ => Err(StoreError::OutOfRange("work defer state")),
    }
}

fn view(row: &PgRow) -> Result<WorkDefer, StoreError> {
    let attempt: Option<i64> = row.try_get("attempt_id")?;
    let state: String = row.try_get("state")?;
    Ok(WorkDefer {
        id: unsigned(row.try_get("id")?)?,
        item_key: row.try_get("item_key")?,
        attempt_id: attempt.map(unsigned).transpose()?,
        title: row.try_get("title")?,
        reason: row.try_get("reason")?,
        vertical: row.try_get("vertical")?,
        state: state_of(&state)? as i32,
        promoted_item_key: row.try_get("promoted_key")?,
        created_at_ms: unsigned(row.try_get("created_ms")?)?,
    })
}

async fn defer_view(
    conn: &mut PgConnection,
    project_id: i64,
    id: i64,
) -> Result<WorkDefer, StoreError> {
    let row = sqlx::query(ONE_DEFER)
        .bind(id)
        .bind(project_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(WorkFault::DeferNotFound)?;
    view(&row)
}

fn vertical(text: &str) -> Result<&str, WorkFault> {
    if line(text, 128) {
        Ok(text)
    } else {
        Err(WorkFault::Invalid("invalid vertical"))
    }
}

impl Store {
    /// Records a defer, optionally tied to an item by key and to an attempt of the project.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ItemNotFound`], [`WorkFault::CrossProject`] for an attempt of another
    /// project, and [`WorkFault::Invalid`] for a bad title, reason, vertical or attempt id.
    pub async fn record_work_defer(
        &self,
        user_id: i64,
        request: &RecordWorkDeferRequest,
    ) -> Result<WorkDefer, StoreError> {
        const RPC: &str = "RecordWorkDefer";
        let key = client_key(&request.key)?;
        if !line(&request.title, MAX_TITLE_CHARS) {
            return Err(WorkFault::Invalid("invalid title").into());
        }
        let why = reason(&request.reason)?;
        let area = vertical(&request.vertical)?;
        let item_name = request.item_key.as_deref().map(item_key).transpose()?;
        let attempt = request
            .attempt_id
            .map(|raw| i64::try_from(raw).map_err(|_| WorkFault::Invalid("invalid attempt id")))
            .transpose()?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let item = match item_name {
            None => None,
            Some(name) => Some(
                sqlx::query_scalar::<_, i64>(ITEM_ID)
                    .bind(project_id)
                    .bind(name)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(WorkFault::ItemNotFound)?,
            ),
        };
        let id = insert_defer(
            &mut tx,
            project_id,
            item,
            attempt,
            (&request.title, why, area),
        )
        .await?;
        insert_event(
            &mut tx,
            project_id,
            item,
            attempt,
            "deferred",
            &actor(user_id),
            &request.title,
        )
        .await?;
        let reply = defer_view(&mut tx, project_id, id).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Promotes an open defer to a new item or drops it.
    ///
    /// # Errors
    ///
    /// [`WorkFault::DeferNotFound`], [`WorkFault::Invalid`] for a promote without an item key or
    /// a drop with one, [`WorkFault::Precondition`] for a defer already resolved,
    /// [`WorkFault::Exists`] for a taken item key and [`WorkFault::Graph`] at the item bound.
    pub async fn resolve_work_defer(
        &self,
        user_id: i64,
        request: &ResolveWorkDeferRequest,
    ) -> Result<WorkDefer, StoreError> {
        const RPC: &str = "ResolveWorkDefer";
        let key = client_key(&request.key)?;
        let defer =
            i64::try_from(request.defer_id).map_err(|_| WorkFault::Invalid("invalid defer id"))?;
        let new_key = match (request.promote, request.item_key.as_deref()) {
            (true, Some(name)) => Some(item_key(name)?),
            (true, None) => return Err(WorkFault::Invalid("promote needs an item key").into()),
            (false, None) => None,
            (false, Some(_)) => return Err(WorkFault::Invalid("drop takes no item key").into()),
        };
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let row = sqlx::query(LOCK_DEFER)
            .bind(defer)
            .bind(project_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(WorkFault::DeferNotFound)?;
        let state: String = row.try_get("state")?;
        if state != "open" {
            return Err(WorkFault::Precondition("defer is already resolved").into());
        }
        let who = actor(user_id);
        let promoted = if let Some(name) = new_key {
            let title: String = row.try_get("title")?;
            let body: String = row.try_get("reason")?;
            let snapshot = Snapshot::load(&mut tx, project_id).await?;
            if snapshot.items.iter().any(|item| item.key == name) {
                return Err(WorkFault::Exists("work item key already used").into());
            }
            let mut proposed = snapshot.graph();
            proposed.nodes.push(Node {
                id: name.to_owned(),
                depends: Vec::new(),
                why: "edge".to_owned(),
                slices: Some(Vec::new()),
                done: false,
            });
            check(&proposed)?;
            let item: i64 = sqlx::query_scalar(INSERT_ITEM)
                .bind(project_id)
                .bind(name)
                .bind(title)
                .bind(body)
                .fetch_one(&mut *tx)
                .await?;
            insert_event(
                &mut tx,
                project_id,
                Some(item),
                None,
                "created",
                &who,
                "promoted from defer",
            )
            .await?;
            Some(item)
        } else {
            let item: Option<i64> = row.try_get("item_id")?;
            let attempt: Option<i64> = row.try_get("attempt_id")?;
            insert_event(
                &mut tx, project_id, item, attempt, "deferred", &who, "dropped",
            )
            .await?;
            None
        };
        set_resolution(&mut tx, project_id, defer, promoted).await?;
        let reply = defer_view(&mut tx, project_id, defer).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Lists defers of a project by id, filtered by vertical and state.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`], [`WorkFault::Invalid`] for a bad filter and
    /// [`WorkFault::Precondition`] when more than 1000 defers match, so a reply never drops
    /// rows silently.
    pub async fn list_work_defers(
        &self,
        user_id: i64,
        request: &ListWorkDefersRequest,
    ) -> Result<ListWorkDefersReply, StoreError> {
        project_name(&request.project)?;
        let area = request.vertical.as_deref().map(vertical).transpose()?;
        let wanted = match request.state {
            None => None,
            Some(raw) => match WorkDeferState::try_from(raw) {
                Ok(WorkDeferState::Unspecified) | Err(_) => {
                    return Err(WorkFault::Invalid("invalid state filter").into());
                }
                Ok(state) => Some(state_name(state)),
            },
        };
        let mut tx = self.begin_read().await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let rows = sqlx::query(LIST_DEFERS)
            .bind(project_id)
            .bind(area)
            .bind(wanted)
            .bind(MAX_LIST_DEFERS + 1)
            .fetch_all(&mut *tx)
            .await?;
        if i64::try_from(rows.len()).is_ok_and(|n| n > MAX_LIST_DEFERS) {
            return Err(
                WorkFault::Precondition("too many defers, filter by vertical or state").into(),
            );
        }
        let defers = rows.iter().map(view).collect::<Result<_, _>>()?;
        Ok(ListWorkDefersReply { defers })
    }
}

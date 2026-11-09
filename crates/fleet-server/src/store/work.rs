//! Work tracker store: projects, slices, items and dependencies (ADR-0064).
//!
//! Every call takes the caller's user id and finds a project by `(user_id, name)`, so another
//! user's project and an unknown one both answer [`WorkFault::ProjectNotFound`].
//!
//! A graph write (slices, items, dependencies, cancel, unblock) takes `FOR UPDATE` on the
//! `work_project` row first, then reads the whole graph, applies the change in memory and runs
//! [`fleet_core::graph::validate`] on the result before it writes a row. Two writers on one
//! project therefore queue on that row, and the cycle and path overlap checks see the committed
//! state of the writer ahead.
//!
//! Every mutating call carries a client key. The first call stores the encoded reply in
//! `work_request_key` under `(project, key)` together with a digest of the request without its
//! key. A repeat with the same digest returns that reply, and a repeat with another request is
//! [`StoreError::KeyConflict`]. `CreateWorkProject` has no project to lock yet, so it locks the
//! user row with `FOR NO KEY UPDATE` and looks the key up over the user's projects.
//!
//! `work_event` and `work_defer` reference items and attempts with single column foreign keys,
//! so the schema alone does not stop a row that points into another project. [`insert_event`]
//! checks the project of every reference inside its own statement.

mod load;
mod write;

use std::fmt;

use fleet_core::graph::{GraphError, MAX_ID_BYTES};
use fleet_core::text::{is_hostile, strip_keeping_lines};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Postgres, Transaction};
use tonic_prost::prost::Message;

use super::StoreError;

#[cfg(test)]
mod tests;

const MAX_NAME_CHARS: usize = 128;
const MAX_TITLE_CHARS: usize = 200;
const MAX_WHY_CHARS: usize = 500;
const MAX_BODY_BYTES: usize = 16384;
const MAX_REASON_BYTES: usize = 2000;
const MAX_LIST_PROJECTS: i64 = 1000;
const MAX_DETAIL_ROWS: i64 = 200;

const SELECT_KEY: &str = "\
SELECT rpc, request_digest, response FROM work_request_key WHERE project_id = $1 AND key = $2";

const INSERT_KEY: &str = "\
INSERT INTO work_request_key (project_id, key, rpc, request_digest, response) \
VALUES ($1, $2, $3, $4, $5)";

const INSERT_EVENT: &str = "\
INSERT INTO work_event (project_id, item_id, attempt_id, kind, actor, note) \
SELECT $1, $2, $3, $4, $5, $6 \
WHERE ($2::bigint IS NULL OR EXISTS (\
SELECT 1 FROM work_item WHERE id = $2 AND project_id = $1)) \
AND ($3::bigint IS NULL OR EXISTS (\
SELECT 1 FROM work_attempt WHERE id = $3 AND project_id = $1))";

const LOCK_PROJECT: &str =
    "SELECT id FROM work_project WHERE user_id = $1 AND name = $2 FOR UPDATE";

const FIND_PROJECT: &str = "SELECT id FROM work_project WHERE user_id = $1 AND name = $2";

/// Why a work tracker call refused.
///
/// Every variant maps to a fixed client message, and none keeps text the client sent, except [`WorkFault::Graph`], whose [`GraphError`] carries only values
/// that passed the graph checks.
#[derive(Debug)]
#[non_exhaustive]
pub enum WorkFault {
    /// The project is unknown or belongs to another user.
    ProjectNotFound,
    /// The item is unknown in that project.
    ItemNotFound,
    /// The dependency edge does not exist.
    DepNotFound,
    /// An input broke a rule. The text is fixed.
    Invalid(&'static str),
    /// The resulting graph is not valid.
    Graph(GraphError),
    /// A unique name is taken. The text is fixed.
    Exists(&'static str),
    /// The state of the project does not allow the call. The text is fixed.
    Precondition(&'static str),
    /// The project repository is not in the caller's registry.
    RepoNotRegistered,
    /// A write would link a row to an item or attempt of another project.
    CrossProject,
}

impl fmt::Display for WorkFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProjectNotFound => f.write_str("work project not found"),
            Self::ItemNotFound => f.write_str("work item not found"),
            Self::DepNotFound => f.write_str("work dependency not found"),
            Self::Invalid(reason) | Self::Exists(reason) | Self::Precondition(reason) => {
                f.write_str(reason)
            }
            Self::Graph(err) => err.fmt(f),
            Self::RepoNotRegistered => f.write_str("repository is not registered"),
            Self::CrossProject => f.write_str("work reference crosses projects"),
        }
    }
}

impl From<WorkFault> for StoreError {
    fn from(fault: WorkFault) -> Self {
        Self::Work(fault)
    }
}

/// A name, key or slice name: 1 to 128 printable ASCII bytes, the id rule of
/// [`fleet_core::graph`].
pub(super) fn ident(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_ID_BYTES && text.bytes().all(|b| b.is_ascii_graphic())
}

/// One line of at most `max` characters with a visible character and no hostile character.
pub(super) fn line(text: &str, max: usize) -> bool {
    text.chars().count() <= max && !text.trim().is_empty() && !text.chars().any(is_hostile)
}

/// Text of at most `max` bytes that keeps only newline and tab from the hostile set.
pub(super) fn lines(text: &str, max: usize) -> bool {
    text.len() <= max && strip_keeping_lines(text) == text
}

pub(super) fn project_name(name: &str) -> Result<&str, WorkFault> {
    if line(name, MAX_NAME_CHARS) {
        Ok(name)
    } else {
        Err(WorkFault::Invalid("invalid project name"))
    }
}

pub(super) fn client_key(key: &str) -> Result<&str, WorkFault> {
    if ident(key) {
        Ok(key)
    } else {
        Err(WorkFault::Invalid("invalid idempotency key"))
    }
}

pub(super) fn item_key(key: &str) -> Result<&str, WorkFault> {
    if ident(key) {
        Ok(key)
    } else {
        Err(WorkFault::Invalid("invalid item key"))
    }
}

pub(super) fn actor(user_id: i64) -> String {
    format!("user {user_id}")
}

pub(super) fn digest<M: Message>(rpc: &str, keyless: &M) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(rpc.as_bytes());
    hasher.update([0]);
    hasher.update(keyless.encode_to_vec());
    hasher.finalize().to_vec()
}

/// The stored reply of an earlier call with the same key and request, `None` for a new key.
///
/// # Errors
///
/// [`StoreError::KeyConflict`] when the key was used for another rpc or another request.
pub(super) async fn replay<R: Message + Default>(
    conn: &mut PgConnection,
    project_id: i64,
    key: &str,
    rpc: &str,
    request_digest: &[u8],
) -> Result<Option<R>, StoreError> {
    let row: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(SELECT_KEY)
        .bind(project_id)
        .bind(key)
        .fetch_optional(&mut *conn)
        .await?;
    let Some((stored_rpc, stored_digest, response)) = row else {
        return Ok(None);
    };
    if stored_rpc != rpc || stored_digest != request_digest {
        return Err(StoreError::KeyConflict);
    }
    R::decode(response.as_slice())
        .map(Some)
        .map_err(|_| StoreError::OutOfRange("work response"))
}

pub(super) async fn remember<R: Message>(
    conn: &mut PgConnection,
    project_id: i64,
    key: &str,
    rpc: &str,
    request_digest: &[u8],
    reply: &R,
) -> Result<(), StoreError> {
    sqlx::query(INSERT_KEY)
        .bind(project_id)
        .bind(key)
        .bind(rpc)
        .bind(request_digest)
        .bind(reply.encode_to_vec())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Records an event of `project_id`. A reference to an item or attempt of another project
/// writes nothing and returns [`WorkFault::CrossProject`].
pub(super) async fn insert_event(
    conn: &mut PgConnection,
    project_id: i64,
    item_id: Option<i64>,
    attempt_id: Option<i64>,
    kind: &str,
    actor: &str,
    note: &str,
) -> Result<(), StoreError> {
    let done = sqlx::query(INSERT_EVENT)
        .bind(project_id)
        .bind(item_id)
        .bind(attempt_id)
        .bind(kind)
        .bind(actor)
        .bind(note)
        .execute(&mut *conn)
        .await?;
    if done.rows_affected() == 0 {
        return Err(WorkFault::CrossProject.into());
    }
    Ok(())
}

pub(super) async fn lock_project(
    tx: &mut Transaction<'_, Postgres>,
    user_id: i64,
    name: &str,
) -> Result<i64, StoreError> {
    sqlx::query_scalar(LOCK_PROJECT)
        .bind(user_id)
        .bind(project_name(name)?)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| WorkFault::ProjectNotFound.into())
}

pub(super) async fn find_project(
    conn: &mut PgConnection,
    user_id: i64,
    name: &str,
) -> Result<i64, StoreError> {
    sqlx::query_scalar(FIND_PROJECT)
        .bind(user_id)
        .bind(project_name(name)?)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| WorkFault::ProjectNotFound.into())
}

pub(super) fn unsigned(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::OutOfRange("work timestamp"))
}

impl std::error::Error for WorkFault {}

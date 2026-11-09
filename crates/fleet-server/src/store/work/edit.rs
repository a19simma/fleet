//! Suggested edits: filing, listing, stale marking and the decide transaction (ADR-0066).
//!
//! Every call takes the project row lock before it reads. A list or a get can move a `pending`
//! edit to `stale`, so those take the lock too. `DecideEdit` applies a `slice_op` or `pitfall`
//! edit in the same transaction that marks it accepted, or rolls back with a fixed reason. A
//! `file_patch` is stored and marked, never applied: the server has no repository to hash, so
//! its `base_hash` is the blob id the filer sent and never goes stale here.

use std::collections::{BTreeMap, BTreeSet};

use fleet_core::Redactor;
use fleet_core::graph::{MAX_PATHS_PER_SLICE, RepoPath};
use fleet_proto::MAX_EDIT_PAYLOAD_BYTES;
use fleet_proto::v1::{
    DecideEditRequest, EditDecision, EditKind, EditState, FileEditRequest, GetEditRequest,
    ListEditsReply, ListEditsRequest, SuggestedEdit,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Postgres, Row, Transaction};

use super::load::{Snapshot, load_slices};
use super::retro::row_id;
use super::write::{Started, check, keyless, replace_slices};
use super::{
    MAX_CAUSE_CHARS, MAX_SYMPTOM_CHARS, WorkFault, actor, client_key, digest, ident, line, lines,
    lock_project, project_name, unsigned,
};
use crate::store::{Store, StoreError};

/// Fixed reason when an accepted edit no longer fits the graph.
pub const REASON_DOES_NOT_APPLY: &str = "edit does not apply to the current graph";
/// Fixed reason for a decide on a stale edit.
pub const REASON_STALE: &str = "edit is stale";
/// Fixed reason for a decide on an edit that is already accepted or rejected.
pub const REASON_DECIDED: &str = "edit is already decided";
/// Fixed reason when a project holds its most pending edits.
pub const REASON_TOO_MANY_PENDING: &str = "too many pending edits";

const MAX_LIST_EDITS: i64 = 1000;
const MAX_REFRESH_ROWS: i64 = 1000;

const COUNT_PENDING: &str =
    "SELECT count(*) FROM suggested_edit WHERE project_id = $1 AND state = 'pending'";

const INSERT_EDIT: &str = "\
INSERT INTO suggested_edit (project_id, kind, target, base_hash, payload, filed_by) \
VALUES ($1, $2, $3, $4, $5, $6) RETURNING id";

const EDIT_VIEW: &str = "\
SELECT id, kind, state, target, base_hash, payload, filed_by, decided_by, \
(extract(epoch FROM decided_at) * 1000)::bigint AS decided_ms, \
(extract(epoch FROM created_at) * 1000)::bigint AS created_ms \
FROM suggested_edit WHERE project_id = $1 AND id = $2 FOR UPDATE";

const LIST_EDITS: &str = "\
SELECT id, kind, state, target, base_hash, payload, filed_by, decided_by, \
(extract(epoch FROM decided_at) * 1000)::bigint AS decided_ms, \
(extract(epoch FROM created_at) * 1000)::bigint AS created_ms \
FROM suggested_edit WHERE project_id = $1 AND ($2::text IS NULL OR state = $2) \
ORDER BY id DESC LIMIT $3";

const PENDING_ROWS: &str = "\
SELECT id, kind, target, base_hash FROM suggested_edit \
WHERE project_id = $1 AND state = 'pending' AND ($2::bigint IS NULL OR id = $2) \
ORDER BY id LIMIT $3";

const MARK_STALE: &str = "\
UPDATE suggested_edit SET state = 'stale' \
WHERE project_id = $1 AND id = $2 AND state = 'pending'";

const MARK_DECIDED: &str = "\
UPDATE suggested_edit SET state = $3, decided_by = $4, decided_at = now() \
WHERE project_id = $1 AND id = $2";

const IS_BOOTSTRAP: &str = "SELECT $1 = bootstrap_user_id()";

const PITFALL_TEXT: &str = "\
SELECT cause, fix FROM pitfall WHERE user_id = $1 AND project_id = $2 AND symptom = $3";

const PITFALL_LOCK: &str = "\
SELECT id, cause, fix FROM pitfall WHERE user_id = $1 AND project_id = $2 AND symptom = $3 FOR UPDATE";

const PITFALL_UPDATE: &str = "\
UPDATE pitfall SET cause = $2, fix = $3 WHERE id = $1 AND user_id = $4";

const PITFALL_INSERT: &str = "\
INSERT INTO pitfall (user_id, project_id, symptom, cause, fix) VALUES ($1, $2, $3, $4, $5)";

/// One change to the slice set, parsed from a `slice_op` payload.
#[derive(Debug, PartialEq, Eq)]
enum SliceOp {
    AddPath(String),
    RemovePath(String),
    MovePath { path: String, to: String },
    Create(Vec<String>),
    Delete,
}

fn path_arg(raw: &str) -> Result<String, WorkFault> {
    RepoPath::new(raw)
        .map(|path| path.as_str().to_owned())
        .map_err(|_| WorkFault::Invalid("invalid path"))
}

/// Parses a tab separated slice op line.
fn parse_slice_op(payload: &str) -> Result<SliceOp, WorkFault> {
    const BAD: WorkFault = WorkFault::Invalid("invalid slice op");
    if payload.contains('\n') {
        return Err(BAD);
    }
    let parts: Vec<&str> = payload.split('\t').collect();
    match parts.as_slice() {
        ["add-path", path] => Ok(SliceOp::AddPath(path_arg(path)?)),
        ["remove-path", path] => Ok(SliceOp::RemovePath(path_arg(path)?)),
        ["move-path", path, to] if ident(to) => Ok(SliceOp::MovePath {
            path: path_arg(path)?,
            to: (*to).to_owned(),
        }),
        ["create-slice", paths @ ..] if !paths.is_empty() && paths.len() <= MAX_PATHS_PER_SLICE => {
            Ok(SliceOp::Create(
                paths
                    .iter()
                    .map(|path| path_arg(path))
                    .collect::<Result<_, _>>()?,
            ))
        }
        ["delete-slice"] => Ok(SliceOp::Delete),
        _ => Err(BAD),
    }
}

/// The pitfall text of a `pitfall` payload: cause, a newline, then fix.
fn parse_pitfall(payload: &str) -> Result<(&str, &str), WorkFault> {
    let (cause, fix) = payload
        .split_once('\n')
        .ok_or(WorkFault::Invalid("invalid pitfall payload"))?;
    if !line(cause, MAX_CAUSE_CHARS) || !line(fix, MAX_CAUSE_CHARS) {
        return Err(WorkFault::Invalid("invalid pitfall payload"));
    }
    Ok((cause, fix))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The hash of a slice path set. A slice that does not exist hashes to a fixed value.
fn slice_hash(paths: Option<&[String]>) -> String {
    let mut hasher = Sha256::new();
    match paths {
        None => hasher.update(b"slice-absent"),
        Some(paths) => {
            hasher.update(b"slice\n");
            let mut sorted: Vec<&String> = paths.iter().collect();
            sorted.sort();
            sorted.dedup();
            for path in sorted {
                hasher.update(path.as_bytes());
                hasher.update(b"\n");
            }
        }
    }
    hex(&hasher.finalize())
}

/// The hash of a pitfall text. A pitfall that does not exist hashes to a fixed value.
fn pitfall_hash(text: Option<(&str, &str)>) -> String {
    let mut hasher = Sha256::new();
    match text {
        None => hasher.update(b"pitfall-absent"),
        Some((cause, fix)) => {
            hasher.update(b"pitfall\n");
            hasher.update(cause.as_bytes());
            hasher.update(b"\0");
            hasher.update(fix.as_bytes());
        }
    }
    hex(&hasher.finalize())
}

fn kind_text(kind: EditKind) -> Result<&'static str, WorkFault> {
    match kind {
        EditKind::SliceOp => Ok("slice_op"),
        EditKind::Pitfall => Ok("pitfall"),
        EditKind::FilePatch => Ok("file_patch"),
        EditKind::Unspecified => Err(WorkFault::Invalid("invalid edit kind")),
    }
}

fn kind_of(text: &str) -> Result<EditKind, StoreError> {
    match text {
        "slice_op" => Ok(EditKind::SliceOp),
        "pitfall" => Ok(EditKind::Pitfall),
        "file_patch" => Ok(EditKind::FilePatch),
        _ => Err(StoreError::OutOfRange("edit kind")),
    }
}

fn state_text(state: EditState) -> &'static str {
    match state {
        EditState::Pending => "pending",
        EditState::Accepted => "accepted",
        EditState::Rejected => "rejected",
        EditState::Stale => "stale",
        EditState::Unspecified => "",
    }
}

fn state_of(text: &str) -> Result<EditState, StoreError> {
    match text {
        "pending" => Ok(EditState::Pending),
        "accepted" => Ok(EditState::Accepted),
        "rejected" => Ok(EditState::Rejected),
        "stale" => Ok(EditState::Stale),
        _ => Err(StoreError::OutOfRange("edit state")),
    }
}

fn view(row: &PgRow) -> Result<SuggestedEdit, StoreError> {
    let decided_by: Option<i64> = row.try_get("decided_by")?;
    let decided_ms: Option<i64> = row.try_get("decided_ms")?;
    Ok(SuggestedEdit {
        id: unsigned(row.try_get("id")?)?,
        kind: kind_of(row.try_get("kind")?)?.into(),
        state: state_of(row.try_get("state")?)?.into(),
        target: row.try_get("target")?,
        base_hash: row.try_get("base_hash")?,
        payload: row.try_get("payload")?,
        filed_by: row.try_get("filed_by")?,
        decided_by: decided_by.map(unsigned).transpose()?,
        decided_at_ms: decided_ms.map(unsigned).transpose()?,
        created_at_ms: unsigned(row.try_get("created_ms")?)?,
    })
}

/// A filing that passed every check that needs no database.
struct Draft {
    kind: EditKind,
    target: String,
    payload: String,
    filed_hash: Option<String>,
}

impl Draft {
    fn parse(request: &FileEditRequest, redactor: &Redactor) -> Result<Self, WorkFault> {
        let kind = EditKind::try_from(request.kind).unwrap_or(EditKind::Unspecified);
        kind_text(kind)?;
        if request.payload.trim().is_empty() {
            return Err(WorkFault::Invalid("empty payload"));
        }
        if request.payload.len() > MAX_EDIT_PAYLOAD_BYTES {
            return Err(WorkFault::Invalid("payload too large"));
        }
        if !lines(&request.payload, MAX_EDIT_PAYLOAD_BYTES) {
            return Err(WorkFault::Invalid("payload has forbidden characters"));
        }
        if matches!(
            redactor.redact_str(&request.payload),
            std::borrow::Cow::Owned(_)
        ) {
            return Err(WorkFault::Invalid("payload holds a secret"));
        }
        let own_hash = kind != EditKind::FilePatch;
        if own_hash && !request.base_hash.is_empty() {
            return Err(WorkFault::Invalid("base hash is set by the server"));
        }
        let target = match kind {
            EditKind::SliceOp => {
                parse_slice_op(&request.payload)?;
                if !ident(&request.target) {
                    return Err(WorkFault::Invalid("invalid edit target"));
                }
                request.target.clone()
            }
            EditKind::Pitfall => {
                parse_pitfall(&request.payload)?;
                if !line(&request.target, MAX_SYMPTOM_CHARS) {
                    return Err(WorkFault::Invalid("invalid edit target"));
                }
                request.target.clone()
            }
            EditKind::FilePatch | EditKind::Unspecified => RepoPath::new(&request.target)
                .map(|path| path.as_str().to_owned())
                .map_err(|_| WorkFault::Invalid("invalid edit target"))?,
        };
        if !own_hash && !ident(&request.base_hash) {
            return Err(WorkFault::Invalid("invalid base hash"));
        }
        Ok(Self {
            kind,
            target,
            payload: request.payload.clone(),
            filed_hash: (!own_hash).then(|| request.base_hash.clone()),
        })
    }
}

/// The hash `kind` and `target` have in the stored state, `None` for a file patch.
async fn current_hash(
    conn: &mut PgConnection,
    user_id: i64,
    project_id: i64,
    slices: &BTreeMap<String, Vec<String>>,
    kind: &str,
    target: &str,
) -> Result<Option<String>, StoreError> {
    match kind {
        "slice_op" => Ok(Some(slice_hash(slices.get(target).map(Vec::as_slice)))),
        "pitfall" => {
            let text: Option<(String, String)> = sqlx::query_as(PITFALL_TEXT)
                .bind(user_id)
                .bind(project_id)
                .bind(target)
                .fetch_optional(&mut *conn)
                .await?;
            Ok(Some(pitfall_hash(
                text.as_ref()
                    .map(|(cause, fix)| (cause.as_str(), fix.as_str())),
            )))
        }
        _ => Ok(None),
    }
}

/// Moves each `pending` edit (or only `only`) whose target changed since filing to `stale`.
async fn refresh_pending(
    conn: &mut PgConnection,
    user_id: i64,
    project_id: i64,
    only: Option<i64>,
) -> Result<(), StoreError> {
    let (slices, _) = load_slices(conn, project_id).await?;
    let rows: Vec<(i64, String, String, String)> = sqlx::query_as(PENDING_ROWS)
        .bind(project_id)
        .bind(only)
        .bind(MAX_REFRESH_ROWS)
        .fetch_all(&mut *conn)
        .await?;
    for (id, kind, target, base_hash) in rows {
        let now = current_hash(conn, user_id, project_id, &slices, &kind, &target).await?;
        if now.is_some_and(|now| now != base_hash) {
            sqlx::query(MARK_STALE)
                .bind(project_id)
                .bind(id)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}

async fn apply_slice_op(
    tx: &mut Transaction<'static, Postgres>,
    project_id: i64,
    target: &str,
    op: SliceOp,
) -> Result<(), StoreError> {
    let snapshot = Snapshot::load(tx, project_id).await?;
    let mut wanted: BTreeMap<String, BTreeSet<String>> = snapshot
        .slices
        .iter()
        .map(|(name, paths)| (name.clone(), paths.iter().cloned().collect()))
        .collect();
    let missing = || StoreError::from(WorkFault::Precondition(REASON_DOES_NOT_APPLY));
    match op {
        SliceOp::AddPath(path) => {
            wanted.get_mut(target).ok_or_else(missing)?.insert(path);
        }
        SliceOp::RemovePath(path) => {
            if !wanted.get_mut(target).ok_or_else(missing)?.remove(&path) {
                return Err(missing());
            }
        }
        SliceOp::MovePath { path, to } => {
            if !wanted.get_mut(target).ok_or_else(missing)?.remove(&path) {
                return Err(missing());
            }
            wanted.get_mut(&to).ok_or_else(missing)?.insert(path);
        }
        SliceOp::Create(paths) => {
            if wanted
                .insert(target.to_owned(), paths.into_iter().collect())
                .is_some()
            {
                return Err(missing());
            }
        }
        SliceOp::Delete => {
            wanted.remove(target).ok_or_else(missing)?;
        }
    }
    let mut proposed = snapshot.graph();
    proposed.slices = wanted
        .iter()
        .map(|(name, paths)| (name.clone(), paths.iter().cloned().collect()))
        .collect();
    check(&proposed).map_err(|_| missing())?;
    let wanted: Vec<(String, BTreeSet<String>)> = wanted.into_iter().collect();
    replace_slices(tx, project_id, &snapshot, &wanted).await
}

/// Applies a pitfall edit under the row lock and returns `false`, writing nothing, when the
/// locked row no longer hashes to `base_hash`.
async fn apply_pitfall(
    conn: &mut PgConnection,
    user_id: i64,
    project_id: i64,
    symptom: &str,
    payload: &str,
    base_hash: &str,
) -> Result<bool, StoreError> {
    let (cause, fix) = parse_pitfall(payload)?;
    let existing: Option<(i64, String, String)> = sqlx::query_as(PITFALL_LOCK)
        .bind(user_id)
        .bind(project_id)
        .bind(symptom)
        .fetch_optional(&mut *conn)
        .await?;
    let locked = pitfall_hash(
        existing
            .as_ref()
            .map(|(_, cause, fix)| (cause.as_str(), fix.as_str())),
    );
    if locked != base_hash {
        return Ok(false);
    }
    match existing {
        Some((id, _, _)) => {
            sqlx::query(PITFALL_UPDATE)
                .bind(id)
                .bind(cause)
                .bind(fix)
                .bind(user_id)
                .execute(&mut *conn)
                .await?;
        }
        None => {
            sqlx::query(PITFALL_INSERT)
                .bind(user_id)
                .bind(project_id)
                .bind(symptom)
                .bind(cause)
                .bind(fix)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(true)
}

impl Store {
    /// Files a suggested edit.
    ///
    /// A `slice_op` or `pitfall` edit stores the hash of its target as of this call. A
    /// `file_patch` stores the blob id the filer sent. `pending_cap` is the most `pending`
    /// edits the project may hold; the service passes
    /// [`fleet_proto::MAX_PENDING_EDITS_PER_PROJECT`].
    ///
    /// # Errors
    ///
    /// [`WorkFault::Invalid`] for a bad field or a payload that is too large, holds a secret or
    /// holds a hostile character, and [`WorkFault::Precondition`] with [`REASON_TOO_MANY_PENDING`]
    /// when the project holds `pending_cap` pending edits.
    pub async fn file_edit(
        &self,
        user_id: i64,
        request: &FileEditRequest,
        redactor: &Redactor,
        pending_cap: usize,
    ) -> Result<SuggestedEdit, StoreError> {
        const RPC: &str = "FileEdit";
        let key = client_key(&request.key)?;
        project_name(&request.project)?;
        let draft = Draft::parse(request, redactor)?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let pending: i64 = sqlx::query_scalar(COUNT_PENDING)
            .bind(project_id)
            .fetch_one(&mut *tx)
            .await?;
        if usize::try_from(pending).map_or(true, |held| held >= pending_cap) {
            return Err(WorkFault::Precondition(REASON_TOO_MANY_PENDING).into());
        }
        let kind = kind_text(draft.kind)?;
        let base_hash = if let Some(hash) = draft.filed_hash {
            hash
        } else {
            let (slices, _) = load_slices(&mut tx, project_id).await?;
            current_hash(&mut tx, user_id, project_id, &slices, kind, &draft.target)
                .await?
                .ok_or(StoreError::OutOfRange("edit hash"))?
        };
        let id: i64 = sqlx::query_scalar(INSERT_EDIT)
            .bind(project_id)
            .bind(kind)
            .bind(&draft.target)
            .bind(&base_hash)
            .bind(&draft.payload)
            .bind(actor(user_id))
            .fetch_one(&mut *tx)
            .await?;
        let row = sqlx::query(EDIT_VIEW)
            .bind(project_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        let reply = view(&row)?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Lists the newest edits of a project, at most 1000, oldest first. Pending edits whose
    /// target changed since filing become `stale` first.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] and [`WorkFault::Invalid`] for an unknown state filter.
    pub async fn list_edits(
        &self,
        user_id: i64,
        request: &ListEditsRequest,
    ) -> Result<ListEditsReply, StoreError> {
        let state = match request.state {
            None => None,
            Some(raw) => match EditState::try_from(raw) {
                Ok(EditState::Unspecified) | Err(_) => {
                    return Err(WorkFault::Invalid("invalid edit state").into());
                }
                Ok(state) => Some(state_text(state)),
            },
        };
        let mut tx = self.pool.begin().await?;
        let project_id = lock_project(&mut tx, user_id, &request.project).await?;
        refresh_pending(&mut tx, user_id, project_id, None).await?;
        let rows = sqlx::query(LIST_EDITS)
            .bind(project_id)
            .bind(state)
            .bind(MAX_LIST_EDITS)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        let mut edits = rows.iter().map(view).collect::<Result<Vec<_>, _>>()?;
        edits.reverse();
        Ok(ListEditsReply { edits })
    }

    /// Reads one edit, marking it `stale` first when its target changed since filing.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] and [`WorkFault::EditNotFound`].
    pub async fn get_edit(
        &self,
        user_id: i64,
        request: &GetEditRequest,
    ) -> Result<SuggestedEdit, StoreError> {
        let id = row_id(request.id, "invalid edit id")?;
        let mut tx = self.pool.begin().await?;
        let project_id = lock_project(&mut tx, user_id, &request.project).await?;
        refresh_pending(&mut tx, user_id, project_id, Some(id)).await?;
        let row = sqlx::query(EDIT_VIEW)
            .bind(project_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(WorkFault::EditNotFound)?;
        let reply = view(&row)?;
        tx.commit().await?;
        Ok(reply)
    }

    /// Accepts or rejects an edit as `user_id`, a person.
    ///
    /// The transaction locks the project row first, refuses the shared bootstrap user, marks the
    /// edit `stale` when its target changed, and for an accept applies a `slice_op` or `pitfall`
    /// edit and re-runs the graph check before it marks the edit accepted. A failed apply rolls
    /// back and leaves the edit `pending`. A `file_patch` is only marked.
    ///
    /// # Errors
    ///
    /// [`WorkFault::NotInteractive`] for the bootstrap user, [`WorkFault::EditNotFound`],
    /// [`WorkFault::Precondition`] with [`REASON_STALE`], [`REASON_DECIDED`] or
    /// [`REASON_DOES_NOT_APPLY`], and [`WorkFault::Invalid`] for an unset decision.
    pub async fn decide_edit(
        &self,
        user_id: i64,
        request: &DecideEditRequest,
    ) -> Result<SuggestedEdit, StoreError> {
        const RPC: &str = "DecideEdit";
        let key = client_key(&request.key)?;
        project_name(&request.project)?;
        let id = row_id(request.id, "invalid edit id")?;
        let accept = match EditDecision::try_from(request.decision) {
            Ok(EditDecision::Accept) => true,
            Ok(EditDecision::Reject) => false,
            Ok(EditDecision::Unspecified) | Err(_) => {
                return Err(WorkFault::Invalid("invalid decision").into());
            }
        };
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let bootstrap: bool = sqlx::query_scalar(IS_BOOTSTRAP)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if bootstrap {
            return Err(WorkFault::NotInteractive.into());
        }
        refresh_pending(&mut tx, user_id, project_id, Some(id)).await?;
        let row = sqlx::query(EDIT_VIEW)
            .bind(project_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(WorkFault::EditNotFound)?;
        let edit = view(&row)?;
        match EditState::try_from(edit.state).unwrap_or(EditState::Unspecified) {
            EditState::Accepted | EditState::Rejected => {
                return Err(WorkFault::Precondition(REASON_DECIDED).into());
            }
            EditState::Stale if accept => {
                tx.commit().await?;
                return Err(WorkFault::Precondition(REASON_STALE).into());
            }
            _ => {}
        }
        if accept {
            match EditKind::try_from(edit.kind).unwrap_or(EditKind::Unspecified) {
                EditKind::SliceOp => {
                    let op = parse_slice_op(&edit.payload)?;
                    apply_slice_op(&mut tx, project_id, &edit.target, op).await?;
                }
                EditKind::Pitfall => {
                    let applied = apply_pitfall(
                        &mut tx,
                        user_id,
                        project_id,
                        &edit.target,
                        &edit.payload,
                        &edit.base_hash,
                    )
                    .await?;
                    if !applied {
                        sqlx::query(MARK_STALE)
                            .bind(project_id)
                            .bind(id)
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                        return Err(WorkFault::Precondition(REASON_STALE).into());
                    }
                }
                EditKind::FilePatch | EditKind::Unspecified => {}
            }
        }
        let state = if accept { "accepted" } else { "rejected" };
        sqlx::query(MARK_DECIDED)
            .bind(project_id)
            .bind(id)
            .bind(state)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(EDIT_VIEW)
            .bind(project_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        let reply = view(&row)?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }
}

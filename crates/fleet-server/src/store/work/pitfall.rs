//! Pitfalls: known traps, user-level or tied to one project (ADR-0065).
//!
//! A pitfall without a project belongs to its user and reaches every project of that user. Each
//! call scopes by the caller's user id, so another user's pitfall is never read or counted.

use fleet_core::Redactor;
use fleet_proto::v1::{ListPitfallsReply, ListPitfallsRequest, Pitfall, RecordPitfallRequest};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use super::retro::clean_line;
use super::write::{Started, keyless};
use super::{
    MAX_CAUSE_CHARS, MAX_LIST_PITFALLS, MAX_SYMPTOM_CHARS, WorkFault, client_key, digest,
    find_project, project_name, unsigned,
};
use crate::store::{Store, StoreError};

const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE";

const FIND_PITFALL: &str = "\
SELECT id, cause, fix FROM pitfall \
WHERE user_id = $1 AND project_id IS NOT DISTINCT FROM $2::bigint AND symptom = $3 FOR UPDATE";

const INSERT_PITFALL: &str = "\
INSERT INTO pitfall (user_id, project_id, symptom, cause, fix) \
VALUES ($1, $2, $3, $4, $5) RETURNING id";

const HIT_PITFALL: &str = "\
UPDATE pitfall SET hits = hits + 1, last_hit_at = now() WHERE id = $1 AND user_id = $2";

const PITFALL_VIEW: &str = "\
SELECT p.id, w.name AS project, p.symptom, p.cause, p.fix, p.hits, \
(extract(epoch FROM p.last_hit_at) * 1000)::bigint AS hit_ms, \
(extract(epoch FROM p.created_at) * 1000)::bigint AS created_ms \
FROM pitfall p LEFT JOIN work_project w ON w.id = p.project_id AND w.user_id = p.user_id \
WHERE p.id = $1 AND p.user_id = $2";

const LIST_PITFALLS: &str = "\
SELECT p.id, w.name AS project, p.symptom, p.cause, p.fix, p.hits, \
(extract(epoch FROM p.last_hit_at) * 1000)::bigint AS hit_ms, \
(extract(epoch FROM p.created_at) * 1000)::bigint AS created_ms \
FROM pitfall p LEFT JOIN work_project w ON w.id = p.project_id AND w.user_id = p.user_id \
WHERE p.user_id = $1 AND p.project_id IS NOT DISTINCT FROM $2::bigint \
ORDER BY p.hits DESC, p.last_hit_at DESC NULLS LAST, p.id DESC LIMIT $3";

fn view(row: &PgRow) -> Result<Pitfall, StoreError> {
    let hits: i32 = row.try_get("hits")?;
    let hit: Option<i64> = row.try_get("hit_ms")?;
    Ok(Pitfall {
        id: unsigned(row.try_get("id")?)?,
        project: row.try_get("project")?,
        symptom: row.try_get("symptom")?,
        cause: row.try_get("cause")?,
        fix: row.try_get("fix")?,
        hits: u32::try_from(hits).map_err(|_| StoreError::OutOfRange("pitfall hits"))?,
        last_hit_at_ms: hit.map(unsigned).transpose()?,
        created_at_ms: unsigned(row.try_get("created_ms")?)?,
    })
}

async fn pitfall_by_id(
    conn: &mut PgConnection,
    user_id: i64,
    id: i64,
) -> Result<Pitfall, StoreError> {
    let row = sqlx::query(PITFALL_VIEW)
        .bind(id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(WorkFault::ProjectNotFound)?;
    view(&row)
}

async fn upsert(
    conn: &mut PgConnection,
    user_id: i64,
    project_id: Option<i64>,
    text: (&str, &str, &str),
) -> Result<i64, StoreError> {
    let existing: Option<(i64, String, String)> = sqlx::query_as(FIND_PITFALL)
        .bind(user_id)
        .bind(project_id)
        .bind(text.0)
        .fetch_optional(&mut *conn)
        .await?;
    let Some((id, cause, fix)) = existing else {
        return Ok(sqlx::query_scalar(INSERT_PITFALL)
            .bind(user_id)
            .bind(project_id)
            .bind(text.0)
            .bind(text.1)
            .bind(text.2)
            .fetch_one(&mut *conn)
            .await?);
    };
    if cause != text.1 || fix != text.2 {
        return Err(WorkFault::Exists("pitfall already recorded with other text").into());
    }
    sqlx::query(HIT_PITFALL)
        .bind(id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    Ok(id)
}

impl Store {
    /// Records a pitfall for the caller, tied to `project` or user-level without one.
    ///
    /// A symptom already recorded at that level with the same cause and fix counts one more hit
    /// and returns the stored pitfall. The same symptom with other text is
    /// [`WorkFault::Exists`]. A project pitfall replays by key. A user-level pitfall has no row
    /// to hold a key, so its retry counts as a hit.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] for a project that is unknown or another user's,
    /// [`WorkFault::Exists`] and [`WorkFault::Invalid`] for bad text.
    pub async fn record_pitfall(
        &self,
        user_id: i64,
        request: &RecordPitfallRequest,
        redactor: &Redactor,
    ) -> Result<Pitfall, StoreError> {
        const RPC: &str = "RecordPitfall";
        let key = client_key(&request.key)?;
        let symptom = clean_line(
            redactor,
            &request.symptom,
            MAX_SYMPTOM_CHARS,
            "invalid symptom",
        )?;
        let cause = clean_line(redactor, &request.cause, MAX_CAUSE_CHARS, "invalid cause")?;
        let fix = clean_line(redactor, &request.fix, MAX_CAUSE_CHARS, "invalid fix")?;
        let text = (symptom.as_str(), cause.as_str(), fix.as_str());
        let Some(project) = request.project.as_deref() else {
            let mut tx = self.pool.begin().await?;
            sqlx::query_scalar::<_, i64>(LOCK_USER)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(WorkFault::ProjectNotFound)?;
            let id = upsert(&mut tx, user_id, None, text).await?;
            let reply = pitfall_by_id(&mut tx, user_id, id).await?;
            tx.commit().await?;
            return Ok(reply);
        };
        project_name(project)?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let id = upsert(&mut tx, user_id, Some(project_id), text).await?;
        let reply = pitfall_by_id(&mut tx, user_id, id).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Lists the caller's pitfalls at one level: those of `project`, or the user-level ones
    /// without it. Most hit first, then most recently hit.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] and [`WorkFault::Precondition`] when more than 1000
    /// pitfalls match.
    pub async fn list_pitfalls(
        &self,
        user_id: i64,
        request: &ListPitfallsRequest,
    ) -> Result<ListPitfallsReply, StoreError> {
        let mut tx = self.begin_read().await?;
        let project_id = match request.project.as_deref() {
            None => None,
            Some(name) => Some(find_project(&mut tx, user_id, name).await?),
        };
        let rows = sqlx::query(LIST_PITFALLS)
            .bind(user_id)
            .bind(project_id)
            .bind(MAX_LIST_PITFALLS + 1)
            .fetch_all(&mut *tx)
            .await?;
        if i64::try_from(rows.len()).is_ok_and(|n| n > MAX_LIST_PITFALLS) {
            return Err(WorkFault::Precondition("too many pitfalls").into());
        }
        let pitfalls = rows.iter().map(view).collect::<Result<_, _>>()?;
        Ok(ListPitfallsReply { pitfalls })
    }
}

//! Claims, lease renewals, attempt reports, notes and the lease sweep.

use fleet_core::Redactor;
use fleet_core::text::{Cap, sanitise_lines};
use fleet_proto::v1::{
    AddWorkNoteRequest, ClaimWorkRequest, NextWorkReply, NextWorkRequest, RenewLeaseRequest,
    ReportAttemptRequest, WorkAttempt, WorkEvent, WorkVerdict,
};
use sqlx::{PgConnection, Row};

use super::load::{Snapshot, verdict_of};
use super::write::{Started, keyless};
use super::{
    DEFAULT_LEASE_TTL_SECS, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_INPUT_BYTES, MAX_LEASE_TTL_SECS,
    MAX_NOTE_BYTES, MAX_REAP_BATCH, MIN_LEASE_TTL_SECS, WorkFault, actor, client_key, digest,
    find_project, insert_event, item_key, line, lines, project_name, unsigned,
};
use crate::store::{Store, StoreError};

const INSERT_ATTEMPT: &str = "\
INSERT INTO work_attempt (project_id, item_id, holder, expires_at) \
VALUES ($1, $2, $3, now() + make_interval(secs => $4::double precision)) RETURNING id";

const INSERT_LEASES: &str = "\
INSERT INTO work_slice_lease (slice_id, project_id, attempt_id) \
SELECT m.slice_id, $1, $2 FROM work_item_slice m WHERE m.project_id = $1 AND m.item_id = $3 \
ON CONFLICT DO NOTHING";

const RENEW: &str = "\
UPDATE work_attempt SET expires_at = now() + make_interval(secs => $3::double precision) \
WHERE id = $1 AND project_id = $2 AND verdict IS NULL AND expires_at > now() \
RETURNING item_id";

const CLOSE: &str = "\
UPDATE work_attempt SET verdict = $3, note = $4, evidence = $5, closed_at = now() \
WHERE id = $1 AND project_id = $2 AND verdict IS NULL RETURNING item_id";

const ATTEMPT_CLOSED: &str =
    "SELECT verdict IS NOT NULL FROM work_attempt WHERE id = $1 AND project_id = $2";

const DELETE_LEASES: &str =
    "DELETE FROM work_slice_lease WHERE project_id = $1 AND attempt_id = $2";

const ITEM_ID: &str = "SELECT id FROM work_item WHERE project_id = $1 AND key = $2";

const ATTEMPT_VIEW: &str = "\
SELECT a.id, i.key, a.holder, a.verdict, a.note, a.evidence, \
(extract(epoch FROM a.claimed_at) * 1000)::bigint AS claimed_ms, \
(extract(epoch FROM a.expires_at) * 1000)::bigint AS expires_ms, \
(extract(epoch FROM a.closed_at) * 1000)::bigint AS closed_ms \
FROM work_attempt a JOIN work_item i ON i.id = a.item_id AND i.project_id = a.project_id \
WHERE a.id = $1 AND a.project_id = $2";

const REAP: &str = "\
WITH expired AS (\
UPDATE work_attempt SET verdict = 'lost', closed_at = now(), note = 'lease expired' \
WHERE id IN (SELECT id FROM work_attempt WHERE verdict IS NULL AND expires_at < now() \
ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED) \
RETURNING id, project_id, item_id), \
freed AS (DELETE FROM work_slice_lease WHERE attempt_id IN (SELECT id FROM expired)) \
INSERT INTO work_event (project_id, item_id, attempt_id, kind, actor, note) \
SELECT project_id, item_id, id, 'lost', 'reaper', 'lease expired' FROM expired";

/// Seconds of a lease for a request value: 0 is [`DEFAULT_LEASE_TTL_SECS`], anything else must
/// lie in [`MIN_LEASE_TTL_SECS`] to [`MAX_LEASE_TTL_SECS`].
pub(super) fn lease_ttl(secs: u32) -> Result<f64, WorkFault> {
    let secs = if secs == 0 {
        DEFAULT_LEASE_TTL_SECS
    } else {
        secs
    };
    if (MIN_LEASE_TTL_SECS..=MAX_LEASE_TTL_SECS).contains(&secs) {
        Ok(f64::from(secs))
    } else {
        Err(WorkFault::Invalid("invalid lease ttl"))
    }
}

/// Redacts first, strips hostile characters, then cuts to [`MAX_EVIDENCE_BYTES`], so a secret
/// straddling the cap is masked whole and leaves no prefix.
pub(super) fn evidence(redactor: &Redactor, raw: &str) -> Result<String, WorkFault> {
    if raw.len() > MAX_EVIDENCE_INPUT_BYTES {
        return Err(WorkFault::Invalid("evidence too long"));
    }
    Ok(sanitise_lines(redactor, raw, Cap::Bytes(MAX_EVIDENCE_BYTES)).text)
}

fn note_text(text: &str) -> Result<&str, WorkFault> {
    if text.trim().is_empty() || !lines(text, MAX_NOTE_BYTES) {
        return Err(WorkFault::Invalid("invalid note"));
    }
    Ok(text)
}

async fn item_id(conn: &mut PgConnection, project_id: i64, key: &str) -> Result<i64, StoreError> {
    sqlx::query_scalar(ITEM_ID)
        .bind(project_id)
        .bind(key)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| WorkFault::ItemNotFound.into())
}

fn attempt_id(raw: u64) -> Result<i64, WorkFault> {
    i64::try_from(raw).map_err(|_| WorkFault::Invalid("invalid attempt id"))
}

async fn why_not_open(
    conn: &mut PgConnection,
    project_id: i64,
    attempt: i64,
    expired: &'static str,
) -> StoreError {
    let closed: Result<Option<bool>, sqlx::Error> = sqlx::query_scalar(ATTEMPT_CLOSED)
        .bind(attempt)
        .bind(project_id)
        .fetch_optional(&mut *conn)
        .await;
    match closed {
        Err(err) => err.into(),
        Ok(None) => WorkFault::AttemptNotFound.into(),
        Ok(Some(true)) => WorkFault::Precondition("attempt is closed").into(),
        Ok(Some(false)) => WorkFault::Precondition(expired).into(),
    }
}

async fn attempt_view(
    conn: &mut PgConnection,
    project_id: i64,
    attempt: i64,
) -> Result<WorkAttempt, StoreError> {
    let row = sqlx::query(ATTEMPT_VIEW)
        .bind(attempt)
        .bind(project_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(WorkFault::AttemptNotFound)?;
    let verdict: Option<String> = row.try_get("verdict")?;
    let closed: Option<i64> = row.try_get("closed_ms")?;
    Ok(WorkAttempt {
        id: unsigned(row.try_get("id")?)?,
        item_key: row.try_get("key")?,
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
    })
}

impl Store {
    /// The first ready item of a project by creation order, `None` when nothing is ready.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] for an unknown or foreign project.
    pub async fn next_work(
        &self,
        user_id: i64,
        request: &NextWorkRequest,
    ) -> Result<NextWorkReply, StoreError> {
        project_name(&request.project)?;
        let mut tx = self.begin_read().await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let snapshot = Snapshot::load(&mut tx, project_id).await?;
        let item = snapshot.views()?.into_iter().find(|item| item.ready);
        Ok(NextWorkReply { item })
    }

    /// Claims a ready item: inserts the attempt and one lease per slice of the item in one
    /// transaction under the project row lock.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ItemNotFound`], [`WorkFault::Invalid`] for a bad holder or a `ttl_secs`
    /// outside the lease range, and [`WorkFault::Precondition`] when the item is cancelled,
    /// blocked or not ready, or a slice already carries a lease. Nothing is written then.
    pub async fn claim_work(
        &self,
        user_id: i64,
        request: &ClaimWorkRequest,
    ) -> Result<WorkAttempt, StoreError> {
        const RPC: &str = "ClaimWork";
        let key = client_key(&request.key)?;
        let name = item_key(&request.item_key)?;
        if !line(&request.holder, 128) {
            return Err(WorkFault::Invalid("invalid holder").into());
        }
        let ttl = lease_ttl(request.ttl_secs)?;
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
        match item.state.as_str() {
            "cancelled" => return Err(WorkFault::Precondition("work item is cancelled").into()),
            "blocked" => return Err(WorkFault::Precondition("work item is blocked").into()),
            _ => {}
        }
        if !snapshot.is_ready(name) {
            return Err(WorkFault::Precondition("work item is not ready").into());
        }
        let item_id = item.id;
        let wanted = snapshot.view_of(name)?.slices.len();
        let attempt: i64 = sqlx::query_scalar(INSERT_ATTEMPT)
            .bind(project_id)
            .bind(item_id)
            .bind(&request.holder)
            .bind(ttl)
            .fetch_one(&mut *tx)
            .await?;
        let leased = sqlx::query(INSERT_LEASES)
            .bind(project_id)
            .bind(attempt)
            .bind(item_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if usize::try_from(leased).ok() != Some(wanted) {
            return Err(WorkFault::Precondition("slice is leased").into());
        }
        insert_event(
            &mut tx,
            project_id,
            Some(item_id),
            Some(attempt),
            "claimed",
            &actor(user_id),
            &request.holder,
        )
        .await?;
        let reply = attempt_view(&mut tx, project_id, attempt).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Extends the lease of an open attempt to `ttl_secs` from now on the database clock.
    ///
    /// # Errors
    ///
    /// [`WorkFault::AttemptNotFound`], [`WorkFault::Invalid`] for a `ttl_secs` outside the lease
    /// range and [`WorkFault::Precondition`] for a closed attempt or a lease already past its
    /// expiry.
    pub async fn renew_lease(
        &self,
        user_id: i64,
        request: &RenewLeaseRequest,
    ) -> Result<WorkAttempt, StoreError> {
        const RPC: &str = "RenewLease";
        let key = client_key(&request.key)?;
        let attempt = attempt_id(request.attempt_id)?;
        let ttl = lease_ttl(request.ttl_secs)?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let item: Option<i64> = sqlx::query_scalar(RENEW)
            .bind(attempt)
            .bind(project_id)
            .bind(ttl)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(item) = item else {
            return Err(why_not_open(&mut tx, project_id, attempt, "lease expired").await);
        };
        insert_event(
            &mut tx,
            project_id,
            Some(item),
            Some(attempt),
            "renewed",
            &actor(user_id),
            "",
        )
        .await?;
        let reply = attempt_view(&mut tx, project_id, attempt).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Closes an open attempt with a pass or fail verdict, frees its leases and keeps the
    /// evidence cut to [`MAX_EVIDENCE_BYTES`] after `redactor` ran over it.
    ///
    /// # Errors
    ///
    /// [`WorkFault::AttemptNotFound`], [`WorkFault::Invalid`] for a verdict other than pass or
    /// fail, a bad note or evidence over [`MAX_EVIDENCE_INPUT_BYTES`], and
    /// [`WorkFault::Precondition`] for a closed attempt.
    pub async fn report_attempt(
        &self,
        user_id: i64,
        request: &ReportAttemptRequest,
        redactor: &Redactor,
    ) -> Result<WorkAttempt, StoreError> {
        const RPC: &str = "ReportAttempt";
        let key = client_key(&request.key)?;
        let attempt = attempt_id(request.attempt_id)?;
        let (verdict, kind) = match WorkVerdict::try_from(request.verdict) {
            Ok(WorkVerdict::Pass) => ("pass", "passed"),
            Ok(WorkVerdict::Fail) => ("fail", "failed"),
            _ => return Err(WorkFault::Invalid("invalid verdict").into()),
        };
        let note = if request.note.is_empty() {
            ""
        } else {
            note_text(&request.note)?
        };
        let kept = evidence(redactor, &request.evidence_tail)?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let item: Option<i64> = sqlx::query_scalar(CLOSE)
            .bind(attempt)
            .bind(project_id)
            .bind(verdict)
            .bind(note)
            .bind(&kept)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(item) = item else {
            return Err(why_not_open(&mut tx, project_id, attempt, "attempt is open").await);
        };
        sqlx::query(DELETE_LEASES)
            .bind(project_id)
            .bind(attempt)
            .execute(&mut *tx)
            .await?;
        insert_event(
            &mut tx,
            project_id,
            Some(item),
            Some(attempt),
            kind,
            &actor(user_id),
            note,
        )
        .await?;
        let reply = attempt_view(&mut tx, project_id, attempt).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Adds a note to the timeline of an item.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ItemNotFound`] and [`WorkFault::Invalid`] for a blank, long or hostile note.
    pub async fn add_work_note(
        &self,
        user_id: i64,
        request: &AddWorkNoteRequest,
    ) -> Result<WorkEvent, StoreError> {
        const RPC: &str = "AddWorkNote";
        let key = client_key(&request.key)?;
        let name = item_key(&request.item_key)?;
        let note = note_text(&request.note)?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let item = item_id(&mut tx, project_id, name).await?;
        let who = actor(user_id);
        let (id, at_ms) =
            insert_event(&mut tx, project_id, Some(item), None, "note", &who, note).await?;
        let reply = WorkEvent {
            id: unsigned(id)?,
            item_key: Some(name.to_owned()),
            attempt_id: None,
            kind: "note".to_owned(),
            actor: who,
            note: note.to_owned(),
            at_ms: unsigned(at_ms)?,
        };
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Closes up to [`MAX_REAP_BATCH`] open attempts past their expiry as lost, frees their
    /// leases and records a `lost` event for each. Returns the attempts closed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] when the statement fails.
    pub async fn reap_work_leases(&self) -> Result<u64, StoreError> {
        let done = sqlx::query(REAP)
            .bind(MAX_REAP_BATCH)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }
}

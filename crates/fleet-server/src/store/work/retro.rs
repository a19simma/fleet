//! Retros and improvements (ADR-0065).
//!
//! Every write takes the `work_project` row `FOR UPDATE` first through `begin_graph_write`, so a
//! filing, a disposition and a close queue on one lock. A close reads the undecided count under
//! that lock, and a filing that races it either lands before the count or sees the retro closed.

use fleet_core::Redactor;
use fleet_core::text::{Cap, sanitise_lines, sanitise_text};
use fleet_proto::v1::{
    CloseRetroRequest, DispositionImprovementRequest, FileImprovementRequest, Improvement,
    ImprovementDisposition, ImprovementKind, ListImprovementsReply, ListImprovementsRequest,
    ListRetrosReply, ListRetrosRequest, OpenRetroRequest, Retro, RetroState,
};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use super::write::{Started, keyless};
use super::{
    MAX_BODY_BYTES, MAX_LIST_IMPROVEMENTS, MAX_LIST_RETROS, MAX_NOTE_BYTES, MAX_OCCURRENCES,
    MAX_REASON_CHARS, MAX_TEXT_INPUT_BYTES, MAX_TITLE_CHARS, MAX_VERTICAL_CHARS, WorkFault,
    client_key, digest, find_project, item_key, line, project_name, unsigned,
};
use crate::store::{Store, StoreError};

const ITEM_ID: &str = "SELECT id FROM work_item WHERE project_id = $1 AND key = $2";

const INSERT_RETRO: &str = "\
INSERT INTO retro (project_id, title, span_from_item_id, span_to_item_id) \
VALUES ($1, $2, $3, $4) RETURNING id";

const RETRO_VIEW: &str = "\
SELECT r.id, r.title, r.state, f.key AS from_key, t.key AS to_key, \
(extract(epoch FROM r.opened_at) * 1000)::bigint AS opened_ms, \
(extract(epoch FROM r.closed_at) * 1000)::bigint AS closed_ms \
FROM retro r \
LEFT JOIN work_item f ON f.id = r.span_from_item_id AND f.project_id = r.project_id \
LEFT JOIN work_item t ON t.id = r.span_to_item_id AND t.project_id = r.project_id \
WHERE r.id = $1 AND r.project_id = $2";

const LIST_RETROS: &str = "\
SELECT r.id, r.title, r.state, f.key AS from_key, t.key AS to_key, \
(extract(epoch FROM r.opened_at) * 1000)::bigint AS opened_ms, \
(extract(epoch FROM r.closed_at) * 1000)::bigint AS closed_ms \
FROM retro r \
LEFT JOIN work_item f ON f.id = r.span_from_item_id AND f.project_id = r.project_id \
LEFT JOIN work_item t ON t.id = r.span_to_item_id AND t.project_id = r.project_id \
WHERE r.project_id = $1 AND ($2::text IS NULL OR r.state = $2) ORDER BY r.id LIMIT $3";

const LOCK_RETRO: &str = "SELECT state FROM retro WHERE id = $1 AND project_id = $2 FOR UPDATE";

const UNDECIDED: &str = "\
SELECT count(*) FROM improvement \
WHERE project_id = $1 AND retro_id = $2 AND disposition IS NULL";

const CLOSE_RETRO: &str = "\
UPDATE retro SET state = 'closed', closed_at = now() WHERE id = $1 AND project_id = $2";

const FIND_IMPROVEMENT: &str =
    "SELECT id FROM improvement WHERE project_id = $1 AND title = $2 FOR UPDATE";

const INSERT_IMPROVEMENT: &str = "\
INSERT INTO improvement (project_id, retro_id, item_id, vertical, title, body, kind) \
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id";

const BUMP_OCCURRENCES: &str = "\
UPDATE improvement SET occurrences = occurrences + 1 \
WHERE id = $1 AND project_id = $2 AND occurrences < $3";

const INSERT_OCCURRENCE: &str = "\
INSERT INTO improvement_occurrence (project_id, improvement_id, attempt_id, retro_id, note) \
SELECT $1, $2, $3, $4, $5 \
WHERE $3::bigint IS NULL OR EXISTS (\
SELECT 1 FROM work_attempt WHERE id = $3 AND project_id = $1) RETURNING id";

const IMPROVEMENT_VIEW: &str = "\
SELECT i.id, i.retro_id, it.key AS item_key, i.vertical, i.title, i.body, i.kind, \
i.occurrences, i.disposition, i.disposition_reason, \
(extract(epoch FROM i.created_at) * 1000)::bigint AS created_ms \
FROM improvement i \
LEFT JOIN work_item it ON it.id = i.item_id AND it.project_id = i.project_id \
WHERE i.id = $1 AND i.project_id = $2";

const LIST_IMPROVEMENTS: &str = "\
SELECT i.id, i.retro_id, it.key AS item_key, i.vertical, i.title, i.body, i.kind, \
i.occurrences, i.disposition, i.disposition_reason, \
(extract(epoch FROM i.created_at) * 1000)::bigint AS created_ms \
FROM improvement i \
LEFT JOIN work_item it ON it.id = i.item_id AND it.project_id = i.project_id \
WHERE i.project_id = $1 AND ($2::text IS NULL OR i.vertical = $2) \
AND ($3::bigint IS NULL OR i.retro_id = $3) \
AND ($4::boolean IS NULL OR (i.disposition IS NULL) = $4) \
ORDER BY i.occurrences DESC, i.id LIMIT $5";

const LOCK_IMPROVEMENT: &str =
    "SELECT disposition FROM improvement WHERE id = $1 AND project_id = $2 FOR UPDATE";

const SET_DISPOSITION: &str = "\
UPDATE improvement SET disposition = $3, disposition_reason = $4 \
WHERE id = $1 AND project_id = $2";

/// One line of free text: redacted, stripped of hostile characters, then cut to `max` chars. A
/// secret straddling the cut is masked whole. Text blank after cleaning is refused.
pub(super) fn clean_line(
    redactor: &Redactor,
    raw: &str,
    max: usize,
    what: &'static str,
) -> Result<String, WorkFault> {
    if raw.len() > MAX_TEXT_INPUT_BYTES {
        return Err(WorkFault::Invalid(what));
    }
    let text = sanitise_text(redactor, raw, Cap::Chars(max)).text;
    if text.trim().is_empty() {
        return Err(WorkFault::Invalid(what));
    }
    Ok(text)
}

fn clean_body(redactor: &Redactor, raw: &str, max: usize) -> Result<String, WorkFault> {
    if raw.len() > MAX_TEXT_INPUT_BYTES {
        return Err(WorkFault::Invalid("text too long"));
    }
    Ok(sanitise_lines(redactor, raw, Cap::Bytes(max)).text)
}

pub(super) fn row_id(raw: u64, what: &'static str) -> Result<i64, WorkFault> {
    i64::try_from(raw).map_err(|_| WorkFault::Invalid(what))
}

fn retro_state_of(text: &str) -> Result<RetroState, StoreError> {
    match text {
        "open" => Ok(RetroState::Open),
        "closed" => Ok(RetroState::Closed),
        _ => Err(StoreError::OutOfRange("retro state")),
    }
}

fn kind_name(kind: ImprovementKind) -> Option<&'static str> {
    match kind {
        ImprovementKind::Process => Some("process"),
        ImprovementKind::Tooling => Some("tooling"),
        ImprovementKind::Docs => Some("docs"),
        ImprovementKind::Test => Some("test"),
        ImprovementKind::Pitfall => Some("pitfall"),
        ImprovementKind::Other => Some("other"),
        ImprovementKind::Unspecified => None,
    }
}

fn kind_of(text: &str) -> Result<ImprovementKind, StoreError> {
    [
        ImprovementKind::Process,
        ImprovementKind::Tooling,
        ImprovementKind::Docs,
        ImprovementKind::Test,
        ImprovementKind::Pitfall,
        ImprovementKind::Other,
    ]
    .into_iter()
    .find(|kind| kind_name(*kind) == Some(text))
    .ok_or(StoreError::OutOfRange("improvement kind"))
}

fn disposition_name(value: ImprovementDisposition) -> Option<&'static str> {
    match value {
        ImprovementDisposition::Accepted => Some("accepted"),
        ImprovementDisposition::Rejected => Some("rejected"),
        ImprovementDisposition::Deferred => Some("deferred"),
        ImprovementDisposition::Applied => Some("applied"),
        ImprovementDisposition::Unspecified => None,
    }
}

fn disposition_of(text: &str) -> Result<ImprovementDisposition, StoreError> {
    [
        ImprovementDisposition::Accepted,
        ImprovementDisposition::Rejected,
        ImprovementDisposition::Deferred,
        ImprovementDisposition::Applied,
    ]
    .into_iter()
    .find(|value| disposition_name(*value) == Some(text))
    .ok_or(StoreError::OutOfRange("improvement disposition"))
}

fn retro_view(row: &PgRow) -> Result<Retro, StoreError> {
    let state: String = row.try_get("state")?;
    let closed: Option<i64> = row.try_get("closed_ms")?;
    Ok(Retro {
        id: unsigned(row.try_get("id")?)?,
        title: row.try_get("title")?,
        state: retro_state_of(&state)? as i32,
        span_from_item_key: row.try_get("from_key")?,
        span_to_item_key: row.try_get("to_key")?,
        opened_at_ms: unsigned(row.try_get("opened_ms")?)?,
        closed_at_ms: closed.map(unsigned).transpose()?,
    })
}

fn improvement_view(row: &PgRow) -> Result<Improvement, StoreError> {
    let retro: Option<i64> = row.try_get("retro_id")?;
    let kind: String = row.try_get("kind")?;
    let occurrences: i32 = row.try_get("occurrences")?;
    let disposition: Option<String> = row.try_get("disposition")?;
    Ok(Improvement {
        id: unsigned(row.try_get("id")?)?,
        retro_id: retro.map(unsigned).transpose()?,
        item_key: row.try_get("item_key")?,
        vertical: row.try_get("vertical")?,
        title: row.try_get("title")?,
        body: row.try_get("body")?,
        kind: kind_of(&kind)? as i32,
        occurrences: u32::try_from(occurrences)
            .map_err(|_| StoreError::OutOfRange("improvement occurrences"))?,
        disposition: disposition
            .as_deref()
            .map(disposition_of)
            .transpose()?
            .map(|value| value as i32),
        disposition_reason: row.try_get("disposition_reason")?,
        created_at_ms: unsigned(row.try_get("created_ms")?)?,
    })
}

async fn retro_by_id(
    conn: &mut PgConnection,
    project_id: i64,
    id: i64,
) -> Result<Retro, StoreError> {
    let row = sqlx::query(RETRO_VIEW)
        .bind(id)
        .bind(project_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(WorkFault::RetroNotFound)?;
    retro_view(&row)
}

async fn improvement_by_id(
    conn: &mut PgConnection,
    project_id: i64,
    id: i64,
) -> Result<Improvement, StoreError> {
    let row = sqlx::query(IMPROVEMENT_VIEW)
        .bind(id)
        .bind(project_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(WorkFault::ImprovementNotFound)?;
    improvement_view(&row)
}

async fn optional_item(
    conn: &mut PgConnection,
    project_id: i64,
    key: Option<&str>,
) -> Result<Option<i64>, StoreError> {
    let Some(name) = key else {
        return Ok(None);
    };
    let found: Option<i64> = sqlx::query_scalar(ITEM_ID)
        .bind(project_id)
        .bind(item_key(name)?)
        .fetch_optional(&mut *conn)
        .await?;
    found
        .map(Some)
        .ok_or_else(|| WorkFault::ItemNotFound.into())
}

/// Locks a retro of the project and returns its state, so a close cannot interleave.
async fn lock_retro(
    conn: &mut PgConnection,
    project_id: i64,
    id: i64,
) -> Result<String, StoreError> {
    sqlx::query_scalar(LOCK_RETRO)
        .bind(id)
        .bind(project_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| WorkFault::RetroNotFound.into())
}

struct Filing<'a> {
    project_id: i64,
    retro: Option<i64>,
    item: Option<i64>,
    attempt: Option<i64>,
    vertical: &'a str,
    title: &'a str,
    body: &'a str,
    kind: &'static str,
}

fn note_of(body: &str) -> &str {
    let end = (0..=MAX_NOTE_BYTES.min(body.len()))
        .rev()
        .find(|&i| body.is_char_boundary(i))
        .unwrap_or(0);
    &body[..end]
}

/// Files one improvement. A title already filed in the project gets one more occurrence row and
/// a raised count; a new title gets its first row and a count of 1. Both writes share the
/// caller's transaction, and the project row lock held by the caller keeps two filings of one
/// title from counting the same occurrence.
async fn file(conn: &mut PgConnection, filing: &Filing<'_>) -> Result<i64, StoreError> {
    let existing: Option<i64> = sqlx::query_scalar(FIND_IMPROVEMENT)
        .bind(filing.project_id)
        .bind(filing.title)
        .fetch_optional(&mut *conn)
        .await?;
    let id = if let Some(id) = existing {
        let bumped = sqlx::query(BUMP_OCCURRENCES)
            .bind(id)
            .bind(filing.project_id)
            .bind(MAX_OCCURRENCES)
            .execute(&mut *conn)
            .await?;
        if bumped.rows_affected() == 0 {
            return Err(WorkFault::Precondition("improvement occurrence limit reached").into());
        }
        id
    } else {
        sqlx::query_scalar(INSERT_IMPROVEMENT)
            .bind(filing.project_id)
            .bind(filing.retro)
            .bind(filing.item)
            .bind(filing.vertical)
            .bind(filing.title)
            .bind(filing.body)
            .bind(filing.kind)
            .fetch_one(&mut *conn)
            .await?
    };
    sqlx::query_scalar::<_, i64>(INSERT_OCCURRENCE)
        .bind(filing.project_id)
        .bind(id)
        .bind(filing.attempt)
        .bind(filing.retro)
        .bind(note_of(filing.body))
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(WorkFault::AttemptNotFound)?;
    Ok(id)
}

impl Store {
    /// Opens a retro over an optional span of items of the project.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`], [`WorkFault::ItemNotFound`] for a span key that is not an
    /// item of the project and [`WorkFault::Invalid`] for a bad title or key.
    pub async fn open_retro(
        &self,
        user_id: i64,
        request: &OpenRetroRequest,
        redactor: &Redactor,
    ) -> Result<Retro, StoreError> {
        const RPC: &str = "OpenRetro";
        let key = client_key(&request.key)?;
        project_name(&request.project)?;
        let title = clean_line(redactor, &request.title, MAX_TITLE_CHARS, "invalid title")?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let from =
            optional_item(&mut tx, project_id, request.span_from_item_key.as_deref()).await?;
        let to = optional_item(&mut tx, project_id, request.span_to_item_key.as_deref()).await?;
        let id: i64 = sqlx::query_scalar(INSERT_RETRO)
            .bind(project_id)
            .bind(title)
            .bind(from)
            .bind(to)
            .fetch_one(&mut *tx)
            .await?;
        let reply = retro_by_id(&mut tx, project_id, id).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Closes a retro once every improvement filed into it has a disposition.
    ///
    /// # Errors
    ///
    /// [`WorkFault::RetroNotFound`], [`WorkFault::Precondition`] for a retro already closed and
    /// [`WorkFault::Undecided`] with the count of improvements still lacking a disposition.
    pub async fn close_retro(
        &self,
        user_id: i64,
        request: &CloseRetroRequest,
    ) -> Result<Retro, StoreError> {
        const RPC: &str = "CloseRetro";
        let key = client_key(&request.key)?;
        let retro = row_id(request.retro_id, "invalid retro id")?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        if lock_retro(&mut tx, project_id, retro).await? != "open" {
            return Err(WorkFault::Precondition("retro is already closed").into());
        }
        let undecided: i64 = sqlx::query_scalar(UNDECIDED)
            .bind(project_id)
            .bind(retro)
            .fetch_one(&mut *tx)
            .await?;
        if undecided > 0 {
            return Err(WorkFault::Undecided(undecided).into());
        }
        sqlx::query(CLOSE_RETRO)
            .bind(retro)
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
        let reply = retro_by_id(&mut tx, project_id, retro).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Lists the retros of a project by id, optionally by state.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`], [`WorkFault::Invalid`] for an unspecified state filter and
    /// [`WorkFault::Precondition`] when more than 1000 retros match.
    pub async fn list_retros(
        &self,
        user_id: i64,
        request: &ListRetrosRequest,
    ) -> Result<ListRetrosReply, StoreError> {
        let wanted = match request.state {
            None => None,
            Some(raw) => match RetroState::try_from(raw) {
                Ok(RetroState::Open) => Some("open"),
                Ok(RetroState::Closed) => Some("closed"),
                Ok(RetroState::Unspecified) | Err(_) => {
                    return Err(WorkFault::Invalid("invalid state filter").into());
                }
            },
        };
        let mut tx = self.begin_read().await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let rows = sqlx::query(LIST_RETROS)
            .bind(project_id)
            .bind(wanted)
            .bind(MAX_LIST_RETROS + 1)
            .fetch_all(&mut *tx)
            .await?;
        if i64::try_from(rows.len()).is_ok_and(|n| n > MAX_LIST_RETROS) {
            return Err(WorkFault::Precondition("too many retros, filter by state").into());
        }
        let retros = rows.iter().map(retro_view).collect::<Result<_, _>>()?;
        Ok(ListRetrosReply { retros })
    }

    /// Files an improvement, or adds an occurrence to the improvement of the same title.
    ///
    /// # Errors
    ///
    /// [`WorkFault::RetroNotFound`] for a retro of another project, [`WorkFault::Precondition`]
    /// for a closed retro or a count at its limit, [`WorkFault::ItemNotFound`],
    /// [`WorkFault::AttemptNotFound`] and [`WorkFault::Invalid`] for bad text or ids.
    pub async fn file_improvement(
        &self,
        user_id: i64,
        request: &FileImprovementRequest,
        redactor: &Redactor,
    ) -> Result<Improvement, StoreError> {
        const RPC: &str = "FileImprovement";
        let key = client_key(&request.key)?;
        project_name(&request.project)?;
        let title = clean_line(redactor, &request.title, MAX_TITLE_CHARS, "invalid title")?;
        let body = clean_body(redactor, &request.body, MAX_BODY_BYTES)?;
        if !line(&request.vertical, MAX_VERTICAL_CHARS) {
            return Err(WorkFault::Invalid("invalid vertical").into());
        }
        let kind = ImprovementKind::try_from(request.kind)
            .ok()
            .and_then(kind_name)
            .ok_or(WorkFault::Invalid("invalid kind"))?;
        let retro = request
            .retro_id
            .map(|raw| row_id(raw, "invalid retro id"))
            .transpose()?;
        let attempt = request
            .attempt_id
            .map(|raw| row_id(raw, "invalid attempt id"))
            .transpose()?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        if let Some(id) = retro
            && lock_retro(&mut tx, project_id, id).await? != "open"
        {
            return Err(WorkFault::Precondition("retro is closed").into());
        }
        let item = optional_item(&mut tx, project_id, request.item_key.as_deref()).await?;
        let id = file(
            &mut tx,
            &Filing {
                project_id,
                retro,
                item,
                attempt,
                vertical: &request.vertical,
                title: &title,
                body: &body,
                kind,
            },
        )
        .await?;
        let reply = improvement_by_id(&mut tx, project_id, id).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }

    /// Lists improvements of a project, most often filed first.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`], [`WorkFault::Invalid`] for a bad filter and
    /// [`WorkFault::Precondition`] when more than 1000 improvements match.
    pub async fn list_improvements(
        &self,
        user_id: i64,
        request: &ListImprovementsRequest,
    ) -> Result<ListImprovementsReply, StoreError> {
        let area = match request.vertical.as_deref() {
            None => None,
            Some(text) if line(text, MAX_VERTICAL_CHARS) => Some(text),
            Some(_) => return Err(WorkFault::Invalid("invalid vertical").into()),
        };
        let retro = request
            .retro_id
            .map(|raw| row_id(raw, "invalid retro id"))
            .transpose()?;
        let mut tx = self.begin_read().await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let rows = sqlx::query(LIST_IMPROVEMENTS)
            .bind(project_id)
            .bind(area)
            .bind(retro)
            .bind(request.undecided)
            .bind(MAX_LIST_IMPROVEMENTS + 1)
            .fetch_all(&mut *tx)
            .await?;
        if i64::try_from(rows.len()).is_ok_and(|n| n > MAX_LIST_IMPROVEMENTS) {
            return Err(WorkFault::Precondition("too many improvements, add a filter").into());
        }
        let improvements = rows
            .iter()
            .map(improvement_view)
            .collect::<Result<_, _>>()?;
        Ok(ListImprovementsReply { improvements })
    }

    /// Records the disposition of an improvement. A rejected or applied improvement is final;
    /// a deferred or accepted one can move on.
    ///
    /// # Errors
    ///
    /// [`WorkFault::ImprovementNotFound`], [`WorkFault::Invalid`] for an unspecified
    /// disposition or a bad reason and [`WorkFault::Precondition`] for a final improvement.
    pub async fn disposition_improvement(
        &self,
        user_id: i64,
        request: &DispositionImprovementRequest,
        redactor: &Redactor,
    ) -> Result<Improvement, StoreError> {
        const RPC: &str = "DispositionImprovement";
        let key = client_key(&request.key)?;
        let id = row_id(request.improvement_id, "invalid improvement id")?;
        let wanted = ImprovementDisposition::try_from(request.disposition)
            .ok()
            .and_then(disposition_name)
            .ok_or(WorkFault::Invalid("invalid disposition"))?;
        let why = clean_line(
            redactor,
            &request.reason,
            MAX_REASON_CHARS,
            "invalid reason",
        )?;
        let request_digest = digest(RPC, &keyless(request, |r| r.key.clear()));
        let (mut tx, project_id) = match self
            .begin_graph_write(user_id, &request.project, key, RPC, &request_digest)
            .await?
        {
            Started::Replayed(reply) => return Ok(reply),
            Started::Fresh(tx, project_id) => (tx, project_id),
        };
        let current: Option<String> = sqlx::query_scalar::<_, Option<String>>(LOCK_IMPROVEMENT)
            .bind(id)
            .bind(project_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(WorkFault::ImprovementNotFound)?;
        if matches!(current.as_deref(), Some("rejected" | "applied")) {
            return Err(WorkFault::Precondition("improvement is final").into());
        }
        sqlx::query(SET_DISPOSITION)
            .bind(id)
            .bind(project_id)
            .bind(wanted)
            .bind(why)
            .execute(&mut *tx)
            .await?;
        let reply = improvement_by_id(&mut tx, project_id, id).await?;
        Self::finish_graph_write(tx, project_id, key, RPC, &request_digest, &reply).await?;
        Ok(reply)
    }
}

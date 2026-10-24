//! Postgres storage: ingest transaction, heartbeat upsert and fleet read model.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use fleet_core::{BoxName, Envelope};
use fleet_proto::v1::{BoxStatus, BoxView, HeartbeatRequest, SessionState, SessionView};
use serde_json::json;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::projection::{Projection, State, project};

const INSERT_EVENTS: &str = "\
INSERT INTO events (box, id, boot_id, seq, schema_version, source, kind, captured_at_ms, \
    occurred_at_ms, session_id, prompt_id, workdir, payload) \
SELECT t.box, t.id, t.boot_id, t.seq, t.schema_version, t.source, t.kind, t.captured_at_ms, \
    t.occurred_at_ms, t.session_id, t.prompt_id, t.workdir, t.payload::jsonb \
FROM UNNEST($1::text[], $2::text[], $3::text[], $4::bigint[], $5::integer[], $6::text[], \
    $7::text[], $8::bigint[], $9::bigint[], $10::text[], $11::text[], $12::text[], $13::text[]) \
    AS t(box, id, boot_id, seq, schema_version, source, kind, captured_at_ms, occurred_at_ms, \
    session_id, prompt_id, workdir, payload) \
ON CONFLICT (box, id) DO NOTHING \
RETURNING box, id";

const UPSERT_SESSION: &str = "\
INSERT INTO sessions AS s (box, session_id, kind, state, state_at, workdir, last_prompt, \
    last_message, last_notification, last_event_at, last_event_kind) \
VALUES ($1, $2, $3, $4::text, \
    LEAST(to_timestamp($5::bigint::double precision / 1000.0), now()), \
    $6::text, $7::text, $8::text, $9::text, \
    LEAST(to_timestamp($5::bigint::double precision / 1000.0), now()), $10::text) \
ON CONFLICT (box, session_id) DO UPDATE SET \
    state = CASE WHEN $11::boolean AND (s.state <> 'ended' OR $12::boolean) \
        THEN EXCLUDED.state ELSE s.state END, \
    state_at = CASE WHEN $11::boolean AND (s.state <> 'ended' OR $12::boolean) \
        AND s.state <> EXCLUDED.state THEN EXCLUDED.state_at ELSE s.state_at END, \
    workdir = COALESCE(EXCLUDED.workdir, s.workdir), \
    last_prompt = COALESCE(EXCLUDED.last_prompt, s.last_prompt), \
    last_message = COALESCE(EXCLUDED.last_message, s.last_message), \
    last_notification = COALESCE(EXCLUDED.last_notification, s.last_notification), \
    last_event_at = GREATEST(s.last_event_at, EXCLUDED.last_event_at), \
    last_event_kind = CASE WHEN EXCLUDED.last_event_at >= s.last_event_at \
        THEN EXCLUDED.last_event_kind ELSE s.last_event_kind END";

const TOUCH_BOX: &str = "\
INSERT INTO boxes AS b (box, hostname, machine_id, boot_id, last_event_at) \
VALUES ($1, $2, $3, $4, now()) \
ON CONFLICT (box) DO UPDATE SET hostname = EXCLUDED.hostname, \
    machine_id = EXCLUDED.machine_id, boot_id = EXCLUDED.boot_id, last_event_at = now()";

const UPSERT_HEARTBEAT: &str = "\
INSERT INTO boxes AS b (box, hostname, machine_id, boot_id, fleetd_version, \
    last_heartbeat_at, state) \
VALUES ($1, $2, $3, $4, $5, now(), $6::text::jsonb) \
ON CONFLICT (box) DO UPDATE SET hostname = EXCLUDED.hostname, \
    machine_id = EXCLUDED.machine_id, boot_id = EXCLUDED.boot_id, \
    fleetd_version = EXCLUDED.fleetd_version, last_heartbeat_at = now(), \
    state = EXCLUDED.state";

const LIST_BOXES: &str = "\
SELECT box, hostname, boot_id, fleetd_version, \
    state->>'queue_pending' AS queue_pending, \
    state->>'queue_oldest_age_s' AS queue_oldest_age_s, \
    CASE WHEN last_heartbeat_at IS NULL THEN NULL \
        ELSE GREATEST(EXTRACT(EPOCH FROM (now() - last_heartbeat_at)), 0)::bigint END \
        AS heartbeat_age_s, \
    CASE WHEN last_heartbeat_at IS NULL THEN 'unknown' \
        WHEN now() - last_heartbeat_at < interval '90 seconds' THEN 'live' \
        WHEN now() - last_heartbeat_at < interval '10 minutes' THEN 'stale' \
        ELSE 'lost' END AS status \
FROM boxes \
WHERE $1::text IS NULL OR box = $1 \
ORDER BY box";

const LIST_SESSIONS: &str = "\
SELECT box, session_id, kind, state, workdir, last_prompt, last_message, \
    GREATEST(EXTRACT(EPOCH FROM (now() - state_at)), 0)::bigint AS state_age_s, \
    GREATEST(EXTRACT(EPOCH FROM (now() - last_event_at)), 0)::bigint AS last_event_age_s \
FROM sessions \
WHERE $1::text IS NULL OR box = $1 \
ORDER BY box, last_event_at DESC, session_id";

const NOW_MS: &str = "SELECT (EXTRACT(EPOCH FROM now()) * 1000)::bigint";

/// Why a store call failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// Postgres or the connection pool failed.
    Database(sqlx::Error),
    /// Applying the embedded migrations failed.
    Migrate(sqlx::migrate::MigrateError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(err) => write!(f, "database error: {err}"),
            Self::Migrate(err) => write!(f, "migration error: {err}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(err) => Some(err),
            Self::Migrate(err) => Some(err),
        }
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

impl From<sqlx::migrate::MigrateError> for StoreError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::Migrate(err)
    }
}

/// Result of one [`Store::ingest`] call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IngestOutcome {
    /// Events inserted for the first time.
    pub stored: u32,
    /// Events whose `(box, id)` was already stored.
    pub duplicate: u32,
    /// Events the store refused, as `(seq, reason)`.
    pub rejected: Vec<(u64, String)>,
}

struct Prepared {
    seq: i64,
    captured_at_ms: i64,
    occurred_at_ms: Option<i64>,
    schema_version: i32,
    payload: String,
    envelope: Envelope,
}

fn has_nul(env: &Envelope, payload: &str) -> bool {
    let fields = [
        env.box_name.as_str(),
        env.hostname.as_str(),
        env.machine_id.as_str(),
        env.boot_id.as_str(),
        env.kind.as_str(),
    ];
    let optional = [&env.session_id, &env.prompt_id, &env.workdir];
    fields.iter().any(|f| f.contains('\0'))
        || optional
            .iter()
            .any(|f| f.as_deref().is_some_and(|v| v.contains('\0')))
        || payload.contains("\\u0000")
}

fn prepare(seq: u64, env: &Envelope) -> Result<Prepared, String> {
    let payload = env.payload.to_string();
    if has_nul(env, &payload) {
        return Err("event contains a NUL character".to_owned());
    }
    let out_of_range = |field: &str| format!("{field} out of range");
    Ok(Prepared {
        seq: i64::try_from(seq).map_err(|_| out_of_range("seq"))?,
        captured_at_ms: i64::try_from(env.ts).map_err(|_| out_of_range("ts_ms"))?,
        occurred_at_ms: env
            .occurred_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| out_of_range("occurred_at_ms"))?,
        schema_version: i32::try_from(env.schema_version)
            .map_err(|_| out_of_range("schema_version"))?,
        payload,
        envelope: env.clone(),
    })
}

fn to_count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn to_u64(value: Option<i64>) -> u64 {
    value.and_then(|v| u64::try_from(v).ok()).unwrap_or(0)
}

fn parse_u64(value: Option<String>) -> u64 {
    value.and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// Postgres-backed storage for events, box state and the session projection.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Wraps a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies the embedded migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Migrate`] when a migration fails or the history diverges.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!().run(&self.pool).await?;
        Ok(())
    }

    /// Stores a batch in one transaction.
    ///
    /// Each `(seq, envelope)` inserts with `ON CONFLICT (box, id) DO NOTHING`. The session
    /// projection then runs over the rows that were new, in `seq` order, and the box row's
    /// `last_event_at` moves to now. A repeated event changes nothing. Events that cannot
    /// be stored (a NUL character, a number beyond the column range) come back in
    /// [`IngestOutcome::rejected`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the transaction fails. Nothing is stored then.
    pub async fn ingest(&self, events: &[(u64, Envelope)]) -> Result<IngestOutcome, StoreError> {
        let mut outcome = IngestOutcome::default();
        let mut rows = Vec::with_capacity(events.len());
        for (seq, env) in events {
            match prepare(*seq, env) {
                Ok(row) => rows.push(row),
                Err(reason) => outcome.rejected.push((*seq, reason)),
            }
        }
        rows.sort_by_key(|row| row.seq);
        let Some(last) = rows.last() else {
            return Ok(outcome);
        };
        let identity = last.envelope.clone();

        let mut tx = self.pool.begin().await?;
        let mut fresh = insert_events(&mut tx, &rows).await?;
        for row in &rows {
            let key = (row.envelope.box_name.clone(), row.envelope.id.to_string());
            if !fresh.remove(&key) {
                continue;
            }
            outcome.stored += 1;
            if let Some(projection) = project(&row.envelope) {
                apply_projection(&mut tx, &row.envelope, row.captured_at_ms, &projection).await?;
            }
        }
        sqlx::query(TOUCH_BOX)
            .bind(&identity.box_name)
            .bind(&identity.hostname)
            .bind(&identity.machine_id)
            .bind(&identity.boot_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        outcome.duplicate = to_count(rows.len()).saturating_sub(outcome.stored);
        Ok(outcome)
    }

    /// Records a heartbeat: upserts the box row, stamps `last_heartbeat_at` with the
    /// server clock and stores the queue figures from the request in `state`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the upsert fails.
    pub async fn heartbeat(
        &self,
        box_name: &BoxName,
        request: &HeartbeatRequest,
    ) -> Result<(), StoreError> {
        let state = json!({
            "uptime_s": request.uptime_s,
            "queue_pending": request.queue_pending,
            "queue_oldest_age_s": request.queue_oldest_age_s,
            "last_ack_age_s": request.last_ack_age_s,
        });
        sqlx::query(UPSERT_HEARTBEAT)
            .bind(box_name.as_str())
            .bind(&request.hostname)
            .bind(&request.machine_id)
            .bind(&request.boot_id)
            .bind(&request.fleetd_version)
            .bind(state.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Lists boxes with their sessions, optionally one box.
    ///
    /// Box status and every age come from the database clock at read time: `UNKNOWN`
    /// with no heartbeat, `LIVE` under 90 seconds, `STALE` under 10 minutes, `LOST`
    /// beyond. Returns the server time in milliseconds with the views.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when a query fails.
    pub async fn list_fleet(&self, only: Option<&str>) -> Result<(u64, Vec<BoxView>), StoreError> {
        let as_of_ms = to_u64(
            sqlx::query_scalar::<_, i64>(NOW_MS)
                .fetch_one(&self.pool)
                .await
                .ok(),
        );
        let box_rows = sqlx::query(LIST_BOXES)
            .bind(only)
            .fetch_all(&self.pool)
            .await?;
        let session_rows = sqlx::query(LIST_SESSIONS)
            .bind(only)
            .fetch_all(&self.pool)
            .await?;

        let mut sessions: BTreeMap<String, Vec<SessionView>> = BTreeMap::new();
        for row in &session_rows {
            sessions
                .entry(row.try_get("box")?)
                .or_default()
                .push(session_view(row)?);
        }
        let mut boxes = Vec::with_capacity(box_rows.len());
        for row in &box_rows {
            let name: String = row.try_get("box")?;
            let status: String = row.try_get("status")?;
            let sessions = sessions.remove(&name).unwrap_or_default();
            boxes.push(BoxView {
                sessions,
                ..box_view(row, name, &status)?
            });
        }
        Ok((as_of_ms, boxes))
    }
}

async fn insert_events(
    tx: &mut Transaction<'_, Postgres>,
    rows: &[Prepared],
) -> Result<HashSet<(String, String)>, sqlx::Error> {
    let boxes: Vec<&str> = rows.iter().map(|r| r.envelope.box_name.as_str()).collect();
    let ids: Vec<String> = rows.iter().map(|r| r.envelope.id.to_string()).collect();
    let boots: Vec<&str> = rows.iter().map(|r| r.envelope.boot_id.as_str()).collect();
    let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
    let versions: Vec<i32> = rows.iter().map(|r| r.schema_version).collect();
    let sources: Vec<String> = rows
        .iter()
        .map(|r| {
            serde_json::to_value(r.envelope.source)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        })
        .collect();
    let kinds: Vec<&str> = rows.iter().map(|r| r.envelope.kind.as_str()).collect();
    let captured: Vec<i64> = rows.iter().map(|r| r.captured_at_ms).collect();
    let occurred: Vec<Option<i64>> = rows.iter().map(|r| r.occurred_at_ms).collect();
    let sessions: Vec<Option<&str>> = rows
        .iter()
        .map(|r| r.envelope.session_id.as_deref())
        .collect();
    let prompts: Vec<Option<&str>> = rows
        .iter()
        .map(|r| r.envelope.prompt_id.as_deref())
        .collect();
    let workdirs: Vec<Option<&str>> = rows.iter().map(|r| r.envelope.workdir.as_deref()).collect();
    let payloads: Vec<&str> = rows.iter().map(|r| r.payload.as_str()).collect();

    let inserted = sqlx::query(INSERT_EVENTS)
        .bind(boxes)
        .bind(ids)
        .bind(boots)
        .bind(seqs)
        .bind(versions)
        .bind(sources)
        .bind(kinds)
        .bind(captured)
        .bind(occurred)
        .bind(sessions)
        .bind(prompts)
        .bind(workdirs)
        .bind(payloads)
        .fetch_all(&mut **tx)
        .await?;
    inserted
        .iter()
        .map(|row| Ok((row.try_get("box")?, row.try_get("id")?)))
        .collect()
}

async fn apply_projection(
    tx: &mut Transaction<'_, Postgres>,
    env: &Envelope,
    captured_at_ms: i64,
    projection: &Projection,
) -> Result<(), sqlx::Error> {
    sqlx::query(UPSERT_SESSION)
        .bind(&env.box_name)
        .bind(&projection.session_id)
        .bind(&projection.session_kind)
        .bind(projection.state.as_str())
        .bind(captured_at_ms)
        .bind(&projection.workdir)
        .bind(&projection.prompt)
        .bind(&projection.message)
        .bind(&projection.notification)
        .bind(&env.kind)
        .bind(projection.apply_state)
        .bind(projection.reopen)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn session_state(raw: &str) -> SessionState {
    match State::parse(raw) {
        Some(State::Active) => SessionState::Active,
        Some(State::Working) => SessionState::Working,
        Some(State::Idle) => SessionState::Idle,
        Some(State::Stalled) => SessionState::Stalled,
        Some(State::Ended) => SessionState::Ended,
        Some(State::Crashed) => SessionState::Crashed,
        None => SessionState::Unspecified,
    }
}

fn box_status(raw: &str) -> BoxStatus {
    match raw {
        "unknown" => BoxStatus::Unknown,
        "live" => BoxStatus::Live,
        "stale" => BoxStatus::Stale,
        "lost" => BoxStatus::Lost,
        _ => BoxStatus::Unspecified,
    }
}

fn session_view(row: &PgRow) -> Result<SessionView, sqlx::Error> {
    let state: String = row.try_get("state")?;
    Ok(SessionView {
        session_id: row.try_get("session_id")?,
        kind: row.try_get("kind")?,
        state: session_state(&state).into(),
        state_age_s: to_u64(row.try_get("state_age_s")?),
        workdir: row.try_get("workdir")?,
        last_prompt: row.try_get("last_prompt")?,
        last_message: row.try_get("last_message")?,
        last_event_age_s: to_u64(row.try_get("last_event_age_s")?),
    })
}

fn box_view(row: &PgRow, name: String, status: &str) -> Result<BoxView, sqlx::Error> {
    let heartbeat_age: Option<i64> = row.try_get("heartbeat_age_s")?;
    Ok(BoxView {
        r#box: name,
        hostname: row.try_get("hostname")?,
        status: box_status(status).into(),
        heartbeat_age_s: heartbeat_age.and_then(|v| u64::try_from(v).ok()),
        boot_id: row.try_get("boot_id")?,
        fleetd_version: row.try_get("fleetd_version")?,
        queue_pending: parse_u64(row.try_get("queue_pending")?),
        queue_oldest_age_s: parse_u64(row.try_get("queue_oldest_age_s")?),
        sessions: Vec::new(),
    })
}

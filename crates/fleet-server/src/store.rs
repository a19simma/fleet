//! Postgres storage: ingest transaction, heartbeat upsert and fleet read model.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use fleet_core::{BoxName, Envelope, SCHEMA_VERSION};
use fleet_proto::v1::{BoxStatus, BoxView, HeartbeatRequest, SessionState, SessionView};
use serde_json::{Value, json};
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
    last_message, last_notification, last_event_at, last_event_kind, state_event_at) \
SELECT $1::text, $2::text, $3::text, $4::text, \
    LEAST(to_timestamp($5::bigint::double precision / 1000.0), now()), \
    $6::text, $7::text, $8::text, $9::text, \
    LEAST(to_timestamp($5::bigint::double precision / 1000.0), now()), $10::text, \
    LEAST(to_timestamp($5::bigint::double precision / 1000.0), now()) \
WHERE $13::boolean OR EXISTS (SELECT 1 FROM sessions e WHERE e.box = $1 AND e.session_id = $2) \
ON CONFLICT (box, session_id) DO UPDATE SET \
    state = CASE WHEN $11::boolean AND EXCLUDED.state_event_at >= s.state_event_at \
        AND (s.state <> 'ended' OR $12::boolean) \
        THEN EXCLUDED.state ELSE s.state END, \
    state_at = CASE WHEN $11::boolean AND EXCLUDED.state_event_at >= s.state_event_at \
        AND (s.state <> 'ended' OR $12::boolean) \
        AND s.state <> EXCLUDED.state THEN EXCLUDED.state_at ELSE s.state_at END, \
    state_event_at = CASE WHEN $11::boolean \
        THEN GREATEST(s.state_event_at, EXCLUDED.state_event_at) ELSE s.state_event_at END, \
    workdir = COALESCE(EXCLUDED.workdir, s.workdir), \
    last_prompt = COALESCE(EXCLUDED.last_prompt, s.last_prompt), \
    last_message = COALESCE(EXCLUDED.last_message, s.last_message), \
    last_notification = COALESCE(EXCLUDED.last_notification, s.last_notification), \
    last_event_at = GREATEST(s.last_event_at, EXCLUDED.last_event_at), \
    last_event_kind = CASE WHEN EXCLUDED.last_event_at >= s.last_event_at \
        THEN EXCLUDED.last_event_kind ELSE s.last_event_kind END";

const TOUCH_BOX: &str = "\
INSERT INTO boxes AS b (box, hostname, machine_id, boot_id, last_event_at, identity_at_ms) \
VALUES ($1, $2, $3, $4, now(), \
    LEAST($5::bigint, (extract(epoch FROM clock_timestamp()) * 1000)::bigint)) \
ON CONFLICT (box) DO UPDATE SET \
    hostname = CASE WHEN EXCLUDED.identity_at_ms >= b.identity_at_ms \
        THEN EXCLUDED.hostname ELSE b.hostname END, \
    machine_id = CASE WHEN EXCLUDED.identity_at_ms >= b.identity_at_ms \
        THEN EXCLUDED.machine_id ELSE b.machine_id END, \
    boot_id = CASE WHEN EXCLUDED.identity_at_ms >= b.identity_at_ms \
        THEN EXCLUDED.boot_id ELSE b.boot_id END, \
    identity_at_ms = GREATEST(b.identity_at_ms, EXCLUDED.identity_at_ms), \
    last_event_at = now()";

const UPSERT_HEARTBEAT: &str = "\
INSERT INTO boxes AS b (box, hostname, machine_id, boot_id, fleetd_version, \
    last_heartbeat_at, state, identity_at_ms) \
VALUES ($1, $2, $3, $4, $5, now(), $6::text::jsonb, \
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint) \
ON CONFLICT (box) DO UPDATE SET \
    hostname = CASE WHEN EXCLUDED.identity_at_ms >= b.identity_at_ms \
        THEN EXCLUDED.hostname ELSE b.hostname END, \
    machine_id = CASE WHEN EXCLUDED.identity_at_ms >= b.identity_at_ms \
        THEN EXCLUDED.machine_id ELSE b.machine_id END, \
    boot_id = CASE WHEN EXCLUDED.identity_at_ms >= b.identity_at_ms \
        THEN EXCLUDED.boot_id ELSE b.boot_id END, \
    identity_at_ms = GREATEST(b.identity_at_ms, EXCLUDED.identity_at_ms), \
    fleetd_version = COALESCE(NULLIF(EXCLUDED.fleetd_version, ''), b.fleetd_version), \
    last_heartbeat_at = now(), \
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

/// Last millisecond of the year 9999, the largest timestamp an event may carry.
pub const MAX_TS_MS: u64 = 253_402_300_799_999;

/// Why a store call failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// Postgres or the connection pool failed.
    Database(sqlx::Error),
    /// Applying the embedded migrations failed.
    Migrate(sqlx::migrate::MigrateError),
    /// A stored value does not fit the type the read model needs.
    OutOfRange(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(err) => write!(f, "database error: {err}"),
            Self::Migrate(err) => write!(f, "migration error: {err}"),
            Self::OutOfRange(field) => write!(f, "stored {field} is out of range"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(err) => Some(err),
            Self::Migrate(err) => Some(err),
            Self::OutOfRange(_) => None,
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
    /// Lowest `seq` rejected for an unsupported `schema_version`. The caller must not ack
    /// this `seq` or any later one, so the sender keeps and retries them.
    pub retry_from_seq: Option<u64>,
}

struct Prepared {
    seq: i64,
    captured_at_ms: i64,
    occurred_at_ms: Option<i64>,
    schema_version: i32,
    payload: String,
    envelope: Envelope,
}

fn value_has_nul(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains('\0'),
        Value::Array(items) => items.iter().any(value_has_nul),
        Value::Object(map) => map
            .iter()
            .any(|(key, item)| key.contains('\0') || value_has_nul(item)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn has_nul(env: &Envelope) -> bool {
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
        || value_has_nul(&env.payload)
}

fn prepare(seq: u64, env: &Envelope) -> Result<Prepared, String> {
    if env.schema_version != SCHEMA_VERSION {
        return Err(format!("unsupported schema_version {}", env.schema_version));
    }
    if has_nul(env) {
        return Err("event contains a NUL character".to_owned());
    }
    let out_of_range = |field: &str| format!("{field} out of range");
    let timestamp = |value: u64, field: &str| {
        if value > MAX_TS_MS {
            return Err(out_of_range(field));
        }
        i64::try_from(value).map_err(|_| out_of_range(field))
    };
    Ok(Prepared {
        seq: i64::try_from(seq).map_err(|_| out_of_range("seq"))?,
        captured_at_ms: timestamp(env.ts, "ts_ms")?,
        occurred_at_ms: env
            .occurred_at
            .map(|value| timestamp(value, "occurred_at_ms"))
            .transpose()?,
        schema_version: i32::try_from(env.schema_version)
            .map_err(|_| out_of_range("schema_version"))?,
        payload: env.payload.to_string(),
        envelope: env.clone(),
    })
}

fn count(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::OutOfRange(field))
}

fn parse_count(value: Option<String>, field: &'static str) -> Result<u64, StoreError> {
    value.map_or(Ok(0), |text| {
        text.parse().map_err(|_| StoreError::OutOfRange(field))
    })
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
    /// `last_event_at` moves to now when at least one event was new. The box identity
    /// comes from the newest new event and an older one never replaces a newer one. A
    /// repeated event changes nothing. Events that cannot be stored (a NUL character, a
    /// timestamp beyond the year 9999, a number beyond the column range, a
    /// `schema_version` other than [`SCHEMA_VERSION`]) come back in
    /// [`IngestOutcome::rejected`]. The lowest `seq` rejected for its schema version is
    /// also reported in [`IngestOutcome::retry_from_seq`]. Only the current schema version is accepted, since
    /// no earlier one has shipped.
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
                Err(reason) => {
                    if env.schema_version != SCHEMA_VERSION {
                        outcome.retry_from_seq =
                            Some(outcome.retry_from_seq.map_or(*seq, |low| low.min(*seq)));
                    }
                    outcome.rejected.push((*seq, reason));
                }
            }
        }
        rows.sort_by_key(|row| row.seq);
        if rows.is_empty() {
            return Ok(outcome);
        }
        let batch_len = u32::try_from(rows.len()).map_err(|_| StoreError::OutOfRange("batch"))?;

        let mut tx = self.pool.begin().await?;
        let mut fresh = insert_events(&mut tx, &rows).await?;
        let mut newest: Option<&Prepared> = None;
        for row in &rows {
            let key = (row.envelope.box_name.clone(), row.envelope.id.to_string());
            if !fresh.remove(&key) {
                continue;
            }
            outcome.stored += 1;
            if newest.is_none_or(|n| (row.captured_at_ms, row.seq) >= (n.captured_at_ms, n.seq)) {
                newest = Some(row);
            }
            if let Some(projection) = project(&row.envelope) {
                apply_projection(&mut tx, &row.envelope, row.captured_at_ms, &projection).await?;
            }
        }
        if let Some(row) = newest {
            let identity = &row.envelope;
            sqlx::query(TOUCH_BOX)
                .bind(&identity.box_name)
                .bind(&identity.hostname)
                .bind(&identity.machine_id)
                .bind(&identity.boot_id)
                .bind(row.captured_at_ms)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        outcome.duplicate = batch_len.saturating_sub(outcome.stored);
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
        let as_of_ms = count(
            sqlx::query_scalar::<_, i64>(NOW_MS)
                .fetch_one(&self.pool)
                .await?,
            "as_of_ms",
        )?;
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
    let sources: Vec<&str> = rows.iter().map(|r| r.envelope.source.as_str()).collect();
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
        .bind(projection.creates_row)
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

fn session_view(row: &PgRow) -> Result<SessionView, StoreError> {
    let state: String = row.try_get("state")?;
    Ok(SessionView {
        session_id: row.try_get("session_id")?,
        kind: row.try_get("kind")?,
        state: session_state(&state).into(),
        state_age_s: count(row.try_get("state_age_s")?, "state_age_s")?,
        workdir: row.try_get("workdir")?,
        last_prompt: row.try_get("last_prompt")?,
        last_message: row.try_get("last_message")?,
        last_event_age_s: count(row.try_get("last_event_age_s")?, "last_event_age_s")?,
    })
}

fn box_view(row: &PgRow, name: String, status: &str) -> Result<BoxView, StoreError> {
    let heartbeat_age: Option<i64> = row.try_get("heartbeat_age_s")?;
    Ok(BoxView {
        r#box: name,
        hostname: row.try_get("hostname")?,
        status: box_status(status).into(),
        heartbeat_age_s: heartbeat_age
            .map(|age| count(age, "heartbeat_age_s"))
            .transpose()?,
        boot_id: row.try_get("boot_id")?,
        fleetd_version: row.try_get("fleetd_version")?,
        queue_pending: parse_count(row.try_get("queue_pending")?, "queue_pending")?,
        queue_oldest_age_s: parse_count(row.try_get("queue_oldest_age_s")?, "queue_oldest_age_s")?,
        sessions: Vec::new(),
    })
}

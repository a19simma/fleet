//! Postgres storage: ingest transaction, heartbeat upsert, fleet read model and jobs.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::time::Duration;

use fleet_core::{BoxName, Envelope, EventId, SCHEMA_VERSION};
use fleet_proto::v1::{
    BoxStatus, BoxView, GetProfileBlobReply, GetStatsReply, GetStatsRequest, HeartbeatRequest, Job,
    JobState, ProfileRef, ReadJobEventsReply, ReadTranscriptReply, ReportJobReply,
    ReportJobRequest, SessionState, SessionView, SubmitBatchReply, SubmitBatchRequest,
    SubmitJobRequest, TranscriptChunk,
};
use serde_json::{Value, json};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::batches::{self, BatchInvalid};
use crate::jobs::{
    JobInvalid, MAX_CHUNKS_PER_REPORT, MAX_PHASE_CHARS, MAX_PROGRESS_CHARS, MAX_TRANSCRIPT_BYTES,
    MAX_TRANSCRIPT_ROWS, MIN_CHUNK_COST_BYTES, validate_job_id, validate_submit, validate_terminal,
};
use crate::profiles::{self, ProfileFault};
use crate::projection::{Projection, State, project};
use crate::stats;
use crate::telemetry;

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

const SELECT_JOB_BY_KEY: &str = "\
SELECT job_id, idempotency_key, prompt, repo, base_ref, open_pr, state, box, attempt, \
progress, phase, branch, pr_url, error, exit_code, cancel_requested, batch_id, \
profile_name, profile_version, encode(profile_hash, 'hex') AS profile_hash, \
(EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint AS lease_ms, \
(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms, \
(EXTRACT(EPOCH FROM claimed_at) * 1000)::bigint AS claimed_ms, \
(EXTRACT(EPOCH FROM finished_at) * 1000)::bigint AS finished_ms \
FROM jobs WHERE idempotency_key = $1";

const INSERT_JOB: &str = "\
INSERT INTO jobs (job_id, idempotency_key, prompt, repo, base_ref, branch, open_pr) \
VALUES ($1, $2, $3, $4, $5, 'swarm/' || $1, $6) \
ON CONFLICT (idempotency_key) DO NOTHING \
RETURNING job_id";

const SELECT_JOB_BY_ID: &str = "\
SELECT job_id, idempotency_key, prompt, repo, base_ref, open_pr, state, box, attempt, \
progress, phase, branch, pr_url, error, exit_code, cancel_requested, batch_id, \
profile_name, profile_version, encode(profile_hash, 'hex') AS profile_hash, \
(EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint AS lease_ms, \
(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms, \
(EXTRACT(EPOCH FROM claimed_at) * 1000)::bigint AS claimed_ms, \
(EXTRACT(EPOCH FROM finished_at) * 1000)::bigint AS finished_ms \
FROM jobs WHERE job_id = $1";

const LIST_JOBS: &str = "\
SELECT job_id, idempotency_key, prompt, repo, base_ref, open_pr, state, box, attempt, \
progress, phase, branch, pr_url, error, exit_code, cancel_requested, batch_id, \
profile_name, profile_version, encode(profile_hash, 'hex') AS profile_hash, \
(EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint AS lease_ms, \
(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms, \
(EXTRACT(EPOCH FROM claimed_at) * 1000)::bigint AS claimed_ms, \
(EXTRACT(EPOCH FROM finished_at) * 1000)::bigint AS finished_ms \
FROM jobs WHERE $1::text IS NULL OR state = $1 \
ORDER BY created_at DESC, job_id DESC LIMIT $2";

const READ_TRANSCRIPT: &str = "\
SELECT seq, ts_ms, chunk, truncated FROM job_transcript \
WHERE job_id = $1 AND seq > $2 ORDER BY seq LIMIT $3";

const CLAIM_JOB: &str = "\
UPDATE jobs SET state = 'RUNNING', box = $1, attempt = attempt + 1, \
claimed_at = now(), lease_expires_at = now() + make_interval(secs => $2) \
WHERE job_id = ( \
SELECT job_id FROM jobs WHERE state = 'QUEUED' \
ORDER BY created_at, job_id LIMIT 1 FOR UPDATE SKIP LOCKED) \
RETURNING job_id, idempotency_key, prompt, repo, base_ref, open_pr, state, box, attempt, \
progress, phase, branch, pr_url, error, exit_code, cancel_requested, batch_id, \
profile_name, profile_version, encode(profile_hash, 'hex') AS profile_hash, \
(EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint AS lease_ms, \
(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms, \
(EXTRACT(EPOCH FROM claimed_at) * 1000)::bigint AS claimed_ms, \
(EXTRACT(EPOCH FROM finished_at) * 1000)::bigint AS finished_ms";

const CANCEL_JOB: &str = "\
UPDATE jobs SET \
state = CASE WHEN state = 'QUEUED' THEN 'CANCELLED' ELSE state END, \
finished_at = CASE WHEN state = 'QUEUED' THEN now() ELSE finished_at END, \
cancel_requested = cancel_requested OR state = 'RUNNING' \
WHERE job_id = $1 \
RETURNING job_id, idempotency_key, prompt, repo, base_ref, open_pr, state, box, attempt, \
progress, phase, branch, pr_url, error, exit_code, cancel_requested, batch_id, \
profile_name, profile_version, encode(profile_hash, 'hex') AS profile_hash, \
(EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint AS lease_ms, \
(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms, \
(EXTRACT(EPOCH FROM claimed_at) * 1000)::bigint AS claimed_ms, \
(EXTRACT(EPOCH FROM finished_at) * 1000)::bigint AS finished_ms";

const REPORT_JOB: &str = "\
UPDATE jobs SET phase = $4, progress = $5, \
lease_expires_at = now() + make_interval(secs => $6), \
state = COALESCE($7, state), \
finished_at = CASE WHEN $7::text IS NULL THEN finished_at ELSE now() END, \
pr_url = CASE WHEN $7::text IS NULL THEN pr_url ELSE $8 END, \
error = CASE WHEN $7::text IS NULL THEN error ELSE $9 END, \
exit_code = CASE WHEN $7::text IS NULL THEN exit_code ELSE $10 END, \
branch = COALESCE($11, branch) \
WHERE job_id = $1 AND attempt = $2 AND box = $3 AND state = 'RUNNING' \
AND ($7::text IS DISTINCT FROM 'CANCELLED' OR cancel_requested) \
RETURNING cancel_requested, transcript_bytes, \
(EXTRACT(EPOCH FROM lease_expires_at) * 1000)::bigint AS lease_ms";

const REAP_EXPIRED: &str = "\
UPDATE jobs SET state = 'LOST', finished_at = now(), error = 'lease expired' \
WHERE state = 'RUNNING' AND lease_expires_at < now()";

const PRUNE_EVENTS: &str = "\
WITH doomed AS (\
SELECT e.job_id, e.seq FROM job_event e JOIN jobs j ON j.job_id = e.job_id \
WHERE j.state IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'LOST') \
AND COALESCE(j.finished_at, j.created_at) < now() - make_interval(days => $1) \
LIMIT $2 FOR UPDATE OF e SKIP LOCKED) \
DELETE FROM job_event d USING doomed WHERE d.job_id = doomed.job_id AND d.seq = doomed.seq";

const PRUNE_SUMMARIES: &str = "\
WITH doomed AS (\
SELECT s.job_id FROM job_summary s JOIN jobs j ON j.job_id = s.job_id \
WHERE j.state IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'LOST') \
AND COALESCE(j.finished_at, j.created_at) < now() - make_interval(days => $1) \
LIMIT $2 FOR UPDATE OF s SKIP LOCKED) \
DELETE FROM job_summary d USING doomed WHERE d.job_id = doomed.job_id";

const TRANSCRIPT_STATE: &str = "\
SELECT count(*), COALESCE(bool_or(truncated), false) FROM job_transcript WHERE job_id = $1";

const TRANSCRIPT_KNOWN_SEQS: &str = "\
SELECT seq FROM job_transcript WHERE job_id = $1 AND seq = ANY($2)";

const TRANSCRIPT_PREFIX: &str = "\
SELECT COALESCE(max(seq), 0) FROM ( \
SELECT seq, seq - row_number() OVER (ORDER BY seq) AS gap \
FROM job_transcript WHERE job_id = $1) s WHERE gap = 0";

const INSERT_CHUNKS: &str = "\
INSERT INTO job_transcript (job_id, seq, ts_ms, chunk, truncated) \
SELECT $1, t.seq, t.ts_ms, t.chunk, t.truncated \
FROM UNNEST($2::bigint[], $3::bigint[], $4::text[], $5::boolean[]) \
AS t(seq, ts_ms, chunk, truncated) \
ON CONFLICT DO NOTHING";

const SET_TRANSCRIPT_BYTES: &str = "UPDATE jobs SET transcript_bytes = $2 WHERE job_id = $1";

/// Lease granted to a claimed job when the store is not configured otherwise.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(120);

const NOW_MS: &str = "SELECT (EXTRACT(EPOCH FROM now()) * 1000)::bigint";
pub(crate) const NOW_SECONDS: &str = "SELECT CEIL(EXTRACT(EPOCH FROM now()))::bigint";

/// Jobs `list_jobs` returns when the request sets no limit.
pub const DEFAULT_LIST_LIMIT: u32 = 50;
/// Most jobs `list_jobs` returns.
pub const MAX_LIST_LIMIT: u32 = 200;
/// Chunks `read_transcript` returns when the request sets no limit.
pub const DEFAULT_TRANSCRIPT_LIMIT: u32 = 100;
/// Most chunks `read_transcript` returns.
pub const MAX_TRANSCRIPT_LIMIT: u32 = 500;
/// Events `read_job_events` returns when the request sets no limit.
pub const DEFAULT_EVENTS_LIMIT: u32 = 200;
/// Most events `read_job_events` returns.
pub const MAX_EVENTS_LIMIT: u32 = 1000;

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
    /// A job request failed validation.
    InvalidJob(JobInvalid),
    /// An idempotency key was reused with different submit parameters. The handler maps
    /// this to gRPC `ALREADY_EXISTS`.
    KeyConflict,
    /// A report named a job that is missing, not running, held by another box or at
    /// another attempt. The handler maps this to gRPC `FAILED_PRECONDITION`. No input is
    /// kept.
    StaleReport,
    /// A transcript chunk has a sequence number or text the store cannot keep. No input is
    /// kept.
    InvalidChunk,
    /// A telemetry event or summary has a value the store cannot keep. No input is kept.
    InvalidTelemetry,
    /// A report carries more telemetry events than [`fleet_proto::MAX_EVENTS_PER_REPORT`].
    TelemetryTooLarge,
    /// A get, cancel or transcript read named a job that does not exist. The handler maps
    /// this to gRPC `NOT_FOUND`. No input is kept.
    NotFound,
    /// A profile request failed validation. No input is kept.
    InvalidProfile(ProfileFault),
    /// A batch request failed validation. No input is kept.
    InvalidBatch(BatchInvalid),
    /// A batch named a profile that has no version. The handler maps this to gRPC
    /// `NOT_FOUND`. No input is kept.
    UnknownProfile,
    /// A profile blob read did not match a live lease, or no such job exists. The handler
    /// maps this to gRPC `PERMISSION_DENIED`. No input is kept.
    LeaseDenied,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(err) => write!(f, "database error: {err}"),
            Self::Migrate(err) => write!(f, "migration error: {err}"),
            Self::OutOfRange(field) => write!(f, "stored {field} is out of range"),
            Self::InvalidJob(reason) => reason.fmt(f),
            Self::KeyConflict => f.write_str("idempotency key already used with other parameters"),
            Self::StaleReport => f.write_str("job is not running here at this attempt"),
            Self::InvalidChunk => f.write_str("invalid transcript chunk"),
            Self::InvalidTelemetry => f.write_str("invalid job telemetry"),
            Self::TelemetryTooLarge => f.write_str("too many telemetry events in one report"),
            Self::NotFound => f.write_str("job not found"),
            Self::InvalidProfile(reason) => reason.fmt(f),
            Self::InvalidBatch(reason) => reason.fmt(f),
            Self::UnknownProfile => f.write_str("profile not found"),
            Self::LeaseDenied => f.write_str("lease does not match"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(err) => Some(err),
            Self::Migrate(err) => Some(err),
            Self::InvalidJob(err) => Some(err),
            Self::InvalidProfile(err) => Some(err),
            Self::InvalidBatch(err) => Some(err),
            Self::OutOfRange(_)
            | Self::KeyConflict
            | Self::StaleReport
            | Self::InvalidChunk
            | Self::InvalidTelemetry
            | Self::TelemetryTooLarge
            | Self::NotFound
            | Self::UnknownProfile
            | Self::LeaseDenied => None,
        }
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

impl From<ProfileFault> for StoreError {
    fn from(err: ProfileFault) -> Self {
        Self::InvalidProfile(err)
    }
}

impl From<JobInvalid> for StoreError {
    fn from(err: JobInvalid) -> Self {
        Self::InvalidJob(err)
    }
}

type ChunkRow<'a> = (i64, i64, &'a str);

#[derive(Default)]
struct ChunkPlan<'a> {
    seqs: Vec<i64>,
    ts_ms: Vec<i64>,
    text: Vec<&'a str>,
    marks: Vec<bool>,
    bytes: usize,
    row_count: i64,
    truncated: bool,
}

fn check_chunks(chunks: &[TranscriptChunk]) -> Result<Vec<ChunkRow<'_>>, StoreError> {
    if chunks.len() > MAX_CHUNKS_PER_REPORT {
        return Err(StoreError::InvalidChunk);
    }
    let mut rows = Vec::with_capacity(chunks.len());
    let mut previous = 0_i64;
    for chunk in chunks {
        let seq = i64::try_from(chunk.seq).map_err(|_| StoreError::InvalidChunk)?;
        if seq <= previous || chunk.text.contains('\0') {
            return Err(StoreError::InvalidChunk);
        }
        previous = seq;
        let ts_ms =
            i64::try_from(chunk.ts_ms.min(MAX_TS_MS)).map_err(|_| StoreError::InvalidChunk)?;
        rows.push((seq, ts_ms, chunk.text.as_str()));
    }
    Ok(rows)
}

fn plan_chunks<'a>(
    rows: &[ChunkRow<'a>],
    known: &HashSet<i64>,
    bytes: usize,
    row_count: i64,
    truncated: bool,
) -> ChunkPlan<'a> {
    let mut plan = ChunkPlan {
        bytes,
        row_count,
        truncated,
        ..ChunkPlan::default()
    };
    for &(seq, ts_ms, text) in rows {
        if known.contains(&seq) || plan.truncated {
            continue;
        }
        let cost = text.len().max(MIN_CHUNK_COST_BYTES);
        let over = plan.bytes.saturating_add(cost) > MAX_TRANSCRIPT_BYTES
            || plan.row_count >= MAX_TRANSCRIPT_ROWS;
        if !over {
            plan.bytes += cost;
        }
        plan.row_count += 1;
        plan.truncated = over;
        plan.seqs.push(seq);
        plan.ts_ms.push(ts_ms);
        plan.text.push(if over { "" } else { text });
        plan.marks.push(over);
    }
    plan
}

fn job_state(text: &str) -> Result<JobState, StoreError> {
    Ok(match text {
        "QUEUED" => JobState::Queued,
        "RUNNING" => JobState::Running,
        "SUCCEEDED" => JobState::Succeeded,
        "FAILED" => JobState::Failed,
        "CANCELLED" => JobState::Cancelled,
        "LOST" => JobState::Lost,
        _ => return Err(StoreError::OutOfRange("job state")),
    })
}

fn job_state_text(state: JobState) -> &'static str {
    match state {
        JobState::Unspecified => "",
        JobState::Queued => "QUEUED",
        JobState::Running => "RUNNING",
        JobState::Succeeded => "SUCCEEDED",
        JobState::Failed => "FAILED",
        JobState::Cancelled => "CANCELLED",
        JobState::Lost => "LOST",
    }
}

pub(crate) fn ms(value: Option<i64>, field: &'static str) -> Result<Option<u64>, StoreError> {
    value.map(|v| count(v, field)).transpose()
}

fn profile_ref(row: &PgRow) -> Result<Option<ProfileRef>, StoreError> {
    let Some(name) = row.try_get::<Option<String>, _>("profile_name")? else {
        return Ok(None);
    };
    let version: Option<i32> = row.try_get("profile_version")?;
    let hash: Option<String> = row.try_get("profile_hash")?;
    let (Some(version), Some(hash)) = (version, hash) else {
        return Err(StoreError::OutOfRange("job profile"));
    };
    Ok(Some(ProfileRef {
        name,
        version: u32::try_from(version).map_err(|_| StoreError::OutOfRange("profile version"))?,
        hash,
    }))
}

fn job_from_row(row: &PgRow) -> Result<Job, StoreError> {
    let state: String = row.try_get("state")?;
    let attempt: i32 = row.try_get("attempt")?;
    Ok(Job {
        job_id: row.try_get("job_id")?,
        idempotency_key: row
            .try_get::<Option<String>, _>("idempotency_key")?
            .unwrap_or_default(),
        prompt: row.try_get("prompt")?,
        repo: row.try_get("repo")?,
        base_ref: row.try_get("base_ref")?,
        open_pr: row.try_get("open_pr")?,
        state: job_state(&state)?.into(),
        r#box: row.try_get("box")?,
        attempt: u32::try_from(attempt).map_err(|_| StoreError::OutOfRange("attempt"))?,
        lease_expires_at_ms: ms(row.try_get("lease_ms")?, "lease_expires_at")?,
        progress: row.try_get("progress")?,
        exit_code: row.try_get("exit_code")?,
        branch: row.try_get("branch")?,
        pr_url: row.try_get("pr_url")?,
        error: row.try_get("error")?,
        cancel_requested: row.try_get("cancel_requested")?,
        created_at_ms: count(row.try_get("created_ms")?, "created_at")?,
        claimed_at_ms: ms(row.try_get("claimed_ms")?, "claimed_at")?,
        finished_at_ms: ms(row.try_get("finished_ms")?, "finished_at")?,
        phase: row.try_get("phase")?,
        summary: None,
        profile: profile_ref(row)?,
        batch_id: row.try_get("batch_id")?,
    })
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

pub(crate) fn count(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::OutOfRange(field))
}

fn parse_count(value: Option<String>, bad: &mut u32) -> u64 {
    let Some(text) = value else {
        return 0;
    };
    text.parse().unwrap_or_else(|_| {
        *bad = bad.saturating_add(1);
        0
    })
}

/// Postgres-backed storage for events, box state and the session projection.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
    lease: Duration,
    #[cfg(test)]
    snapshot_gate: Option<std::sync::Arc<SnapshotGate>>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct SnapshotGate {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

impl Store {
    /// Wraps a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            lease: DEFAULT_LEASE,
            #[cfg(test)]
            snapshot_gate: None,
        }
    }

    /// The lease a claim grants and a report renews.
    pub fn lease(&self) -> Duration {
        self.lease
    }

    /// Sets the lease a claim grants, [`DEFAULT_LEASE`] otherwise.
    #[must_use]
    pub fn with_lease(mut self, lease: Duration) -> Self {
        self.lease = lease;
        self
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
    /// also reported in [`IngestOutcome::retry_from_seq`].
    ///
    /// Only the current schema version is accepted, since no earlier one has shipped.
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

    /// Queues a job, or returns the one already stored under the same idempotency key.
    ///
    /// The request is validated once, by [`validate_submit`]. The job id is a fresh
    /// ULID-shaped [`EventId`]. The insert uses `ON CONFLICT (idempotency_key) DO NOTHING`,
    /// so concurrent submits with one key create one row. The stored row is then compared
    /// with the request on prompt, repo, base ref and `open_pr`: identical parameters
    /// return the stored job unchanged, any difference is refused.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when the request fails validation,
    /// [`StoreError::KeyConflict`] when the key exists with different parameters, and
    /// [`StoreError::Database`] when a query fails.
    pub async fn submit_job(&self, request: &SubmitJobRequest) -> Result<Job, StoreError> {
        let job = validate_submit(request)?;
        sqlx::query(INSERT_JOB)
            .bind(EventId::generate().to_string())
            .bind(&job.key)
            .bind(&job.prompt)
            .bind(&job.repo)
            .bind(&job.base_ref)
            .bind(job.open_pr)
            .fetch_optional(&self.pool)
            .await?;
        let row = sqlx::query(SELECT_JOB_BY_KEY)
            .bind(&job.key)
            .fetch_one(&self.pool)
            .await?;
        let stored = job_from_row(&row)?;
        if stored.prompt != job.prompt
            || stored.repo != job.repo
            || stored.base_ref != job.base_ref
            || stored.open_pr != job.open_pr
        {
            return Err(StoreError::KeyConflict);
        }
        Ok(stored)
    }

    /// Claims the oldest queued job for `box_name`.
    ///
    /// One statement picks the head of the queue by `created_at` with
    /// `FOR UPDATE SKIP LOCKED`, so concurrent claimers never take the same job. The job
    /// becomes `RUNNING` with the box, the attempt incremented, `claimed_at` set and the
    /// lease expiry one store lease after the claim. Cancelled and other non-queued jobs
    /// are skipped. An empty queue returns `None`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn claim_job(&self, box_name: &BoxName) -> Result<Option<Job>, StoreError> {
        let row = sqlx::query(CLAIM_JOB)
            .bind(box_name.as_str())
            .bind(self.lease.as_secs_f64())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(job_from_row).transpose()
    }

    /// Returns the job with `job_id`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when `job_id` fails validation,
    /// [`StoreError::NotFound`] when no job has it, and [`StoreError::Database`] when the
    /// query fails.
    pub async fn get_job(&self, job_id: &str) -> Result<Job, StoreError> {
        validate_job_id(job_id)?;
        let row = sqlx::query(SELECT_JOB_BY_ID)
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        job_from_row(&row)
    }

    /// Lists jobs newest first, optionally only those in `state`.
    ///
    /// `state` is the wire value of a [`JobState`]. A `limit` of 0 means
    /// [`DEFAULT_LIST_LIMIT`]; larger values are cut to [`MAX_LIST_LIMIT`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when `state` is unspecified or unknown, and
    /// [`StoreError::Database`] when the query fails.
    pub async fn list_jobs(&self, state: Option<i32>, limit: u32) -> Result<Vec<Job>, StoreError> {
        let state = state
            .map(|raw| match JobState::try_from(raw) {
                Ok(JobState::Unspecified) | Err(_) => Err(JobInvalid::State),
                Ok(known) => Ok(job_state_text(known)),
            })
            .transpose()?;
        let limit = match limit {
            0 => DEFAULT_LIST_LIMIT,
            n => n.min(MAX_LIST_LIMIT),
        };
        let rows = sqlx::query(LIST_JOBS)
            .bind(state)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(job_from_row).collect()
    }

    /// Reads transcript chunks of a job after `after_seq`, in `seq` order.
    ///
    /// A `limit` of 0 means [`DEFAULT_TRANSCRIPT_LIMIT`]; larger values are cut to
    /// [`MAX_TRANSCRIPT_LIMIT`]. `done` is true when the job has ended and no chunk
    /// follows the last one returned.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when `job_id` fails validation,
    /// [`StoreError::NotFound`] when no job has it, and [`StoreError::Database`] when a
    /// query fails.
    pub async fn read_transcript(
        &self,
        job_id: &str,
        after_seq: u64,
        limit: u32,
    ) -> Result<ReadTranscriptReply, StoreError> {
        let job = self.get_job(job_id).await?;
        let limit = match limit {
            0 => DEFAULT_TRANSCRIPT_LIMIT,
            n => n.min(MAX_TRANSCRIPT_LIMIT),
        };
        let after = i64::try_from(after_seq).unwrap_or(i64::MAX);
        let rows = sqlx::query(READ_TRANSCRIPT)
            .bind(job_id)
            .bind(after)
            .bind(i64::from(limit) + 1)
            .fetch_all(&self.pool)
            .await?;
        let more = rows.len() > limit as usize;
        let chunks = rows
            .iter()
            .take(limit as usize)
            .map(|row| {
                Ok(TranscriptChunk {
                    seq: count(row.try_get("seq")?, "seq")?,
                    ts_ms: count(row.try_get("ts_ms")?, "ts_ms")?,
                    text: row.try_get("chunk")?,
                    truncated: row.try_get("truncated")?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let ended = !matches!(job.state(), JobState::Queued | JobState::Running);
        Ok(ReadTranscriptReply {
            chunks,
            done: ended && !more,
        })
    }

    /// Returns the job with `job_id` and its telemetry summary, when one is stored.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Store::get_job`].
    pub async fn get_job_with_summary(&self, job_id: &str) -> Result<Job, StoreError> {
        let mut job = self.get_job(job_id).await?;
        job.summary = telemetry::read_summary(&self.pool, job_id).await?;
        Ok(job)
    }

    /// Reads telemetry events of a job after `after_seq`, in `seq` order.
    ///
    /// `after_seq` is exclusive and `None` starts at the first event, whose `seq` may be 0.
    /// A `limit` of 0 means [`DEFAULT_EVENTS_LIMIT`]; larger values are cut to
    /// [`MAX_EVENTS_LIMIT`]. `next_seq` is the `seq` of the last event returned, else
    /// `after_seq` (0 when unset): a client keeps its own cursor and stops on an empty page.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when `job_id` fails validation,
    /// [`StoreError::NotFound`] when no job has it, and [`StoreError::Database`] when a
    /// query fails.
    pub async fn read_job_events(
        &self,
        job_id: &str,
        after_seq: Option<u32>,
        limit: u32,
    ) -> Result<ReadJobEventsReply, StoreError> {
        self.get_job(job_id).await?;
        let limit = match limit {
            0 => DEFAULT_EVENTS_LIMIT,
            n => n.min(MAX_EVENTS_LIMIT),
        };
        let events = telemetry::read_events(&self.pool, job_id, after_seq, limit).await?;
        let next_seq = events
            .last()
            .map_or_else(|| after_seq.unwrap_or(0), |event| event.seq);
        Ok(ReadJobEventsReply { events, next_seq })
    }

    /// Aggregates job outcomes and telemetry over a time window.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when the window, a filter or the grouping fails
    /// validation, and [`StoreError::Database`] when the query fails.
    pub async fn stats(&self, request: &GetStatsRequest) -> Result<GetStatsReply, StoreError> {
        stats::stats(&self.pool, request).await
    }

    /// Stores a profile under `name` and returns its version.
    ///
    /// The request is validated once, by [`profiles::validate_create`]. The canonical
    /// content is inserted as a blob keyed by its hash, so one blob serves every name that
    /// holds the same content. Under a per-name advisory lock, content already stored under
    /// the name returns that version with `created` false, and new content gets the next
    /// version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidProfile`] when the name or content fails validation and
    /// [`StoreError::Database`] when a query fails.
    pub async fn create_profile(
        &self,
        name: &str,
        content_json: &str,
    ) -> Result<fleet_proto::v1::ProfileVersion, StoreError> {
        profiles::create(&self.pool, name, content_json).await
    }

    /// Reads a profile version, or the latest one when `version` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidProfile`] for a bad name, [`StoreError::NotFound`] when
    /// the name or version is missing and [`StoreError::Database`] when a query fails.
    pub async fn get_profile(
        &self,
        name: &str,
        version: Option<u32>,
    ) -> Result<fleet_proto::v1::ProfileVersion, StoreError> {
        profiles::get(&self.pool, name, version).await
    }

    /// Lists profile names in order with their latest version and hash.
    ///
    /// A `limit` of 0 means [`DEFAULT_LIST_LIMIT`] and any limit is capped at
    /// [`MAX_LIST_LIMIT`]. `after_name` resumes after that name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn list_profiles(
        &self,
        limit: u32,
        after_name: Option<&str>,
    ) -> Result<fleet_proto::v1::ListProfilesReply, StoreError> {
        profiles::list(&self.pool, limit, after_name).await
    }

    /// Queues one job per named profile as one batch, or returns the stored batch.
    ///
    /// The request is validated once, by [`batches::validate_batch`]. One transaction inserts
    /// the batch row, takes the advisory lock of each profile name in sorted order, pins the
    /// latest version and hash of each profile, and inserts one job per profile in list
    /// order. Any failure rolls back the batch and every job. A repeat of the same key with
    /// identical parameters returns the stored batch with `created` false.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidBatch`], [`StoreError::InvalidProfile`] or
    /// [`StoreError::InvalidJob`] when the request fails validation,
    /// [`StoreError::UnknownProfile`] when a profile has no version,
    /// [`StoreError::KeyConflict`] when the key exists with other parameters and
    /// [`StoreError::Database`] when a query fails.
    pub async fn submit_batch(
        &self,
        request: &SubmitBatchRequest,
    ) -> Result<SubmitBatchReply, StoreError> {
        batches::submit(&self.pool, request).await
    }

    /// Reads the profile blob a running job pins, authorised against its lease.
    ///
    /// The job must be `RUNNING` at `attempt` on `box_name` with an unexpired lease. A job
    /// that does not exist gives the same error as a lease mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when `job_id` fails validation,
    /// [`StoreError::LeaseDenied`] when no job matches the lease,
    /// [`StoreError::UnknownProfile`] when the leased job pins no profile,
    /// [`StoreError::OutOfRange`] when the stored blob fails the hash check and
    /// [`StoreError::Database`] when the query fails.
    pub async fn get_profile_blob(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &BoxName,
    ) -> Result<GetProfileBlobReply, StoreError> {
        validate_job_id(job_id)?;
        profiles::blob_for_lease(&self.pool, job_id, attempt, box_name.as_str()).await
    }

    /// Cancels a job.
    ///
    /// One statement decides by the stored state. A `QUEUED` job becomes `CANCELLED` at
    /// once with `finished_at` set. A `RUNNING` job only gets `cancel_requested`; its box
    /// sees the flag on the next report and ends the job. Any other state is returned
    /// unchanged, so a repeat cancel is safe.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when `job_id` fails validation,
    /// [`StoreError::NotFound`] when no job has it, and [`StoreError::Database`] when the
    /// statement fails.
    pub async fn cancel_job(&self, job_id: &str) -> Result<Job, StoreError> {
        validate_job_id(job_id)?;
        let row = sqlx::query(CANCEL_JOB)
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        job_from_row(&row)
    }

    /// Records a progress or final report from the box that holds the job and renews its
    /// lease.
    ///
    /// One statement matches the job id, the attempt and the box on a `RUNNING` row, then
    /// stores `phase` and `progress` and moves the lease expiry to one store lease from
    /// now. Only that holder can append `chunks`, in the same transaction. `phase` is cut
    /// to [`MAX_PHASE_CHARS`] characters and `progress` to [`MAX_PROGRESS_CHARS`].
    ///
    /// With `terminal_state` set to `SUCCEEDED`, `FAILED` or `CANCELLED`, the same
    /// statement also ends the job: it stores the state, `finished_at`, `exit_code`,
    /// `error` (cut to [`crate::jobs::MAX_ERROR_CHARS`] characters), `pr_url` and `branch`. The row is
    /// then no longer `RUNNING`, so a second final report is stale. Result fields on a
    /// report without `terminal_state` are ignored.
    ///
    /// A chunk whose `seq` is already stored is skipped and counts as acked. A report
    /// carries at most [`MAX_CHUNKS_PER_REPORT`] chunks, each `seq` at least 1 and strictly
    /// greater than the one before it. Each stored chunk is charged its text length or
    /// [`MIN_CHUNK_COST_BYTES`], whichever is larger. Once the charge would pass
    /// [`MAX_TRANSCRIPT_BYTES`] or the row count would pass [`MAX_TRANSCRIPT_ROWS`], one
    /// marker row with `truncated` set takes the first dropped `seq`, and that chunk and
    /// every later one is dropped and acked. All new chunks go in with one
    /// `INSERT ... ON CONFLICT DO NOTHING`.
    ///
    /// The reply carries the new expiry, the cancel flag, `transcript_truncated` and
    /// `acked_through_seq`, the end of the contiguous stored prefix starting at 1. After
    /// truncation it also covers the dropped chunks of this report.
    ///
    /// A `CANCELLED` final report matches only when `cancel_requested` is set.
    ///
    /// Telemetry `events` and the `summary` go in through [`crate::telemetry`] in the same
    /// transaction, so only the holder of the running job can write them. A repeated event
    /// `seq` is skipped, and the summary replaces the stored snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidJob`] when the terminal state, `pr_url`, `error` or
    /// `branch` is invalid, [`StoreError::InvalidChunk`] when a report has too many chunks,
    /// a `seq` is 0, out of the database range or not increasing, or a chunk text holds a
    /// NUL character, [`StoreError::TelemetryTooLarge`] when a report carries too many
    /// events, [`StoreError::InvalidTelemetry`] when an event or the summary holds a value
    /// the store cannot keep, [`StoreError::StaleReport`] when no running row matches the job,
    /// attempt and box (a reaped `LOST` row no longer matches) or a `CANCELLED` report
    /// arrives without a cancel request, and [`StoreError::Database`] when a statement
    /// fails. A failed call stores nothing.
    pub async fn report_job(
        &self,
        box_name: &BoxName,
        request: &ReportJobRequest,
    ) -> Result<ReportJobReply, StoreError> {
        let job_id = request.job_id.as_str();
        let attempt = i32::try_from(request.attempt).map_err(|_| StoreError::StaleReport)?;
        let terminal = validate_terminal(request)?;
        let rows = check_chunks(&request.chunks)?;
        let telemetry = telemetry::check(&request.events, request.summary.as_ref())?;
        let phase: String = request.phase.chars().take(MAX_PHASE_CHARS).collect();
        let progress: String = request.progress.chars().take(MAX_PROGRESS_CHARS).collect();
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(REPORT_JOB)
            .bind(job_id)
            .bind(attempt)
            .bind(box_name.as_str())
            .bind(&phase)
            .bind(&progress)
            .bind(self.lease.as_secs_f64())
            .bind(terminal.as_ref().map(|t| t.state))
            .bind(terminal.as_ref().and_then(|t| t.pr_url.as_deref()))
            .bind(terminal.as_ref().and_then(|t| t.error.as_deref()))
            .bind(terminal.as_ref().and_then(|t| t.exit_code))
            .bind(terminal.as_ref().and_then(|t| t.branch.as_deref()))
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::StaleReport)?;
        let lease_ms: Option<i64> = row.try_get("lease_ms")?;
        let cancel_requested: bool = row.try_get("cancel_requested")?;
        let stored: i64 = row.try_get("transcript_bytes")?;
        let mut bytes =
            usize::try_from(stored).map_err(|_| StoreError::OutOfRange("transcript"))?;
        let (row_count, mut truncated): (i64, bool) = sqlx::query_as(TRANSCRIPT_STATE)
            .bind(job_id)
            .fetch_one(&mut *tx)
            .await?;
        if !rows.is_empty() {
            let seqs: Vec<i64> = rows.iter().map(|row| row.0).collect();
            let known: HashSet<i64> = sqlx::query_scalar(TRANSCRIPT_KNOWN_SEQS)
                .bind(job_id)
                .bind(&seqs)
                .fetch_all(&mut *tx)
                .await?
                .into_iter()
                .collect();
            let plan = plan_chunks(&rows, &known, bytes, row_count, truncated);
            (bytes, truncated) = (plan.bytes, plan.truncated);
            if !plan.seqs.is_empty() {
                sqlx::query(INSERT_CHUNKS)
                    .bind(job_id)
                    .bind(&plan.seqs)
                    .bind(&plan.ts_ms)
                    .bind(&plan.text)
                    .bind(&plan.marks)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(SET_TRANSCRIPT_BYTES)
                    .bind(job_id)
                    .bind(i64::try_from(bytes).map_err(|_| StoreError::OutOfRange("transcript"))?)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        telemetry::persist(&mut tx, job_id, &telemetry).await?;
        let mut acked: i64 = sqlx::query_scalar(TRANSCRIPT_PREFIX)
            .bind(job_id)
            .fetch_one(&mut *tx)
            .await?;
        if truncated && let Some(last) = rows.last() {
            acked = acked.max(last.0);
        }
        tx.commit().await?;
        Ok(ReportJobReply {
            lease_expires_at_ms: ms(lease_ms, "lease")?.unwrap_or_default(),
            cancel_requested,
            acked_through_seq: u64::try_from(acked).map_err(|_| StoreError::OutOfRange("seq"))?,
            transcript_truncated: truncated,
        })
    }

    /// Marks every `RUNNING` job whose lease has expired as `LOST` and returns how many.
    ///
    /// One statement tests `state = 'RUNNING'` and `lease_expires_at < now()` and sets
    /// `state`, `finished_at` and the fixed `error` text `lease expired`, so a report that
    /// renews the lease first wins and a report that arrives after the reap is stale. A
    /// `LOST` job is never retried: the box may have pushed commits before it vanished.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn reap_expired(&self) -> Result<u64, StoreError> {
        let done = sqlx::query(REAP_EXPIRED).execute(&self.pool).await?;
        Ok(done.rows_affected())
    }

    /// Deletes up to `limit` event rows of terminal jobs finished more than `days` days ago.
    ///
    /// The cutoff is `now()` in the database minus `days`, measured from `finished_at` and
    /// from `created_at` when that is null. Rows another transaction holds are skipped.
    /// Jobs in `QUEUED` or `RUNNING` are never touched. Returns the rows deleted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn prune_events(&self, days: i32, limit: i64) -> Result<u64, StoreError> {
        let done = sqlx::query(PRUNE_EVENTS)
            .bind(days)
            .bind(limit)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    /// Deletes up to `limit` summary rows by the same rule as [`Store::prune_events`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn prune_summaries(&self, days: i32, limit: i64) -> Result<u64, StoreError> {
        let done = sqlx::query(PRUNE_SUMMARIES)
            .bind(days)
            .bind(limit)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    /// Starts a `REPEATABLE READ`, read only transaction, so every query in it sees one
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the transaction cannot start.
    pub async fn begin_read(&self) -> Result<Transaction<'static, Postgres>, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
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
        let mut tx = self.begin_read().await?;
        let as_of_ms = count(
            sqlx::query_scalar::<_, i64>(NOW_MS)
                .fetch_one(&mut *tx)
                .await?,
            "as_of_ms",
        )?;
        #[cfg(test)]
        if let Some(gate) = &self.snapshot_gate {
            gate.reached.notify_one();
            gate.resume.notified().await;
        }
        let box_rows = sqlx::query(LIST_BOXES)
            .bind(only)
            .fetch_all(&mut *tx)
            .await?;
        let session_rows = sqlx::query(LIST_SESSIONS)
            .bind(only)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;

        let mut sessions: BTreeMap<String, Vec<SessionView>> = BTreeMap::new();
        for row in &session_rows {
            sessions
                .entry(row.try_get("box")?)
                .or_default()
                .push(session_view(row)?);
        }
        let mut bad_counts = 0;
        let mut boxes = Vec::with_capacity(box_rows.len());
        for row in &box_rows {
            let name: String = row.try_get("box")?;
            let status: String = row.try_get("status")?;
            let sessions = sessions.remove(&name).unwrap_or_default();
            boxes.push(BoxView {
                sessions,
                ..box_view(row, name, &status, &mut bad_counts)?
            });
        }
        if bad_counts > 0 {
            tracing::warn!(bad_counts, "stored queue values are not counts; read as 0");
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

fn box_view(row: &PgRow, name: String, status: &str, bad: &mut u32) -> Result<BoxView, StoreError> {
    let heartbeat_age: Option<i64> = row.try_get("heartbeat_age_s")?;
    Ok(BoxView {
        hostname: row.try_get("hostname")?,
        status: box_status(status).into(),
        heartbeat_age_s: heartbeat_age
            .map(|age| count(age, "heartbeat_age_s"))
            .transpose()?,
        boot_id: row.try_get("boot_id")?,
        fleetd_version: row.try_get("fleetd_version")?,
        queue_pending: parse_count(row.try_get("queue_pending")?, bad),
        queue_oldest_age_s: parse_count(row.try_get("queue_oldest_age_s")?, bad),
        sessions: Vec::new(),
        r#box: name,
    })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    const GATE_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn heartbeat_for(name: &str) -> HeartbeatRequest {
        HeartbeatRequest {
            r#box: name.to_owned(),
            ..HeartbeatRequest::default()
        }
    }

    #[sqlx::test]
    async fn list_fleet_ignores_commits_made_after_its_snapshot(pool: PgPool) {
        let [first, second] = [1, 2].map(|n| format!("box-{n}"));
        let mut store = Store::new(pool);
        let gate = Arc::new(SnapshotGate::default());
        store.snapshot_gate = Some(gate.clone());
        let name = BoxName::new(&first).unwrap();
        store
            .heartbeat(&name, &heartbeat_for(&first))
            .await
            .unwrap();
        let reader = store.clone();
        let read = tokio::spawn(async move { reader.list_fleet(None).await });
        tokio::time::timeout(GATE_TIMEOUT, gate.reached.notified())
            .await
            .unwrap_or_else(|_| panic!("list_fleet never reached the snapshot gate"));
        let late = BoxName::new(&second).unwrap();
        store
            .heartbeat(&late, &heartbeat_for(&second))
            .await
            .unwrap();
        gate.resume.notify_one();
        let (_, boxes) = tokio::time::timeout(GATE_TIMEOUT, read)
            .await
            .unwrap_or_else(|_| panic!("list_fleet did not finish after the gate resumed"))
            .unwrap()
            .unwrap();
        assert_eq!(boxes.len(), 1);
        store.snapshot_gate = None;
        let (_, boxes) = store.list_fleet(None).await.unwrap();
        assert_eq!(boxes.len(), 2);
    }

    #[sqlx::test]
    async fn list_fleet_warns_once_for_many_bad_counts(pool: PgPool) {
        let store = Store::new(pool.clone());
        for n in 0..3 {
            let raw = format!("box-{n}");
            let name = BoxName::new(&raw).unwrap();
            store.heartbeat(&name, &heartbeat_for(&raw)).await.unwrap();
        }
        sqlx::query(
            "UPDATE boxes SET state = jsonb_set(jsonb_set(state, '{queue_pending}', '\"x\"'), '{queue_oldest_age_s}', '\"y\"')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let (_, boxes) = store.list_fleet(None).await.unwrap();
        drop(guard);
        assert_eq!(boxes.len(), 3);
        let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(output.matches("not counts").count(), 1, "{output}");
        assert!(output.contains("bad_counts=6"), "{output}");
    }

    #[test]
    fn parse_count_tallies_bad_values_without_logging() {
        let mut bad = 0;
        assert_eq!(parse_count(None, &mut bad), 0);
        assert_eq!(parse_count(Some("12".into()), &mut bad), 12);
        assert_eq!(bad, 0);
        assert_eq!(parse_count(Some("junk".into()), &mut bad), 0);
        assert_eq!(parse_count(Some("-1".into()), &mut bad), 0);
        assert_eq!(bad, 2);
    }
}

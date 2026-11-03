//! Timing store and RPC logic.

use std::time::Duration;

use fleet_core::BoxName;
use fleet_core::timing::Summary;
use fleet_proto::v1::{
    GetJobTimingReply, GetJobTimingRequest, ReportShellLogReply, ReportShellLogRequest,
    ReportTimingReply, ReportTimingRequest, ShellCommand, StreamShellLogChunk,
    StreamShellLogRequest, TimingSpan, TimingSummary,
};
use fleet_proto::{
    MAX_COMMAND_BYTES, MAX_SHELL_COMMANDS, MAX_SHELL_LOG_BYTES, MAX_SPANS, MAX_TIMING_NAME_BYTES,
    ShellCommandRecord, TimingSpanRecord, shell_commands_from_wire, shell_status_name,
    spans_from_wire, validate_shell_log_bytes, validate_shell_log_command_id,
    validate_shell_log_seq, validate_shell_log_status,
};
use sqlx::{PgPool, Row};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tonic::Status;
use tonic::codegen::BoxStream;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;

use crate::jobs::validate_job_id;

/// Most distinct command ids one job may log.
pub const MAX_LOG_COMMANDS_PER_JOB: usize = 256;

/// Most chunk bytes one job may store across all its commands.
pub const MAX_LOG_BYTES_PER_JOB: usize = 4 * 1024 * 1024;

/// Pause between database polls while a stream follows a command.
pub const STREAM_POLL: Duration = Duration::from_millis(250);

/// Longest one stream follows a command before it ends and the client reconnects with
/// `from_seq`.
pub const STREAM_MAX_WAIT: Duration = Duration::from_secs(600);

/// Clock skew a report may carry: the end of the reported wall window may lie this far past
/// the server clock, and a span may end this far past the reported wall time.
pub const WINDOW_TOLERANCE_MS: u64 = 30_000;

/// Refusal when the five parts do not add up to `wall_ms`.
pub const REASON_PARTS_SUM: &str = "timing parts do not sum to wall time";

/// Refusal when a span lies outside the job window.
pub const REASON_SPAN_OUTSIDE: &str = "timing span lies outside the job window";

/// Refusal when the reported wall window ends after the server clock.
pub const REASON_WINDOW_AHEAD: &str = "timing wall time runs past the present";

const STREAM_BATCH: i64 = 64;
const STREAM_QUEUE: usize = 16;

const LOCK_REPORTED_JOB: &str = "\
SELECT (EXTRACT(EPOCH FROM claimed_at) * 1000)::bigint, \
(EXTRACT(EPOCH FROM now()) * 1000)::bigint \
FROM jobs WHERE job_id = $1 AND attempt = $2 AND state = 'RUNNING' \
AND box = $3 AND lease_expires_at > now() FOR UPDATE";

const UPSERT_TIMING: &str = "\
INSERT INTO job_timing (job_id, wall_ms, api_wait_ms, tool_ms, shell_ms, idle_ms, overhead_ms) \
VALUES ($1, $2, $3, $4, $5, $6, $7) \
ON CONFLICT (job_id) DO UPDATE SET wall_ms = excluded.wall_ms, \
api_wait_ms = excluded.api_wait_ms, tool_ms = excluded.tool_ms, shell_ms = excluded.shell_ms, \
idle_ms = excluded.idle_ms, overhead_ms = excluded.overhead_ms, updated_at = now()";

const DELETE_SPANS: &str = "DELETE FROM job_timing_spans WHERE job_id = $1";

const DELETE_COMMANDS: &str = "DELETE FROM job_shell_commands WHERE job_id = $1";

const INSERT_SPANS: &str = "\
INSERT INTO job_timing_spans (job_id, seq, kind, start_ms, end_ms, name, tool_use_id) \
SELECT $1, t.seq, t.kind, t.start_ms, t.end_ms, t.name, t.tool_use_id \
FROM unnest($2::int[], $3::text[], $4::bigint[], $5::bigint[], $6::text[], $7::text[]) \
AS t (seq, kind, start_ms, end_ms, name, tool_use_id)";

const INSERT_COMMANDS: &str = "\
INSERT INTO job_shell_commands (job_id, seq, id, command, background, started_ms, ended_ms, \
duration_ms, exit_code, log, log_truncated, ended_by) \
SELECT $1, t.seq, t.id, t.command, t.background, t.started_ms, t.ended_ms, t.duration_ms, \
t.exit_code, t.log, t.log_truncated, t.ended_by \
FROM unnest($2::int[], $3::text[], $4::text[], $5::bool[], $6::bigint[], $7::bigint[], \
$8::bigint[], $9::int[], $10::text[], $11::bool[], $12::text[]) \
AS t (seq, id, command, background, started_ms, ended_ms, duration_ms, exit_code, log, \
log_truncated, ended_by)";

fn stored(value: u64) -> Result<i64, Status> {
    i64::try_from(value).map_err(|_| Status::invalid_argument("timing field is out of range"))
}

fn index(position: usize) -> Result<i32, Status> {
    i32::try_from(position).map_err(|_| Status::invalid_argument("too many timing rows"))
}

fn parts_sum_to_wall(wire: &TimingSummary) -> bool {
    [
        wire.api_wait_ms,
        wire.tool_ms,
        wire.shell_ms,
        wire.idle_ms,
        wire.overhead_ms,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
        == Some(wire.wall_ms)
}

/// Refuses a report whose wall window runs past the server clock or whose spans leave the
/// job window.
///
/// Span times are job-relative milliseconds: the job window is `0..wall_ms` and a span may
/// end at most [`WINDOW_TOLERANCE_MS`] past `wall_ms`. The claim time and the server clock,
/// both epoch milliseconds, only bound the wall time: the window from the claim time to
/// `wall_ms` after it must end no later than now plus the tolerance.
fn check_window(
    wall_ms: u64,
    spans: &[TimingSpanRecord],
    claimed_ms: u64,
    now_ms: u64,
) -> Result<(), Status> {
    let refuse = |reason: &'static str| Status::invalid_argument(reason);
    let job_end = claimed_ms
        .checked_add(wall_ms)
        .ok_or_else(|| refuse(REASON_WINDOW_AHEAD))?;
    if job_end > now_ms.saturating_add(WINDOW_TOLERANCE_MS) {
        return Err(refuse(REASON_WINDOW_AHEAD));
    }
    let latest = wall_ms.saturating_add(WINDOW_TOLERANCE_MS);
    if spans
        .iter()
        .any(|record| record.span.interval.end_ms() > latest)
    {
        return Err(refuse(REASON_SPAN_OUTSIDE));
    }
    Ok(())
}

fn kind_name(record: &TimingSpanRecord) -> Result<&'static str, Status> {
    use fleet_core::timing::SpanKind;
    match record.span.kind {
        SpanKind::ApiWait => Ok("api"),
        SpanKind::Tool => Ok("tool"),
        SpanKind::Shell => Ok("shell"),
        SpanKind::BgShell => Ok("bg_shell"),
        _ => Err(Status::invalid_argument("unknown timing span kind")),
    }
}

/// Stores the timing a box reports for one job, replacing any earlier report.
///
/// The `box` field of the request is ignored: `box_name` is the validated reporter. The
/// report is accepted only while the job is `RUNNING` at the reported attempt with an
/// unexpired lease held by `box_name`. That row is locked `FOR UPDATE` for the
/// whole transaction, so two reports for one job run one after the other and the later one
/// replaces the summary, every span and every shell command of the earlier one. The wire
/// converters in `fleet-proto` own the validation: caps of `MAX_SPANS` and
/// `MAX_SHELL_COMMANDS`, a log of at most `MAX_SHELL_LOG_BYTES` per command and text rules.
///
/// The lease is checked first: a box that does not hold it gets `FAILED_PRECONDITION`
/// whatever its body holds. The server then does not trust the box's arithmetic. Before any
/// insert it checks, with checked integer addition, that the parts sum to `wall_ms`
/// ([`REASON_PARTS_SUM`]); that the window from the claim time to `wall_ms` after it ends no
/// later than now plus [`WINDOW_TOLERANCE_MS`] ([`REASON_WINDOW_AHEAD`]); and that every span,
/// in job-relative milliseconds, ends within [`WINDOW_TOLERANCE_MS`] of `wall_ms`
/// ([`REASON_SPAN_OUTSIDE`]). The wire has no agent window, so the server does not recompute
/// the summary from the spans.
///
/// # Errors
/// `INVALID_ARGUMENT` for a missing summary, a fixed reason above or any value a converter
/// refuses,
/// `FAILED_PRECONDITION` when no running lease matches the box, job and attempt, and
/// `UNAVAILABLE` when a statement fails.
pub async fn store_timing(
    pool: &PgPool,
    box_name: &BoxName,
    request: &ReportTimingRequest,
) -> Result<ReportTimingReply, Status> {
    let stale = || Status::failed_precondition("report does not match the running job");
    let attempt = i32::try_from(request.attempt).map_err(|_| stale())?;
    let mut tx = pool.begin().await.map_err(|e| storage_unavailable(&e))?;
    let locked = sqlx::query(LOCK_REPORTED_JOB)
        .bind(&request.job_id)
        .bind(attempt)
        .bind(box_name.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?
        .ok_or_else(stale)?;
    let claimed = locked
        .try_get::<Option<i64>, _>(0)
        .map_err(|e| storage_unavailable(&e))?
        .and_then(|ms| u64::try_from(ms).ok())
        .ok_or_else(stale)?;
    let now = locked
        .try_get::<i64, _>(1)
        .map_err(|e| storage_unavailable(&e))?;
    let now = u64::try_from(now).map_err(|_| stale())?;
    let invalid = |err: fleet_proto::TimingConvertError| Status::invalid_argument(err.to_string());
    let summary = request
        .summary
        .ok_or_else(|| Status::invalid_argument("timing summary is missing"))?;
    if !parts_sum_to_wall(&summary) {
        return Err(Status::invalid_argument(REASON_PARTS_SUM));
    }
    let wall = summary.wall_ms;
    let summary = Summary::try_from(summary).map_err(invalid)?;
    let spans = spans_from_wire(request.spans.clone()).map_err(invalid)?;
    let commands = shell_commands_from_wire(request.shell_commands.clone()).map_err(invalid)?;
    check_window(wall, &spans, claimed, now)?;
    sqlx::query(UPSERT_TIMING)
        .bind(&request.job_id)
        .bind(stored(wall)?)
        .bind(stored(summary.api_wait_ms)?)
        .bind(stored(summary.tool_ms)?)
        .bind(stored(summary.shell_ms)?)
        .bind(stored(summary.idle_ms)?)
        .bind(stored(summary.overhead_ms)?)
        .execute(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    for delete in [DELETE_SPANS, DELETE_COMMANDS] {
        sqlx::query(delete)
            .bind(&request.job_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_unavailable(&e))?;
    }
    insert_spans(&mut tx, &request.job_id, &spans).await?;
    insert_commands(&mut tx, &request.job_id, &commands).await?;
    tx.commit().await.map_err(|e| storage_unavailable(&e))?;
    Ok(ReportTimingReply {})
}

async fn insert_spans(
    tx: &mut sqlx::PgConnection,
    job_id: &str,
    spans: &[TimingSpanRecord],
) -> Result<(), Status> {
    if spans.is_empty() {
        return Ok(());
    }
    let (mut seqs, mut kinds, mut starts, mut ends) = (vec![], vec![], vec![], vec![]);
    let (mut names, mut uses) = (vec![], vec![]);
    for (position, record) in spans.iter().enumerate() {
        seqs.push(index(position)?);
        kinds.push(kind_name(record)?.to_owned());
        starts.push(stored(record.span.interval.start_ms())?);
        ends.push(stored(record.span.interval.end_ms())?);
        names.push(record.name.clone());
        uses.push(record.tool_use_id.clone());
    }
    sqlx::query(INSERT_SPANS)
        .bind(job_id)
        .bind(seqs)
        .bind(kinds)
        .bind(starts)
        .bind(ends)
        .bind(names)
        .bind(uses)
        .execute(tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    Ok(())
}

async fn insert_commands(
    tx: &mut sqlx::PgConnection,
    job_id: &str,
    commands: &[ShellCommandRecord],
) -> Result<(), Status> {
    if commands.is_empty() {
        return Ok(());
    }
    let (mut seqs, mut ids, mut texts, mut background) = (vec![], vec![], vec![], vec![]);
    let (mut started, mut ended, mut durations) = (vec![], vec![], vec![]);
    let (mut codes, mut logs, mut cut, mut by) = (vec![], vec![], vec![], vec![]);
    for (position, record) in commands.iter().enumerate() {
        seqs.push(index(position)?);
        ids.push(record.id.clone());
        texts.push(record.command.clone());
        background.push(record.background);
        started.push(stored(record.started_ms)?);
        ended.push(record.ended_ms.map(stored).transpose()?);
        durations.push(stored(record.duration_ms)?);
        codes.push(record.exit_code);
        logs.push(record.log.clone());
        cut.push(record.log_truncated);
        by.push(record.ended_by.clone());
    }
    sqlx::query(INSERT_COMMANDS)
        .bind(job_id)
        .bind(seqs)
        .bind(ids)
        .bind(texts)
        .bind(background)
        .bind(started)
        .bind(ended)
        .bind(durations)
        .bind(codes)
        .bind(logs)
        .bind(cut)
        .bind(by)
        .execute(tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    Ok(())
}

const SELECT_TIMING_OWNER: &str = "\
SELECT 1 FROM jobs WHERE job_id = $1 AND ($2::bigint IS NULL OR user_id = $2)";

const SELECT_TIMING: &str = "\
SELECT wall_ms, api_wait_ms, tool_ms, shell_ms, idle_ms, overhead_ms \
FROM job_timing WHERE job_id = $1";

const SELECT_SPANS: &str = "\
SELECT kind, start_ms, end_ms, name, tool_use_id \
FROM job_timing_spans WHERE job_id = $1 ORDER BY seq LIMIT $2";

const SELECT_COMMANDS: &str = "\
SELECT id, command, background, started_ms, ended_ms, duration_ms, exit_code, log, \
log_truncated, ended_by FROM job_shell_commands WHERE job_id = $1 ORDER BY seq LIMIT $2";

fn unreadable() -> Status {
    Status::internal("stored timing is unreadable")
}

fn unsigned(value: i64) -> Result<u64, Status> {
    u64::try_from(value).map_err(|_| unreadable())
}

fn read<'r, T>(row: &'r sqlx::postgres::PgRow, column: &str) -> Result<T, Status>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column).map_err(|_| unreadable())
}

fn span_kind(text: &str) -> Result<i32, Status> {
    use fleet_proto::v1::TimingSpanKind;
    let kind = match text {
        "api" => TimingSpanKind::Api,
        "tool" => TimingSpanKind::Tool,
        "shell" => TimingSpanKind::Shell,
        "bg_shell" => TimingSpanKind::BgShell,
        _ => return Err(unreadable()),
    };
    Ok(kind as i32)
}

fn summary_from_row(row: &sqlx::postgres::PgRow) -> Result<TimingSummary, Status> {
    let summary = TimingSummary {
        wall_ms: unsigned(read(row, "wall_ms")?)?,
        api_wait_ms: unsigned(read(row, "api_wait_ms")?)?,
        tool_ms: unsigned(read(row, "tool_ms")?)?,
        shell_ms: unsigned(read(row, "shell_ms")?)?,
        idle_ms: unsigned(read(row, "idle_ms")?)?,
        overhead_ms: unsigned(read(row, "overhead_ms")?)?,
    };
    if parts_sum_to_wall(&summary) {
        Ok(summary)
    } else {
        Err(unreadable())
    }
}

fn span_from_row(row: &sqlx::postgres::PgRow) -> Result<TimingSpan, Status> {
    let kind: String = read(row, "kind")?;
    let name: String = read(row, "name")?;
    if name.len() > MAX_TIMING_NAME_BYTES {
        return Err(unreadable());
    }
    Ok(TimingSpan {
        kind: span_kind(&kind)?,
        start_ms: unsigned(read(row, "start_ms")?)?,
        end_ms: unsigned(read(row, "end_ms")?)?,
        name,
        tool_use_id: read(row, "tool_use_id")?,
    })
}

fn command_from_row(row: &sqlx::postgres::PgRow) -> Result<ShellCommand, Status> {
    let command: String = read(row, "command")?;
    let log: String = read(row, "log")?;
    if command.len() > MAX_COMMAND_BYTES || log.len() > MAX_SHELL_LOG_BYTES {
        return Err(unreadable());
    }
    let ended: Option<i64> = read(row, "ended_ms")?;
    Ok(ShellCommand {
        id: read(row, "id")?,
        command,
        background: read(row, "background")?,
        started_ms: unsigned(read(row, "started_ms")?)?,
        ended_ms: ended.map(unsigned).transpose()?,
        duration_ms: unsigned(read(row, "duration_ms")?)?,
        exit_code: read(row, "exit_code")?,
        log,
        log_truncated: read(row, "log_truncated")?,
        ended_by: read(row, "ended_by")?,
    })
}

/// Reads the stored timing of one job for `owner`.
///
/// `Some(user)` reads only that user's jobs; `None` is the box token and reads any job. The
/// job id is validated before any query. An unknown job and another user's job both answer
/// the same `NOT_FOUND`, so the reply is no existence oracle. A job that never got a report
/// answers `Ok` with `summary` unset and no spans or commands: absent, never zeros. All
/// reads run in one repeatable-read transaction, so a concurrent replacement is seen whole or
/// not at all.
///
/// The reply is bounded: at most `MAX_SPANS` spans and `MAX_SHELL_COMMANDS` commands, each
/// name, command and log within its `fleet-proto` cap. A stored row that breaks a cap, a
/// negative number, an unknown kind or parts that do not sum to `wall_ms` fails closed with
/// `INTERNAL` instead of being sent.
///
/// # Errors
/// `INVALID_ARGUMENT` for a malformed job id, `NOT_FOUND` as above, `INTERNAL` for an
/// unreadable stored row and `UNAVAILABLE` when a statement fails.
pub async fn read_job_timing(
    pool: &PgPool,
    owner: Option<i64>,
    request: &GetJobTimingRequest,
) -> Result<GetJobTimingReply, Status> {
    validate_job_id(&request.job_id)
        .map_err(|_| Status::invalid_argument("invalid job request"))?;
    let mut tx = pool.begin().await.map_err(|e| storage_unavailable(&e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    sqlx::query(SELECT_TIMING_OWNER)
        .bind(&request.job_id)
        .bind(owner)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?
        .ok_or_else(|| Status::not_found("job not found"))?;
    let Some(row) = sqlx::query(SELECT_TIMING)
        .bind(&request.job_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?
    else {
        return Ok(GetJobTimingReply::default());
    };
    let summary = summary_from_row(&row)?;
    let span_cap = i64::try_from(MAX_SPANS).map_err(|_| unreadable())?;
    let span_rows = sqlx::query(SELECT_SPANS)
        .bind(&request.job_id)
        .bind(span_cap.saturating_add(1))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    if span_rows.len() > MAX_SPANS {
        return Err(unreadable());
    }
    let command_cap = i64::try_from(MAX_SHELL_COMMANDS).map_err(|_| unreadable())?;
    let command_rows = sqlx::query(SELECT_COMMANDS)
        .bind(&request.job_id)
        .bind(command_cap.saturating_add(1))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    if command_rows.len() > MAX_SHELL_COMMANDS {
        return Err(unreadable());
    }
    Ok(GetJobTimingReply {
        summary: Some(summary),
        spans: span_rows
            .iter()
            .map(span_from_row)
            .collect::<Result<_, _>>()?,
        shell_commands: command_rows
            .iter()
            .map(command_from_row)
            .collect::<Result<_, _>>()?,
    })
}

/// Waits a stream applies while it follows a command.
#[derive(Debug, Clone, Copy)]
pub struct StreamLimits {
    /// Pause between database polls.
    pub poll: Duration,
    /// Longest the stream stays open.
    pub max_wait: Duration,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            poll: STREAM_POLL,
            max_wait: STREAM_MAX_WAIT,
        }
    }
}

const LOCK_LEASED_JOB: &str = "\
SELECT 1 FROM jobs WHERE job_id = $1 AND attempt = $2 AND state = 'RUNNING' \
AND lease_expires_at > now() FOR NO KEY UPDATE";

const LOG_USAGE: &str = "\
SELECT count(DISTINCT command_id), COALESCE(sum(octet_length(bytes)), 0)::bigint, \
COALESCE(bool_or(command_id = $2), false), \
COALESCE(bool_or(command_id = $2 AND seq = $3), false) \
FROM job_shell_log_chunks WHERE job_id = $1";

const INSERT_LOG_CHUNK: &str = "\
INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
VALUES ($1, $2, $3, $4, $5) ON CONFLICT (job_id, command_id, seq) DO NOTHING";

const SELECT_LOG_CHUNKS: &str = "\
SELECT seq, bytes, status FROM job_shell_log_chunks \
WHERE job_id = $1 AND command_id = $2 AND seq >= $3 ORDER BY seq LIMIT $4";

const SELECT_JOB_ENDED: &str = "\
SELECT state IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'LOST') FROM jobs WHERE job_id = $1";

fn storage_unavailable(err: &sqlx::Error) -> Status {
    tracing::error!(%err, "storage failed");
    Status::unavailable("storage unavailable")
}

/// Stores one live shell log chunk a box reports.
///
/// The `box` field of the request is ignored: the chunk is accepted only while the job is
/// `RUNNING` at the reported attempt with an unexpired lease, which names the box that holds
/// it. Resending a stored `(command_id, seq)` succeeds and keeps the first chunk. One
/// transaction holds the job row, so concurrent reports cannot pass the per-job caps
/// together.
///
/// # Errors
/// `INVALID_ARGUMENT` for a bad `command_id`, `seq`, `bytes` or `status`,
/// `FAILED_PRECONDITION` when no running lease matches the job and attempt,
/// `RESOURCE_EXHAUSTED` past [`MAX_LOG_COMMANDS_PER_JOB`] or [`MAX_LOG_BYTES_PER_JOB`],
/// and `UNAVAILABLE` when a statement fails.
pub async fn report_shell_log(
    pool: &PgPool,
    request: &ReportShellLogRequest,
) -> Result<ReportShellLogReply, Status> {
    if !validate_shell_log_command_id(&request.command_id) {
        return Err(Status::invalid_argument("invalid command id"));
    }
    if !validate_shell_log_seq(request.seq) {
        return Err(Status::invalid_argument("invalid chunk seq"));
    }
    if !validate_shell_log_bytes(&request.bytes) {
        return Err(Status::invalid_argument("chunk too large"));
    }
    let status = validate_shell_log_status(request.status)
        .and_then(shell_status_name)
        .ok_or_else(|| Status::invalid_argument("invalid command status"))?;
    let stale = || Status::failed_precondition("report does not match the running job");
    let attempt = i32::try_from(request.attempt).map_err(|_| stale())?;
    let seq = i32::try_from(request.seq).map_err(|_| stale())?;
    let mut tx = pool.begin().await.map_err(|e| storage_unavailable(&e))?;
    sqlx::query(LOCK_LEASED_JOB)
        .bind(&request.job_id)
        .bind(attempt)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?
        .ok_or_else(stale)?;
    let usage = sqlx::query(LOG_USAGE)
        .bind(&request.job_id)
        .bind(&request.command_id)
        .bind(seq)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    let read = |index: usize| {
        usage
            .try_get::<i64, _>(index)
            .map_err(|e| storage_unavailable(&e))
    };
    let (commands, stored) = (read(0)?, read(1)?);
    let flag = |index: usize| {
        usage
            .try_get::<bool, _>(index)
            .map_err(|e| storage_unavailable(&e))
    };
    let (known_command, duplicate) = (flag(2)?, flag(3)?);
    if duplicate {
        return Ok(ReportShellLogReply {});
    }
    let exhausted = |what: &'static str| Status::resource_exhausted(what);
    if !known_command && usize::try_from(commands).map_or(true, |n| n >= MAX_LOG_COMMANDS_PER_JOB) {
        return Err(exhausted("too many commands for this job"));
    }
    let total = usize::try_from(stored)
        .unwrap_or(usize::MAX)
        .saturating_add(request.bytes.len());
    if total > MAX_LOG_BYTES_PER_JOB {
        return Err(exhausted("job shell log is full"));
    }
    sqlx::query(INSERT_LOG_CHUNK)
        .bind(&request.job_id)
        .bind(&request.command_id)
        .bind(seq)
        .bind(&request.bytes)
        .bind(status)
        .execute(&mut *tx)
        .await
        .map_err(|e| storage_unavailable(&e))?;
    tx.commit().await.map_err(|e| storage_unavailable(&e))?;
    Ok(ReportShellLogReply {})
}

/// Streams the stored chunks of one shell command in seq order from `from_seq`, then the
/// ones that arrive later.
///
/// The caller must have checked that the reader owns the job. The stream ends after a chunk
/// whose status is `done` or `failed`, once the job has ended and the stored chunks are
/// drained, when `limits.max_wait` passes, when the client drops the stream, or after one
/// `UNAVAILABLE` item when a statement fails. A missing seq stops delivery at the gap until
/// the chunk arrives.
///
/// # Errors
/// `INVALID_ARGUMENT` for a bad `command_id` or `from_seq`.
pub fn stream_shell_log(
    pool: &PgPool,
    request: &StreamShellLogRequest,
    limits: StreamLimits,
) -> Result<BoxStream<StreamShellLogChunk>, Status> {
    if !validate_shell_log_command_id(&request.command_id) {
        return Err(Status::invalid_argument("invalid command id"));
    }
    if !validate_shell_log_seq(request.from_seq) {
        return Err(Status::invalid_argument("invalid from_seq"));
    }
    let (tx, rx) = mpsc::channel(STREAM_QUEUE);
    tokio::spawn(follow(
        pool.clone(),
        request.job_id.clone(),
        request.command_id.clone(),
        i32::try_from(request.from_seq).unwrap_or(i32::MAX),
        limits,
        tx,
    ));
    Ok(Box::pin(ReceiverStream::new(rx)))
}

async fn follow(
    pool: PgPool,
    job_id: String,
    command_id: String,
    mut next: i32,
    limits: StreamLimits,
    tx: mpsc::Sender<Result<StreamShellLogChunk, Status>>,
) {
    let deadline = Instant::now() + limits.max_wait;
    loop {
        let ended = match sqlx::query_scalar::<_, bool>(SELECT_JOB_ENDED)
            .bind(&job_id)
            .fetch_optional(&pool)
            .await
        {
            Ok(ended) => ended.unwrap_or(true),
            Err(err) => {
                let _ = tx.send(Err(storage_unavailable(&err))).await;
                return;
            }
        };
        let rows = match sqlx::query(SELECT_LOG_CHUNKS)
            .bind(&job_id)
            .bind(&command_id)
            .bind(next)
            .bind(STREAM_BATCH)
            .fetch_all(&pool)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.send(Err(storage_unavailable(&err))).await;
                return;
            }
        };
        for row in rows {
            let (Ok(seq), Ok(bytes), Ok(status)) = (
                row.try_get::<i32, _>("seq"),
                row.try_get::<Vec<u8>, _>("bytes"),
                row.try_get::<String, _>("status"),
            ) else {
                let _ = tx
                    .send(Err(Status::internal("stored chunk is unreadable")))
                    .await;
                return;
            };
            if seq != next {
                break;
            }
            let Some(code) = status_code(&status) else {
                let _ = tx
                    .send(Err(Status::internal("stored chunk is unreadable")))
                    .await;
                return;
            };
            let chunk = StreamShellLogChunk {
                command_id: command_id.clone(),
                seq: u32::try_from(seq).unwrap_or(0),
                bytes,
                status: code,
            };
            if tx.send(Ok(chunk)).await.is_err() {
                return;
            }
            next += 1;
            if status == "done" || status == "failed" {
                return;
            }
        }
        let now = Instant::now();
        if ended || now >= deadline {
            return;
        }
        tokio::select! {
            () = tx.closed() => return,
            () = tokio::time::sleep(limits.poll.min(deadline - now)) => {}
        }
    }
}

fn status_code(text: &str) -> Option<i32> {
    use fleet_proto::v1::ShellStatus;
    let status = match text {
        "queued" => ShellStatus::Queued,
        "running" => ShellStatus::Running,
        "done" => ShellStatus::Done,
        "failed" => ShellStatus::Failed,
        _ => return None,
    };
    Some(status as i32)
}

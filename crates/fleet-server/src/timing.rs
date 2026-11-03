//! Timing store and RPC logic.

use std::time::Duration;

use fleet_proto::v1::{
    GetJobTimingReply, GetJobTimingRequest, ReportShellLogReply, ReportShellLogRequest,
    ReportTimingReply, ReportTimingRequest, StreamShellLogChunk, StreamShellLogRequest,
};
use fleet_proto::{
    shell_status_name, validate_shell_log_bytes, validate_shell_log_command_id,
    validate_shell_log_seq, validate_shell_log_status,
};
use sqlx::{PgPool, Row};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tonic::Status;
use tonic::codegen::BoxStream;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;

/// Most distinct command ids one job may log.
pub const MAX_LOG_COMMANDS_PER_JOB: usize = 256;

/// Most chunk bytes one job may store across all its commands.
pub const MAX_LOG_BYTES_PER_JOB: usize = 4 * 1024 * 1024;

/// Pause between database polls while a stream follows a command.
pub const STREAM_POLL: Duration = Duration::from_millis(250);

/// Longest one stream follows a command before it ends and the client reconnects with
/// `from_seq`.
pub const STREAM_MAX_WAIT: Duration = Duration::from_secs(600);

const STREAM_BATCH: i64 = 64;
const STREAM_QUEUE: usize = 16;

const NOT_IMPLEMENTED: &str = "job timing is not implemented";

/// Stores the timing a box reports for one job attempt.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn report_timing(_request: &ReportTimingRequest) -> Result<ReportTimingReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Reads the stored timing of one job.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn get_job_timing(_request: &GetJobTimingRequest) -> Result<GetJobTimingReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
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

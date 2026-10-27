//! Job telemetry ingest: validation of reported events and summaries, and their storage.

use fleet_proto::v1::{JobEvent, JobEventKind, JobSummary};
use fleet_proto::{
    MAX_BUNDLE_SHA_CHARS, MAX_CLAUDE_VERSION_CHARS, MAX_EVENT_CMD_BYTES, MAX_EVENT_DETAIL_BYTES,
    MAX_EVENTS_PER_JOB, MAX_EVENTS_PER_REPORT, MAX_MODEL_BYTES, MAX_PHASE_MS, UNKNOWN_STAMP,
    is_plain_text,
};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::store::{MAX_TS_MS, StoreError, count, ms};

/// Longest stored tool name and tool call id, in bytes.
const MAX_NAME_BYTES: usize = 128;
/// Longest stored output hash, in bytes.
const MAX_HASH_BYTES: usize = 64;
/// Longest stored stop reason, result subtype and missing-figure name, in bytes.
const MAX_LABEL_BYTES: usize = 64;
/// Most missing-figure names a summary may carry.
const MAX_MISSING: usize = 32;

const INSERT_JOB_EVENTS: &str = "\
INSERT INTO job_event (job_id, seq, ts_ms, kind, tool_use_id, tool, ok, exit_code, dur_ms, \
    out_bytes, out_hash, cmd, detail) \
SELECT $1, t.seq, t.ts_ms, t.kind, t.tool_use_id, t.tool, t.ok, t.exit_code, t.dur_ms, \
    t.out_bytes, t.out_hash, t.cmd, t.detail \
FROM UNNEST($2::integer[], $3::bigint[], $4::text[], $5::text[], $6::text[], $7::boolean[], \
    $8::integer[], $9::bigint[], $10::bigint[], $11::text[], $12::text[], $13::text[]) \
    AS t(seq, ts_ms, kind, tool_use_id, tool, ok, exit_code, dur_ms, out_bytes, out_hash, \
    cmd, detail) \
ON CONFLICT (job_id, seq) DO NOTHING";

const UPSERT_JOB_SUMMARY: &str = "\
INSERT INTO job_summary (job_id, turns, duration_ms, duration_api_ms, stop_reason, \
    result_subtype, cost_est_usd, tokens_in, tokens_out, tokens_cache_read, \
    tokens_cache_write, tool_calls, tool_errors, bash_calls, bash_nonzero, denials, \
    api_retries, first_edit_ms, complete, missing, stuck_rule, stuck_at_seq, stuck_at_ms, \
    bundle_sha, claude_version, model, clone_ms, push_ms, pr_ms, queue_wait_ms) \
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
    $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, \
    (SELECT CASE WHEN claimed_at IS NULL THEN NULL \
        ELSE GREATEST(EXTRACT(EPOCH FROM (claimed_at - created_at)) * 1000, 0)::bigint END \
        FROM jobs WHERE job_id = $1)) \
ON CONFLICT (job_id) DO UPDATE SET turns = EXCLUDED.turns, \
    duration_ms = EXCLUDED.duration_ms, duration_api_ms = EXCLUDED.duration_api_ms, \
    stop_reason = EXCLUDED.stop_reason, result_subtype = EXCLUDED.result_subtype, \
    cost_est_usd = EXCLUDED.cost_est_usd, tokens_in = EXCLUDED.tokens_in, \
    tokens_out = EXCLUDED.tokens_out, tokens_cache_read = EXCLUDED.tokens_cache_read, \
    tokens_cache_write = EXCLUDED.tokens_cache_write, tool_calls = EXCLUDED.tool_calls, \
    tool_errors = EXCLUDED.tool_errors, bash_calls = EXCLUDED.bash_calls, \
    bash_nonzero = EXCLUDED.bash_nonzero, denials = EXCLUDED.denials, \
    api_retries = EXCLUDED.api_retries, first_edit_ms = EXCLUDED.first_edit_ms, \
    complete = EXCLUDED.complete, missing = EXCLUDED.missing, \
    stuck_rule = EXCLUDED.stuck_rule, stuck_at_seq = EXCLUDED.stuck_at_seq, \
    stuck_at_ms = EXCLUDED.stuck_at_ms, bundle_sha = EXCLUDED.bundle_sha, \
    claude_version = EXCLUDED.claude_version, model = EXCLUDED.model, \
    clone_ms = EXCLUDED.clone_ms, push_ms = EXCLUDED.push_ms, pr_ms = EXCLUDED.pr_ms, \
    queue_wait_ms = EXCLUDED.queue_wait_ms, updated_at = now()";

const READ_JOB_EVENTS: &str = "\
SELECT seq, ts_ms, kind, tool_use_id, tool, ok, exit_code, dur_ms, out_bytes, out_hash, cmd, \
    detail \
FROM job_event WHERE job_id = $1 AND seq > $2::bigint ORDER BY seq LIMIT $3";

const READ_JOB_SUMMARY: &str = "\
SELECT turns, duration_ms, duration_api_ms, stop_reason, result_subtype, cost_est_usd, \
    tokens_in, tokens_out, tokens_cache_read, tokens_cache_write, tool_calls, tool_errors, \
    bash_calls, bash_nonzero, denials, api_retries, first_edit_ms, complete, missing, \
    stuck_rule, stuck_at_seq, stuck_at_ms, bundle_sha, claude_version, model, \
    clone_ms, push_ms, pr_ms, queue_wait_ms \
FROM job_summary WHERE job_id = $1";

#[derive(Default)]
struct EventColumns {
    seq: Vec<i32>,
    ts_ms: Vec<i64>,
    kind: Vec<&'static str>,
    tool_use_id: Vec<Option<String>>,
    tool: Vec<Option<String>>,
    ok: Vec<Option<bool>>,
    exit_code: Vec<Option<i32>>,
    dur_ms: Vec<Option<i64>>,
    out_bytes: Vec<Option<i64>>,
    out_hash: Vec<Option<String>>,
    cmd: Vec<Option<String>>,
    detail: Vec<Option<String>>,
}

struct SummaryRow {
    figures: [Option<i64>; 14],
    stop_reason: Option<String>,
    result_subtype: Option<String>,
    cost_est_usd: Option<f64>,
    complete: bool,
    missing: Vec<String>,
    stuck_rule: Option<&'static str>,
    stuck_at_seq: Option<i64>,
    stuck_at_ms: Option<i64>,
    bundle_sha: Option<String>,
    claude_version: Option<String>,
    model: Option<String>,
    clone_ms: Option<i64>,
    push_ms: Option<i64>,
    pr_ms: Option<i64>,
}

/// Telemetry of one report after validation and clamping.
#[derive(Default)]
pub(crate) struct Checked {
    events: EventColumns,
    summary: Option<SummaryRow>,
}

fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn text(value: Option<&String>, max: usize) -> Result<Option<String>, StoreError> {
    match value {
        None => Ok(None),
        Some(raw) if raw.contains('\0') => Err(StoreError::InvalidTelemetry),
        Some(raw) => Ok(Some(cut(raw, max).to_owned())),
    }
}

fn figure(value: Option<u64>) -> Result<Option<i64>, StoreError> {
    value
        .map(|raw| i64::try_from(raw).map_err(|_| StoreError::InvalidTelemetry))
        .transpose()
}

fn phase_ms(value: Option<u64>) -> Result<Option<i64>, StoreError> {
    if value.is_some_and(|raw| raw > MAX_PHASE_MS) {
        return Err(StoreError::InvalidTelemetry);
    }
    figure(value)
}

fn stamp_field(
    value: Option<&String>,
    max: usize,
    bytes: bool,
) -> Result<Option<String>, StoreError> {
    let Some(raw) = value else { return Ok(None) };
    let size = if bytes {
        raw.len()
    } else {
        raw.chars().count()
    };
    if raw == UNKNOWN_STAMP || !is_plain_text(raw) || size > max {
        return Err(StoreError::InvalidTelemetry);
    }
    Ok(Some(raw.clone()))
}

pub(crate) fn stuck_rule_name(rule: Option<&String>) -> Result<Option<&'static str>, StoreError> {
    match rule.map(String::as_str) {
        None => Ok(None),
        Some("repeat_action_observation") => Ok(Some("repeat_action_observation")),
        Some("repeat_error") => Ok(Some("repeat_error")),
        Some("alternating") => Ok(Some("alternating")),
        Some("monologue") => Ok(Some("monologue")),
        Some(_) => Err(StoreError::InvalidTelemetry),
    }
}

fn kind_name(kind: i32) -> Result<&'static str, StoreError> {
    match JobEventKind::try_from(kind) {
        Ok(JobEventKind::Tool) => Ok("tool"),
        Ok(JobEventKind::Denial) => Ok("denial"),
        Ok(JobEventKind::ApiRetry) => Ok("api_retry"),
        Ok(JobEventKind::Phase) => Ok("phase"),
        Ok(JobEventKind::Stuck) => Ok("stuck"),
        Ok(JobEventKind::Unspecified) | Err(_) => Err(StoreError::InvalidTelemetry),
    }
}

/// Appends one event. `seq` must be below [`MAX_EVENTS_PER_JOB`], which `check` guarantees.
fn push_event(columns: &mut EventColumns, event: &JobEvent) -> Result<(), StoreError> {
    let seq = event.seq.cast_signed();
    let ts_ms =
        i64::try_from(event.ts_ms.min(MAX_TS_MS)).map_err(|_| StoreError::InvalidTelemetry)?;
    columns.seq.push(seq);
    columns.ts_ms.push(ts_ms);
    columns.kind.push(kind_name(event.kind)?);
    columns
        .tool_use_id
        .push(text(event.tool_use_id.as_ref(), MAX_NAME_BYTES)?);
    columns
        .tool
        .push(text(event.tool.as_ref(), MAX_NAME_BYTES)?);
    columns.ok.push(event.ok);
    columns.exit_code.push(event.exit_code);
    columns.dur_ms.push(figure(event.dur_ms)?);
    columns.out_bytes.push(figure(event.out_bytes)?);
    columns
        .out_hash
        .push(text(event.out_hash.as_ref(), MAX_HASH_BYTES)?);
    columns
        .cmd
        .push(text(event.cmd.as_ref(), MAX_EVENT_CMD_BYTES)?);
    columns
        .detail
        .push(text(event.detail.as_ref(), MAX_EVENT_DETAIL_BYTES)?);
    Ok(())
}

fn check_summary(summary: &JobSummary) -> Result<SummaryRow, StoreError> {
    if summary.cost_est_usd.is_some_and(|cost| !cost.is_finite())
        || summary.missing.len() > MAX_MISSING
    {
        return Err(StoreError::InvalidTelemetry);
    }
    let stuck_rule = stuck_rule_name(summary.stuck_rule.as_ref())?;
    let has_seq = summary.stuck_at_seq.is_some();
    let has_ms = summary.stuck_at_ms.is_some();
    let paired = if stuck_rule.is_some() {
        has_seq && has_ms
    } else {
        !has_seq && !has_ms
    };
    if !paired {
        return Err(StoreError::InvalidTelemetry);
    }
    let missing = summary
        .missing
        .iter()
        .map(|name| text(Some(name), MAX_LABEL_BYTES).map(Option::unwrap_or_default))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SummaryRow {
        figures: [
            figure(summary.turns)?,
            figure(summary.duration_ms)?,
            figure(summary.duration_api_ms)?,
            figure(summary.tokens_in)?,
            figure(summary.tokens_out)?,
            figure(summary.tokens_cache_read)?,
            figure(summary.tokens_cache_write)?,
            figure(summary.tool_calls)?,
            figure(summary.tool_errors)?,
            figure(summary.bash_calls)?,
            figure(summary.bash_nonzero)?,
            figure(summary.denials)?,
            figure(summary.api_retries)?,
            figure(summary.first_edit_ms)?,
        ],
        stop_reason: text(summary.stop_reason.as_ref(), MAX_LABEL_BYTES)?,
        result_subtype: text(summary.result_subtype.as_ref(), MAX_LABEL_BYTES)?,
        cost_est_usd: summary.cost_est_usd,
        complete: summary.complete,
        missing,
        stuck_rule,
        stuck_at_seq: summary.stuck_at_seq.map(i64::from),
        stuck_at_ms: figure(summary.stuck_at_ms)?,
        bundle_sha: stamp_field(summary.bundle_sha.as_ref(), MAX_BUNDLE_SHA_CHARS, false)?,
        claude_version: stamp_field(
            summary.claude_version.as_ref(),
            MAX_CLAUDE_VERSION_CHARS,
            false,
        )?,
        model: stamp_field(summary.model.as_ref(), MAX_MODEL_BYTES, true)?,
        clone_ms: phase_ms(summary.clone_ms)?,
        push_ms: phase_ms(summary.push_ms)?,
        pr_ms: phase_ms(summary.pr_ms)?,
    })
}

/// Validates the telemetry of one report.
///
/// Events with a `seq` of [`MAX_EVENTS_PER_JOB`] or more are dropped. `cmd` and `detail` are
/// cut at a UTF-8 boundary to [`MAX_EVENT_CMD_BYTES`] and [`MAX_EVENT_DETAIL_BYTES`], and
/// `ts_ms` is clamped to [`MAX_TS_MS`].
///
/// # Errors
///
/// Returns [`StoreError::TelemetryTooLarge`] when the report carries more than
/// [`MAX_EVENTS_PER_REPORT`] events, and [`StoreError::InvalidTelemetry`] for an unknown
/// event kind, a NUL character in any text, a figure above `i64::MAX`, a non-finite cost or
/// more than 32 missing-figure names, a stuck rule outside the four stable names, a stuck
/// position without a rule, or a stuck rule missing either position, or a `bundle_sha`,
/// `claude_version` or `model` that is empty, over its cap, holds a control character or is
/// the string `unknown`, or a `clone_ms`, `push_ms` or `pr_ms` above [`MAX_PHASE_MS`].
pub(crate) fn check(
    events: &[JobEvent],
    summary: Option<&JobSummary>,
) -> Result<Checked, StoreError> {
    if events.len() > MAX_EVENTS_PER_REPORT {
        return Err(StoreError::TelemetryTooLarge);
    }
    let mut columns = EventColumns::default();
    for event in events.iter().filter(|event| event.seq < MAX_EVENTS_PER_JOB) {
        push_event(&mut columns, event)?;
    }
    Ok(Checked {
        events: columns,
        summary: summary.map(check_summary).transpose()?,
    })
}

/// Stores checked telemetry in the caller's transaction.
///
/// Events insert with `ON CONFLICT DO NOTHING`, so a replayed batch changes nothing. The
/// summary is a full snapshot: it replaces the stored row, and a figure it leaves unset
/// becomes NULL.
///
/// `queue_wait_ms` is never read from the report. The row derives it from the job: the time
/// from `created_at` to `claimed_at`, which is the latest claim and equals the first lease
/// for a job on its first attempt. It is NULL while `claimed_at` is unset.
pub(crate) async fn persist(
    tx: &mut Transaction<'_, Postgres>,
    job_id: &str,
    checked: &Checked,
) -> Result<(), sqlx::Error> {
    let events = &checked.events;
    if !events.seq.is_empty() {
        sqlx::query(INSERT_JOB_EVENTS)
            .bind(job_id)
            .bind(&events.seq)
            .bind(&events.ts_ms)
            .bind(&events.kind)
            .bind(&events.tool_use_id)
            .bind(&events.tool)
            .bind(&events.ok)
            .bind(&events.exit_code)
            .bind(&events.dur_ms)
            .bind(&events.out_bytes)
            .bind(&events.out_hash)
            .bind(&events.cmd)
            .bind(&events.detail)
            .execute(&mut **tx)
            .await?;
    }
    if let Some(row) = &checked.summary {
        let [
            turns,
            duration,
            api,
            tin,
            tout,
            cread,
            cwrite,
            calls,
            errors,
            bash,
            nonzero,
            denials,
            retries,
            edit,
        ] = row.figures;
        sqlx::query(UPSERT_JOB_SUMMARY)
            .bind(job_id)
            .bind(turns)
            .bind(duration)
            .bind(api)
            .bind(&row.stop_reason)
            .bind(&row.result_subtype)
            .bind(row.cost_est_usd)
            .bind(tin)
            .bind(tout)
            .bind(cread)
            .bind(cwrite)
            .bind(calls)
            .bind(errors)
            .bind(bash)
            .bind(nonzero)
            .bind(denials)
            .bind(retries)
            .bind(edit)
            .bind(row.complete)
            .bind(&row.missing)
            .bind(row.stuck_rule)
            .bind(row.stuck_at_seq)
            .bind(row.stuck_at_ms)
            .bind(&row.bundle_sha)
            .bind(&row.claude_version)
            .bind(&row.model)
            .bind(row.clone_ms)
            .bind(row.push_ms)
            .bind(row.pr_ms)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

fn kind_from_name(name: &str) -> Result<JobEventKind, StoreError> {
    match name {
        "tool" => Ok(JobEventKind::Tool),
        "denial" => Ok(JobEventKind::Denial),
        "api_retry" => Ok(JobEventKind::ApiRetry),
        "phase" => Ok(JobEventKind::Phase),
        "stuck" => Ok(JobEventKind::Stuck),
        _ => Err(StoreError::OutOfRange("kind")),
    }
}

/// Reads up to `limit` events of a job in `seq` order.
///
/// `after` is exclusive; `None` starts at the first event, whose `seq` may be 0. The job
/// must exist: the caller checks it.
pub(crate) async fn read_events(
    pool: &PgPool,
    job_id: &str,
    after: Option<u32>,
    limit: u32,
) -> Result<Vec<JobEvent>, StoreError> {
    let after = after.map_or(-1, i64::from);
    let rows = sqlx::query(READ_JOB_EVENTS)
        .bind(job_id)
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|row| {
            let kind: String = row.try_get("kind")?;
            Ok(JobEvent {
                seq: u32::try_from(row.try_get::<i32, _>("seq")?)
                    .map_err(|_| StoreError::OutOfRange("seq"))?,
                ts_ms: count(row.try_get("ts_ms")?, "ts_ms")?,
                kind: kind_from_name(&kind)?.into(),
                tool_use_id: row.try_get("tool_use_id")?,
                tool: row.try_get("tool")?,
                ok: row.try_get("ok")?,
                exit_code: row.try_get("exit_code")?,
                dur_ms: ms(row.try_get("dur_ms")?, "dur_ms")?,
                out_bytes: ms(row.try_get("out_bytes")?, "out_bytes")?,
                out_hash: row.try_get("out_hash")?,
                cmd: row.try_get("cmd")?,
                detail: row.try_get("detail")?,
            })
        })
        .collect()
}

/// Reads the stored summary of a job, or `None` when no report has carried one.
pub(crate) async fn read_summary(
    pool: &PgPool,
    job_id: &str,
) -> Result<Option<JobSummary>, StoreError> {
    let Some(row) = sqlx::query(READ_JOB_SUMMARY)
        .bind(job_id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let figure =
        |name: &'static str| -> Result<Option<u64>, StoreError> { ms(row.try_get(name)?, name) };
    Ok(Some(JobSummary {
        turns: figure("turns")?,
        duration_ms: figure("duration_ms")?,
        duration_api_ms: figure("duration_api_ms")?,
        stop_reason: row.try_get("stop_reason")?,
        result_subtype: row.try_get("result_subtype")?,
        cost_est_usd: row.try_get("cost_est_usd")?,
        tokens_in: figure("tokens_in")?,
        tokens_out: figure("tokens_out")?,
        tokens_cache_read: figure("tokens_cache_read")?,
        tokens_cache_write: figure("tokens_cache_write")?,
        tool_calls: figure("tool_calls")?,
        tool_errors: figure("tool_errors")?,
        bash_calls: figure("bash_calls")?,
        bash_nonzero: figure("bash_nonzero")?,
        denials: figure("denials")?,
        api_retries: figure("api_retries")?,
        first_edit_ms: figure("first_edit_ms")?,
        complete: row.try_get("complete")?,
        missing: row.try_get("missing")?,
        stuck_rule: row.try_get("stuck_rule")?,
        stuck_at_seq: ms(row.try_get("stuck_at_seq")?, "stuck_at_seq")?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| StoreError::OutOfRange("stuck_at_seq"))?,
        stuck_at_ms: figure("stuck_at_ms")?,
        bundle_sha: row.try_get("bundle_sha")?,
        claude_version: row.try_get("claude_version")?,
        model: row.try_get("model")?,
        clone_ms: figure("clone_ms")?,
        push_ms: figure("push_ms")?,
        pr_ms: figure("pr_ms")?,
        queue_wait_ms: figure("queue_wait_ms")?,
    }))
}

//! Fleet stats: one aggregate query over jobs and their telemetry summaries.

use fleet_proto::v1::{
    CostStats, GetStatsReply, GetStatsRequest, Quantiles, StatsGroup, StatsGroupBy, StuckOutcomes,
    StuckRuleStats, Total,
};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::jobs::{JobInvalid, MAX_REPO_BYTES};
use crate::store::{MAX_TS_MS, NOW_SECONDS, StoreError, count};
use crate::telemetry::stuck_rule_name;

/// Seconds in a day.
const DAY_S: i64 = 86_400;
/// Window length used when a request sets no `since`, in seconds.
pub const DEFAULT_WINDOW_S: i64 = 7 * DAY_S;
/// Longest window a request may cover, in seconds. A longer one is cut to this.
pub const MAX_WINDOW_S: i64 = 90 * DAY_S;
/// Most groups one reply carries.
pub const MAX_GROUPS: usize = 200;
/// Error text a box reports for a job its agent timeout ended. Matches the text `fleetd`
/// sends, and splits `FAILED` jobs into failed and timed out.
pub const TIMED_OUT_ERROR: &str = "agent timed out";

macro_rules! scoped {
    () => {
        "\
WITH scoped AS ( \
    SELECT CASE $5::text \
            WHEN 'repo' THEN j.repo \
            WHEN 'box' THEN j.box \
            WHEN 'state' THEN j.state \
            WHEN 'day' THEN to_char(j.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') \
            WHEN 'bundle_sha' THEN s.bundle_sha \
            WHEN 'claude_version' THEN s.claude_version \
            WHEN 'model' THEN s.model \
            ELSE '' \
        END AS grp, \
        j.state, j.error, s.job_id AS summarized, s.complete, s.turns, s.duration_ms, \
        s.cost_est_usd, s.tokens_in, s.tokens_out, s.tokens_cache_read, \
        s.tokens_cache_write, s.tool_calls, s.tool_errors, s.bash_calls, s.bash_nonzero, \
        s.denials, s.api_retries, s.first_edit_ms, s.stuck_rule \
    FROM jobs j LEFT JOIN job_summary s ON s.job_id = j.job_id \
    WHERE j.created_at >= to_timestamp($1::bigint::double precision) \
        AND j.created_at < to_timestamp($2::bigint::double precision) \
        AND ($3::text IS NULL OR j.repo = $3) \
        AND ($4::text IS NULL OR j.box = $4)) \
"
    };
}

const STATS: &str = concat!(
    scoped!(),
    "\
SELECT grp, grp IS NULL AS unknown, count(*) AS jobs, \
    count(*) FILTER (WHERE state = 'SUCCEEDED') AS succeeded, \
    count(*) FILTER (WHERE state = 'FAILED' AND error IS DISTINCT FROM $6) AS failed, \
    count(*) FILTER (WHERE state = 'FAILED' AND error = $6) AS timed_out, \
    count(*) FILTER (WHERE state = 'CANCELLED') AS cancelled, \
    count(*) FILTER (WHERE state = 'LOST') AS lost, \
    count(*) FILTER (WHERE state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'LOST')) AS other, \
    count(summarized) AS with_summary, \
    count(stuck_rule) AS stuck_jobs, \
    count(*) FILTER (WHERE complete) AS complete, \
    count(duration_ms) AS duration_ms_n, \
    percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms::double precision) \
        FILTER (WHERE duration_ms IS NOT NULL) AS duration_ms_p50, \
    percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms::double precision) \
        FILTER (WHERE duration_ms IS NOT NULL) AS duration_ms_p95, \
    count(turns) AS turns_n, \
    percentile_cont(0.5) WITHIN GROUP (ORDER BY turns::double precision) \
        FILTER (WHERE turns IS NOT NULL) AS turns_p50, \
    percentile_cont(0.95) WITHIN GROUP (ORDER BY turns::double precision) \
        FILTER (WHERE turns IS NOT NULL) AS turns_p95, \
    count(first_edit_ms) AS first_edit_ms_n, \
    percentile_cont(0.5) WITHIN GROUP (ORDER BY first_edit_ms::double precision) \
        FILTER (WHERE first_edit_ms IS NOT NULL) AS first_edit_ms_p50, \
    percentile_cont(0.95) WITHIN GROUP (ORDER BY first_edit_ms::double precision) \
        FILTER (WHERE first_edit_ms IS NOT NULL) AS first_edit_ms_p95, \
    count(cost_est_usd) AS cost_n, \
    sum(cost_est_usd) AS cost_sum, \
    percentile_cont(0.5) WITHIN GROUP (ORDER BY cost_est_usd) \
        FILTER (WHERE cost_est_usd IS NOT NULL) AS cost_p50, \
    percentile_cont(0.95) WITHIN GROUP (ORDER BY cost_est_usd) \
        FILTER (WHERE cost_est_usd IS NOT NULL) AS cost_p95, \
    count(tokens_in) AS tokens_in_n, sum(tokens_in)::bigint AS tokens_in_sum, \
    count(tokens_out) AS tokens_out_n, sum(tokens_out)::bigint AS tokens_out_sum, \
    count(tokens_cache_read) AS tokens_cache_read_n, \
    sum(tokens_cache_read)::bigint AS tokens_cache_read_sum, \
    count(tokens_cache_write) AS tokens_cache_write_n, \
    sum(tokens_cache_write)::bigint AS tokens_cache_write_sum, \
    count(tool_calls) AS tool_calls_n, sum(tool_calls)::bigint AS tool_calls_sum, \
    count(tool_errors) AS tool_errors_n, sum(tool_errors)::bigint AS tool_errors_sum, \
    count(bash_calls) AS bash_calls_n, sum(bash_calls)::bigint AS bash_calls_sum, \
    count(bash_nonzero) AS bash_nonzero_n, sum(bash_nonzero)::bigint AS bash_nonzero_sum, \
    count(denials) AS denials_n, sum(denials)::bigint AS denials_sum, \
    count(api_retries) AS api_retries_n, sum(api_retries)::bigint AS api_retries_sum \
FROM scoped GROUP BY grp \
ORDER BY CASE WHEN $5::text = 'day' THEN 0 ELSE -count(*) END, grp \
LIMIT $7"
);

const STUCK_STATS: &str = concat!(
    scoped!(),
    "\
SELECT grp, grp IS NULL AS unknown, stuck_rule, count(*) AS jobs, \
    count(*) FILTER (WHERE state = 'SUCCEEDED') AS succeeded, \
    count(*) FILTER (WHERE state = 'FAILED') AS failed, \
    count(*) FILTER (WHERE state IN ('CANCELLED', 'LOST')) AS other_terminal \
FROM scoped WHERE summarized IS NOT NULL \
GROUP BY grp, stuck_rule \
ORDER BY grp, stuck_rule"
);

/// A validated stats request: the effective window, the filters and the grouping column.
#[derive(Debug, PartialEq, Eq)]
struct Plan<'a> {
    since: i64,
    until: i64,
    clamped: bool,
    repo: Option<&'a str>,
    box_name: Option<&'a str>,
    group: &'static str,
}

fn group_column(raw: i32) -> Result<&'static str, JobInvalid> {
    match StatsGroupBy::try_from(raw) {
        Ok(StatsGroupBy::None) => Ok(""),
        Ok(StatsGroupBy::Repo) => Ok("repo"),
        Ok(StatsGroupBy::Box) => Ok("box"),
        Ok(StatsGroupBy::State) => Ok("state"),
        Ok(StatsGroupBy::Day) => Ok("day"),
        Ok(StatsGroupBy::BundleSha) => Ok("bundle_sha"),
        Ok(StatsGroupBy::ClaudeVersion) => Ok("claude_version"),
        Ok(StatsGroupBy::Model) => Ok("model"),
        Err(_) => Err(JobInvalid::GroupBy),
    }
}

fn filter(value: Option<&String>) -> Result<Option<&str>, JobInvalid> {
    match value.map(String::as_str) {
        Some(text) if text.is_empty() || text.len() > MAX_REPO_BYTES || text.contains('\0') => {
            Err(JobInvalid::Filter)
        }
        other => Ok(other),
    }
}

fn plan(request: &GetStatsRequest, now: i64) -> Result<Plan<'_>, JobInvalid> {
    let limit = i64::try_from(MAX_TS_MS / 1000).map_err(|_| JobInvalid::Window)?;
    let until = request.until.unwrap_or(now);
    let since = request
        .since
        .unwrap_or_else(|| until.saturating_sub(DEFAULT_WINDOW_S));
    if !(0..=limit).contains(&since) || !(0..=limit).contains(&until) || until < since {
        return Err(JobInvalid::Window);
    }
    let clamped = until - since > MAX_WINDOW_S;
    Ok(Plan {
        since: if clamped { until - MAX_WINDOW_S } else { since },
        until,
        clamped,
        repo: filter(request.repo.as_ref())?,
        box_name: filter(request.r#box.as_ref())?,
        group: group_column(request.group_by)?,
    })
}

fn n(row: &PgRow, name: &str) -> Result<u64, StoreError> {
    count(row.try_get::<i64, _>(name)?, "stats")
}

fn quantiles(row: &PgRow, name: &str) -> Result<Option<Quantiles>, StoreError> {
    let n = n(row, &format!("{name}_n"))?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(Quantiles {
        n,
        p50: row.try_get(format!("{name}_p50").as_str())?,
        p95: row.try_get(format!("{name}_p95").as_str())?,
    }))
}

fn total(row: &PgRow, name: &str) -> Result<Option<Total>, StoreError> {
    let n = n(row, &format!("{name}_n"))?;
    if n == 0 {
        return Ok(None);
    }
    let sum: i64 = row.try_get(format!("{name}_sum").as_str())?;
    Ok(Some(Total {
        n,
        sum: count(sum, "stats")?,
    }))
}

fn cost(row: &PgRow) -> Result<Option<CostStats>, StoreError> {
    let n = n(row, "cost_n")?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(CostStats {
        n,
        sum: row.try_get("cost_sum")?,
        p50: row.try_get("cost_p50")?,
        p95: row.try_get("cost_p95")?,
    }))
}

fn outcomes(row: &PgRow) -> Result<StuckOutcomes, StoreError> {
    Ok(StuckOutcomes {
        jobs: n(row, "jobs")?,
        succeeded: n(row, "succeeded")?,
        failed: n(row, "failed")?,
        other_terminal: n(row, "other_terminal")?,
    })
}

fn attach_stuck(groups: &mut [StatsGroup], rows: &[PgRow]) -> Result<(), StoreError> {
    for row in rows {
        let key: Option<String> = row.try_get("grp")?;
        let unknown: bool = row.try_get("unknown")?;
        let Some(group) = groups
            .iter_mut()
            .find(|g| g.unknown == unknown && (unknown || Some(&g.key) == key.as_ref()))
        else {
            continue;
        };
        let outcomes = outcomes(row)?;
        let rule: Option<String> = row.try_get("stuck_rule")?;
        match stuck_rule_name(rule.as_ref())? {
            Some(rule) => group.stuck_rules.push(StuckRuleStats {
                rule: rule.to_owned(),
                outcomes: Some(outcomes),
            }),
            None => group.clean = Some(outcomes),
        }
    }
    Ok(())
}

fn group(row: &PgRow) -> Result<StatsGroup, StoreError> {
    Ok(StatsGroup {
        key: row.try_get::<Option<String>, _>("grp")?.unwrap_or_default(),
        unknown: row.try_get("unknown")?,
        jobs: n(row, "jobs")?,
        succeeded: n(row, "succeeded")?,
        failed: n(row, "failed")?,
        timed_out: n(row, "timed_out")?,
        cancelled: n(row, "cancelled")?,
        lost: n(row, "lost")?,
        other: n(row, "other")?,
        with_summary: n(row, "with_summary")?,
        complete: n(row, "complete")?,
        duration_ms: quantiles(row, "duration_ms")?,
        turns: quantiles(row, "turns")?,
        cost_est_usd: cost(row)?,
        tokens_in: total(row, "tokens_in")?,
        tokens_out: total(row, "tokens_out")?,
        tokens_cache_read: total(row, "tokens_cache_read")?,
        tokens_cache_write: total(row, "tokens_cache_write")?,
        tool_calls: total(row, "tool_calls")?,
        tool_errors: total(row, "tool_errors")?,
        bash_calls: total(row, "bash_calls")?,
        bash_nonzero: total(row, "bash_nonzero")?,
        denials: total(row, "denials")?,
        api_retries: total(row, "api_retries")?,
        first_edit_ms: quantiles(row, "first_edit_ms")?,
        stuck_jobs: n(row, "stuck_jobs")?,
        stuck_rules: Vec::new(),
        clean: None,
    })
}

/// Validates `request` and runs the aggregate.
///
/// A second query over the same scope splits the jobs with a summary by stuck rule. Each
/// rule's jobs carry their outcome split, and jobs with a summary and no rule form `clean`.
/// Jobs without a summary are in neither, because a missing summary is not a clean run. A
/// rule name is read back through the stored-name validation before it reaches the reply.
///
/// The window is half open on `jobs.created_at`: `since` is included, `until` is not. A
/// missing `until` is the database clock rounded up to a whole second, so a job created in
/// the current second is inside, and a missing `since` is seven days before `until`. A window longer than 90 days keeps its `until` and sets `clamped`. The grouping
/// column comes from a fixed match on the enum, and every other request value is a bound
/// parameter.
///
/// # Errors
/// Returns [`StoreError::InvalidJob`] for a bad window, filter or grouping and
/// [`StoreError::Database`] when the query fails.
pub(crate) async fn stats(
    pool: &PgPool,
    request: &GetStatsRequest,
) -> Result<GetStatsReply, StoreError> {
    let now: i64 = sqlx::query_scalar(NOW_SECONDS).fetch_one(pool).await?;
    let plan = plan(request, now)?;
    let limit = i64::try_from(MAX_GROUPS + 1).map_err(|_| StoreError::OutOfRange("stats"))?;
    let rows = sqlx::query(STATS)
        .bind(plan.since)
        .bind(plan.until)
        .bind(plan.repo)
        .bind(plan.box_name)
        .bind(plan.group)
        .bind(TIMED_OUT_ERROR)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    let truncated = rows.len() > MAX_GROUPS;
    let mut groups = rows
        .iter()
        .take(MAX_GROUPS)
        .map(group)
        .collect::<Result<Vec<_>, _>>()?;
    let stuck_rows = sqlx::query(STUCK_STATS)
        .bind(plan.since)
        .bind(plan.until)
        .bind(plan.repo)
        .bind(plan.box_name)
        .bind(plan.group)
        .fetch_all(pool)
        .await?;
    attach_stuck(&mut groups, &stuck_rows)?;
    Ok(GetStatsReply {
        groups,
        truncated,
        since: plan.since,
        until: plan.until,
        clamped: plan.clamped,
    })
}

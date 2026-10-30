//! CI-retry decisions: whether a failed pull request gets a fix Job, and its insertion.

use fleet_core::EventId;
use fleet_proto::ci_retry_key;
use fleet_proto::v1::CiRetry;
use sqlx::{Postgres, Transaction};

use super::{StoreError, ci_retry_name};
use crate::jobs::{expected_branch, fix_prompt};

const SELECT_RETRY_ATTEMPT: &str = "SELECT ci_retry_attempt FROM jobs WHERE job_id = $1";

pub(super) const ROOT_ID: &str = "\
WITH RECURSIVE up AS (\
SELECT job_id, parent_job_id, 0 AS depth FROM jobs WHERE job_id = $1 \
UNION ALL \
SELECT p.job_id, p.parent_job_id, up.depth + 1 FROM jobs p \
JOIN up ON p.job_id = up.parent_job_id WHERE up.depth < 16) \
SELECT job_id FROM up WHERE parent_job_id IS NULL";

const ROOT_PROMPT: &str = "\
WITH RECURSIVE up AS (\
SELECT job_id, parent_job_id, prompt, 0 AS depth FROM jobs WHERE job_id = $1 \
UNION ALL \
SELECT p.job_id, p.parent_job_id, p.prompt, up.depth + 1 FROM jobs p \
JOIN up ON p.job_id = up.parent_job_id WHERE up.depth < 16) \
SELECT prompt FROM up WHERE parent_job_id IS NULL";

const INSERT_FIX: &str = "\
INSERT INTO jobs (job_id, idempotency_key, prompt, repo, base_ref, branch, open_pr, pr_url, \
parent_job_id, ci_retry_attempt, user_id, agent) \
SELECT $1, $2, $3, p.repo, p.branch, p.branch, true, p.pr_url, p.job_id, p.ci_retry_attempt + 1, \
p.user_id, p.agent \
FROM jobs p \
WHERE p.job_id = $4 AND p.kind = 'agent' AND p.state = 'SUCCEEDED' AND p.open_pr \
AND p.pr_url IS NOT NULL AND p.ci_state = 'failure' AND p.batch_id IS NULL \
AND p.profile_name IS NULL AND p.branch = $5 AND p.branch ~ '^swarm/[A-Za-z0-9]{1,64}$' \
ON CONFLICT DO NOTHING \
RETURNING job_id";

const SELECT_FIX_CHILD: &str = "SELECT 1 FROM jobs WHERE parent_job_id = $1";

const SET_RETRY: &str = "UPDATE jobs SET ci_retry = $2 WHERE job_id = $1 AND ci_retry IS NULL";

pub(super) async fn decide_ci_retry(
    tx: &mut Transaction<'_, Postgres>,
    job_id: &str,
    log: Option<&str>,
    max: u32,
) -> Result<(), StoreError> {
    let stored: i32 = sqlx::query_scalar(SELECT_RETRY_ATTEMPT)
        .bind(job_id)
        .fetch_one(&mut **tx)
        .await?;
    let attempt = u32::try_from(stored).map_err(|_| StoreError::OutOfRange("ci retry attempt"))?;
    let outcome = if max == 0 {
        CiRetry::Disabled
    } else if attempt >= max {
        CiRetry::Exhausted
    } else {
        submit_fix(tx, job_id, attempt + 1, log).await?
    };
    sqlx::query(SET_RETRY)
        .bind(job_id)
        .bind(ci_retry_name(outcome))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn submit_fix(
    tx: &mut Transaction<'_, Postgres>,
    parent: &str,
    attempt: u32,
    log: Option<&str>,
) -> Result<CiRetry, StoreError> {
    let id = EventId::generate().to_string();
    let original: String = sqlx::query_scalar(ROOT_PROMPT)
        .bind(parent)
        .fetch_one(&mut **tx)
        .await?;
    let Some(prompt) = log.and_then(|log| fix_prompt(&original, log, &id)) else {
        return Ok(CiRetry::NoLog);
    };
    let root_id: Option<String> = sqlx::query_scalar(ROOT_ID)
        .bind(parent)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(root_id) = root_id else {
        return Ok(CiRetry::Ineligible);
    };
    let inserted = sqlx::query(INSERT_FIX)
        .bind(id)
        .bind(ci_retry_key(parent, attempt))
        .bind(prompt)
        .bind(parent)
        .bind(expected_branch(&root_id))
        .fetch_optional(&mut **tx)
        .await?;
    if inserted.is_some() {
        return Ok(CiRetry::Submitted);
    }
    let child = sqlx::query(SELECT_FIX_CHILD)
        .bind(parent)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(if child.is_some() {
        CiRetry::Submitted
    } else {
        CiRetry::Ineligible
    })
}

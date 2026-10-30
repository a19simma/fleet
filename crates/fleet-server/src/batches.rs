//! Batch submission: one prompt dispatched once per Profile, stored in one transaction.

use std::collections::HashSet;
use std::fmt;

use fleet_core::EventId;
use fleet_proto::v1::{GetBatchReply, SubmitBatchReply, SubmitBatchRequest, SubmitJobRequest};
use sqlx::{PgPool, Row};

use crate::jobs::{DEFAULT_AGENT, validate_job_id, validate_submit};
use crate::profiles::validate_name;
use crate::store::StoreError;

/// Most profiles one batch may name.
pub const MAX_BATCH_PROFILES: usize = 16;

const INSERT_BATCH: &str = "INSERT INTO batch (batch_id, idempotency_key, prompt, repo, base_sha, repeats) \
     VALUES ($1, $2, $3, $4, $5, 1) ON CONFLICT (idempotency_key) DO NOTHING RETURNING batch_id";
const SELECT_BATCH_BY_KEY: &str =
    "SELECT batch_id, prompt, repo, base_sha FROM batch WHERE idempotency_key = $1";
const SELECT_BATCH_JOBS: &str = "SELECT job_id, profile_name, user_id, agent FROM jobs WHERE batch_id = $1 ORDER BY batch_pos LIMIT $2";
const SELECT_BATCH_BY_ID: &str = "SELECT prompt, repo, base_sha, repeats, \
     (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_ms FROM batch WHERE batch_id = $1";
const SELECT_BATCH_JOB_IDS: &str =
    "SELECT job_id FROM jobs WHERE batch_id = $1 ORDER BY batch_pos LIMIT $2";
const LOCK_NAME: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
const SELECT_LATEST: &str =
    "SELECT version, hash FROM profile_version WHERE name = $1 ORDER BY version DESC LIMIT 1";
const INSERT_BATCH_JOB: &str = "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, \
     batch_id, repeat_idx, batch_pos, profile_name, profile_version, profile_hash, user_id, agent) \
     VALUES ($1, $2, $3, $4, 'swarm/' || $1, false, $5, 0, $6, $7, $8, $9, $10, $11)";
const SELECT_BOOTSTRAP_USER: &str = "SELECT bootstrap_user_id()";

/// Why a batch request was refused. The variants carry no client input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BatchInvalid {
    /// `repeats` is neither 0 nor 1.
    Repeats,
    /// `base_sha` is not 40 lowercase hex characters.
    BaseSha,
    /// The profile list is empty or longer than [`MAX_BATCH_PROFILES`].
    ProfileCount,
    /// A profile name breaks the profile name rule.
    ProfileName,
    /// The profile list names one profile twice.
    DuplicateProfile,
    /// A batch id is not a job-shaped id.
    BatchId,
}

impl fmt::Display for BatchInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Repeats => "repeats above 1 is not supported",
            Self::BaseSha => "invalid base sha",
            Self::ProfileCount => "a batch needs 1 to 16 profiles",
            Self::ProfileName => "invalid profile name",
            Self::DuplicateProfile => "duplicate profile in batch",
            Self::BatchId => "invalid batch id",
        })
    }
}

impl std::error::Error for BatchInvalid {}

/// A validated batch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBatch {
    key: String,
    prompt: String,
    repo: String,
    base_sha: String,
    profiles: Vec<String>,
}

fn is_sha(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates a batch request. This is the only check on these fields.
///
/// The key, prompt and repo go through the job validator, with `base_sha` as the base ref.
///
/// # Errors
///
/// Returns the [`StoreError`] of the first rule that fails. It never carries the input.
pub fn validate_batch(request: &SubmitBatchRequest) -> Result<NewBatch, StoreError> {
    if request.repeats > 1 {
        return Err(StoreError::InvalidBatch(BatchInvalid::Repeats));
    }
    if !is_sha(&request.base_sha) {
        return Err(StoreError::InvalidBatch(BatchInvalid::BaseSha));
    }
    if request.profiles.is_empty() || request.profiles.len() > MAX_BATCH_PROFILES {
        return Err(StoreError::InvalidBatch(BatchInvalid::ProfileCount));
    }
    let mut seen = HashSet::with_capacity(MAX_BATCH_PROFILES);
    for name in &request.profiles {
        validate_name(name)?;
        if !seen.insert(name.as_str()) {
            return Err(StoreError::InvalidBatch(BatchInvalid::DuplicateProfile));
        }
    }
    let job = validate_submit(&SubmitJobRequest {
        idempotency_key: request.idempotency_key.clone(),
        prompt: request.prompt.clone(),
        repo: request.repo.clone(),
        base_ref: request.base_sha.clone(),
        open_pr: false,
    })?;
    Ok(NewBatch {
        key: job.key,
        prompt: job.prompt,
        repo: job.repo,
        base_sha: job.base_ref,
        profiles: request.profiles.clone(),
    })
}

/// Reads a batch row and the ids of its jobs in profile order.
///
/// The reply carries no jobs; the caller fills them in. The id is checked once here and an
/// unknown id is [`StoreError::NotFound`]. At most [`MAX_BATCH_PROFILES`] ids come back.
pub(crate) async fn get_head(
    pool: &PgPool,
    batch_id: &str,
) -> Result<(GetBatchReply, Vec<String>), StoreError> {
    validate_job_id(batch_id).map_err(|_| StoreError::InvalidBatch(BatchInvalid::BatchId))?;
    let row = sqlx::query(SELECT_BATCH_BY_ID)
        .bind(batch_id)
        .fetch_optional(pool)
        .await?
        .ok_or(StoreError::NotFound)?;
    let ids = sqlx::query(SELECT_BATCH_JOB_IDS)
        .bind(batch_id)
        .bind(i64::try_from(MAX_BATCH_PROFILES).unwrap_or(i64::MAX))
        .fetch_all(pool)
        .await?
        .iter()
        .map(|row| row.try_get::<String, _>("job_id"))
        .collect::<Result<Vec<_>, _>>()?;
    let repeats = u32::try_from(row.try_get::<i32, _>("repeats")?)
        .map_err(|_| StoreError::OutOfRange("batch repeats"))?;
    let created_at_ms = u64::try_from(row.try_get::<i64, _>("created_at_ms")?)
        .map_err(|_| StoreError::OutOfRange("batch created_at"))?;
    let reply = GetBatchReply {
        batch_id: batch_id.to_owned(),
        prompt: row.try_get("prompt")?,
        repo: row.try_get("repo")?,
        base_sha: row.try_get("base_sha")?,
        repeats,
        created_at_ms,
        jobs: Vec::new(),
    };
    Ok((reply, ids))
}

pub(crate) async fn submit(
    pool: &PgPool,
    owner: Option<i64>,
    request: &SubmitBatchRequest,
) -> Result<SubmitBatchReply, StoreError> {
    let batch = validate_batch(request)?;
    let owner = match owner {
        Some(owner) => owner,
        None => {
            sqlx::query_scalar(SELECT_BOOTSTRAP_USER)
                .fetch_one(pool)
                .await?
        }
    };
    let batch_id = EventId::generate().to_string();
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query(INSERT_BATCH)
        .bind(&batch_id)
        .bind(&batch.key)
        .bind(&batch.prompt)
        .bind(&batch.repo)
        .bind(&batch.base_sha)
        .fetch_optional(&mut *tx)
        .await?;
    if inserted.is_none() {
        let stored = sqlx::query(SELECT_BATCH_BY_KEY)
            .bind(&batch.key)
            .fetch_one(&mut *tx)
            .await?;
        let stored_id: String = stored.try_get("batch_id")?;
        let same = stored.try_get::<String, _>("prompt")? == batch.prompt
            && stored.try_get::<String, _>("repo")? == batch.repo
            && stored.try_get::<String, _>("base_sha")? == batch.base_sha;
        let rows = sqlx::query(SELECT_BATCH_JOBS)
            .bind(&stored_id)
            .bind(i64::try_from(MAX_BATCH_PROFILES).unwrap_or(i64::MAX))
            .fetch_all(&mut *tx)
            .await?;
        let mut names = Vec::with_capacity(rows.len());
        let mut job_ids = Vec::with_capacity(rows.len());
        let mut same_owner = true;
        for row in &rows {
            names.push(row.try_get::<String, _>("profile_name")?);
            job_ids.push(row.try_get::<String, _>("job_id")?);
            same_owner &= row.try_get::<i64, _>("user_id")? == owner
                && row.try_get::<String, _>("agent")? == DEFAULT_AGENT;
        }
        if !same || !same_owner || names != batch.profiles {
            return Err(StoreError::KeyConflict);
        }
        return Ok(SubmitBatchReply {
            batch_id: stored_id,
            job_ids,
            created: false,
        });
    }
    let mut order: Vec<&String> = batch.profiles.iter().collect();
    order.sort();
    for name in order {
        sqlx::query(LOCK_NAME).bind(name).execute(&mut *tx).await?;
    }
    let mut job_ids = Vec::with_capacity(batch.profiles.len());
    for (pos, name) in batch.profiles.iter().enumerate() {
        let pinned = sqlx::query(SELECT_LATEST)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::UnknownProfile)?;
        let job_id = EventId::generate().to_string();
        sqlx::query(INSERT_BATCH_JOB)
            .bind(&job_id)
            .bind(&batch.prompt)
            .bind(&batch.repo)
            .bind(&batch.base_sha)
            .bind(&batch_id)
            .bind(i32::try_from(pos).map_err(|_| StoreError::OutOfRange("batch position"))?)
            .bind(name)
            .bind(pinned.try_get::<i32, _>("version")?)
            .bind(pinned.try_get::<Vec<u8>, _>("hash")?)
            .bind(owner)
            .bind(DEFAULT_AGENT)
            .execute(&mut *tx)
            .await?;
        job_ids.push(job_id);
    }
    tx.commit().await?;
    Ok(SubmitBatchReply {
        batch_id,
        job_ids,
        created: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn request() -> SubmitBatchRequest {
        SubmitBatchRequest {
            idempotency_key: "k1".to_owned(),
            prompt: "do it".to_owned(),
            repo: "https://example.com/r.git".to_owned(),
            base_sha: SHA.to_owned(),
            repeats: 0,
            profiles: vec!["a".to_owned(), "b".to_owned()],
        }
    }

    fn invalid(request: &SubmitBatchRequest) -> Option<BatchInvalid> {
        match validate_batch(request) {
            Err(StoreError::InvalidBatch(reason)) => Some(reason),
            _ => None,
        }
    }

    #[test]
    fn a_good_request_passes_with_repeats_0_or_1() {
        assert!(validate_batch(&request()).is_ok());
        let mut one = request();
        one.repeats = 1;
        assert!(validate_batch(&one).is_ok());
    }

    #[test]
    fn repeats_above_one_is_refused() {
        for repeats in [2, 3, u32::MAX] {
            let mut bad = request();
            bad.repeats = repeats;
            assert_eq!(invalid(&bad), Some(BatchInvalid::Repeats));
        }
    }

    #[test]
    fn base_sha_must_be_40_lowercase_hex() {
        let upper = SHA.to_uppercase();
        let short = &SHA[..39];
        let long = format!("{SHA}0");
        let non_hex = format!("{}g", &SHA[..39]);
        for bad in [upper.as_str(), short, long.as_str(), non_hex.as_str(), ""] {
            let mut req = request();
            bad.clone_into(&mut req.base_sha);
            assert_eq!(invalid(&req), Some(BatchInvalid::BaseSha), "{bad}");
        }
    }

    #[test]
    fn profile_list_is_bounded_unique_and_named_well() {
        let mut none = request();
        none.profiles.clear();
        assert_eq!(invalid(&none), Some(BatchInvalid::ProfileCount));
        let mut many = request();
        many.profiles = (0..=MAX_BATCH_PROFILES).map(|n| format!("p{n}")).collect();
        assert_eq!(invalid(&many), Some(BatchInvalid::ProfileCount));
        let mut full = request();
        full.profiles = (0..MAX_BATCH_PROFILES).map(|n| format!("p{n}")).collect();
        assert!(validate_batch(&full).is_ok());
        let mut dup = request();
        dup.profiles = vec!["a".to_owned(), "a".to_owned()];
        assert_eq!(invalid(&dup), Some(BatchInvalid::DuplicateProfile));
        let mut bad = request();
        bad.profiles = vec!["a b".to_owned()];
        assert!(matches!(
            validate_batch(&bad),
            Err(StoreError::InvalidProfile(_))
        ));
    }

    #[test]
    fn job_rules_apply_to_key_prompt_and_repo() {
        let mut key = request();
        key.idempotency_key.clear();
        assert!(matches!(
            validate_batch(&key),
            Err(StoreError::InvalidJob(_))
        ));
        let mut prompt = request();
        prompt.prompt = " ".to_owned();
        assert!(matches!(
            validate_batch(&prompt),
            Err(StoreError::InvalidJob(_))
        ));
        let mut repo = request();
        repo.repo = "http://example.com/r".to_owned();
        assert!(matches!(
            validate_batch(&repo),
            Err(StoreError::InvalidJob(_))
        ));
    }
}

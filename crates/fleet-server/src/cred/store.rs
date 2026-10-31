//! Postgres credential store over a [`Sealer`] (ADR-0040).
//!
//! Plaintext exists only inside [`Secret`] values. No error or `Debug` output carries it.

use std::fmt;
use std::sync::Arc;

use fleet_core::credential::{
    CredentialError, CredentialKind, CredentialShape, Secret, fingerprint, validate,
};
use fleet_proto::MAX_CREDENTIALS_PER_USER;
use sqlx::{PgPool, Row};

use super::github::MAX_EXPIRY_MS;
use super::seal::{Aad, SealError, Sealer};

const UPSERT: &str = "\
INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint, login, expires_at) \
VALUES ($1, $2, $3, '\\x'::bytea, 'pending', $4, $5, to_timestamp($6::bigint / 1000.0)) \
ON CONFLICT (user_id, kind) DO UPDATE SET shape = EXCLUDED.shape, \
fingerprint = EXCLUDED.fingerprint, login = EXCLUDED.login, expires_at = EXCLUDED.expires_at \
RETURNING id";

const LOCK_USER: &str = "SELECT pg_advisory_xact_lock($1)";

const COUNT_OTHERS: &str = "SELECT count(*) FROM credentials WHERE user_id = $1 AND kind <> $2";

const STORE_SEALED: &str = "UPDATE credentials SET ciphertext = $1, key_id = $2 WHERE id = $3";

const LIST: &str = "\
SELECT id, kind, shape, fingerprint, login, \
(EXTRACT(EPOCH FROM expires_at) * 1000)::bigint AS expires_ms \
FROM credentials WHERE user_id = $1 ORDER BY id";

const DELETE: &str = "DELETE FROM credentials WHERE id = $1 AND user_id = $2";

const SELECT_FOR_USE: &str = "\
SELECT kind, ciphertext, key_id FROM credentials WHERE id = $1 AND user_id = $2 FOR SHARE";

const SELECT_LEASE: &str = "\
SELECT user_id, agent FROM jobs \
WHERE job_id = $1 AND attempt = $2 AND box = $3 AND state = 'RUNNING' \
AND lease_expires_at > now()";

const SELECT_RELEASABLE: &str = "\
SELECT id, kind, (expires_at IS NOT NULL AND expires_at <= now()) AS expired \
FROM credentials WHERE user_id = $1 AND kind = ANY($2) ORDER BY id";

const INSERT_USE: &str = "INSERT INTO credential_use (credential_id, job_id) VALUES ($1, $2)";

/// One credential released to a Box for a leased Job.
pub struct ReleasedCredential {
    /// What the credential authenticates against.
    pub kind: CredentialKind,
    /// Storage shape.
    pub shape: CredentialShape,
    /// The secret value.
    pub value: Secret,
}

impl fmt::Debug for ReleasedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleasedCredential")
            .field("kind", &self.kind)
            .field("shape", &self.shape)
            .finish_non_exhaustive()
    }
}

fn agent_kinds(agent: &str) -> &'static [CredentialKind] {
    match agent {
        "claude" => &[
            CredentialKind::AnthropicApiKey,
            CredentialKind::ClaudeSubscriptionToken,
        ],
        "codex" => &[CredentialKind::CodexApiKey],
        "kimi" => &[
            CredentialKind::KimiMembershipKey,
            CredentialKind::KimiPlatformKey,
        ],
        _ => &[],
    }
}

/// What a user sees of a stored credential. It holds no secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSummary {
    /// Row id.
    pub id: i64,
    /// What the credential authenticates against.
    pub kind: CredentialKind,
    /// Storage shape.
    pub shape: CredentialShape,
    /// Short stable identifier of the value.
    pub fingerprint: String,
    /// Account name the credential belongs to, when known.
    pub login: Option<String>,
    /// Expiry in milliseconds since the Unix epoch, when known.
    pub expires_at_ms: Option<i64>,
}

/// Why a store operation failed. Messages are fixed text.
#[derive(Debug)]
pub enum StoreError {
    /// The value failed validation.
    Invalid(CredentialError),
    /// The expiry lies outside `0..=MAX_EXPIRY_MS`.
    InvalidExpiry,
    /// No such credential, or it belongs to another user.
    NotFound,
    /// Sealing or opening failed.
    Seal(SealError),
    /// The user already holds the most credentials allowed.
    TooMany,
    /// No running job holds this lease. Wrong box, wrong attempt, a job that is not `RUNNING`,
    /// an expired lease and an unknown job all give this.
    LeaseDenied,
    /// The job owner stored no GitHub credential.
    NoGithub,
    /// The job owner stored no credential of a kind the job agent accepts.
    NoAgentCredential,
    /// A credential the job needs is past its expiry.
    Expired,
    /// The database failed.
    Db(sqlx::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => e.fmt(f),
            Self::InvalidExpiry => f.write_str("invalid expiry"),
            Self::NotFound => f.write_str("credential not found"),
            Self::TooMany => f.write_str("too many credentials"),
            Self::LeaseDenied => f.write_str("lease does not match"),
            Self::NoGithub => f.write_str("no github credential"),
            Self::NoAgentCredential => f.write_str("no agent credential"),
            Self::Expired => f.write_str("credential expired"),
            Self::Seal(e) => e.fmt(f),
            Self::Db(_) => f.write_str("credential store database error"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl From<SealError> for StoreError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}

impl From<CredentialError> for StoreError {
    fn from(e: CredentialError) -> Self {
        Self::Invalid(e)
    }
}

/// Stores sealed credentials per user.
#[derive(Clone)]
pub struct CredentialStore {
    pool: PgPool,
    sealer: Arc<dyn Sealer>,
    limit: usize,
}

impl fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialStore(..)")
    }
}

fn kind_of(name: &str) -> Result<CredentialKind, StoreError> {
    CredentialKind::from_wire_name(name).ok_or(StoreError::Seal(SealError::Open))
}

fn shape_of(name: &str) -> CredentialShape {
    if name == CredentialShape::StaticSecret.wire_name() {
        CredentialShape::StaticSecret
    } else {
        CredentialShape::RefreshingFile
    }
}

impl CredentialStore {
    /// Builds a store over `pool` that seals with `sealer`.
    pub fn new(pool: PgPool, sealer: Arc<dyn Sealer>) -> Self {
        Self::with_limit(pool, sealer, MAX_CREDENTIALS_PER_USER)
    }

    /// Builds a store that holds at most `limit` credentials per user.
    pub fn with_limit(pool: PgPool, sealer: Arc<dyn Sealer>, limit: usize) -> Self {
        Self {
            pool,
            sealer,
            limit,
        }
    }

    /// Validates, seals and stores `value`, replacing the user's credential of the same kind.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Invalid`] for a rejected value, [`StoreError::InvalidExpiry`] for an
    /// expiry outside `0..=MAX_EXPIRY_MS`, [`StoreError::TooMany`] when a new kind would pass the
    /// per-user cap, [`StoreError::Seal`] when sealing fails and [`StoreError::Db`] for a
    /// database failure.
    pub async fn put(
        &self,
        user_id: i64,
        kind: CredentialKind,
        shape: CredentialShape,
        value: Secret,
        login: Option<String>,
        expires_at_ms: Option<i64>,
    ) -> Result<CredentialSummary, StoreError> {
        let text = std::str::from_utf8(value.expose()).map_err(|_| CredentialError::Whitespace)?;
        validate(kind, shape, text)?;
        if expires_at_ms.is_some_and(|ms| !(0..=MAX_EXPIRY_MS).contains(&ms)) {
            return Err(StoreError::InvalidExpiry);
        }
        let print = fingerprint(&value);
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        let others: i64 = sqlx::query_scalar(COUNT_OTHERS)
            .bind(user_id)
            .bind(kind.wire_name())
            .fetch_one(&mut *tx)
            .await?;
        if usize::try_from(others).map_or(true, |n| n >= self.limit) {
            return Err(StoreError::TooMany);
        }
        let id: i64 = sqlx::query_scalar(UPSERT)
            .bind(user_id)
            .bind(kind.wire_name())
            .bind(shape.wire_name())
            .bind(&print)
            .bind(&login)
            .bind(expires_at_ms)
            .fetch_one(&mut *tx)
            .await?;
        let aad = Aad::new(&user_id.to_string(), &id.to_string(), kind);
        let sealed = self.sealer.seal(&aad, value.expose())?;
        sqlx::query(STORE_SEALED)
            .bind(&sealed.ciphertext)
            .bind(&sealed.key_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(CredentialSummary {
            id,
            kind,
            shape,
            fingerprint: print,
            login,
            expires_at_ms,
        })
    }

    /// Lists the user's credentials without secret material.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Db`] for a database failure.
    pub async fn list(&self, user_id: i64) -> Result<Vec<CredentialSummary>, StoreError> {
        let rows = sqlx::query(LIST)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let kind: String = row.try_get("kind")?;
            let shape: String = row.try_get("shape")?;
            out.push(CredentialSummary {
                id: row.try_get("id")?,
                kind: kind_of(&kind)?,
                shape: shape_of(&shape),
                fingerprint: row.try_get("fingerprint")?,
                login: row.try_get("login")?,
                expires_at_ms: row.try_get("expires_ms")?,
            });
        }
        Ok(out)
    }

    /// Deletes the user's credential. The delete is final: use rows stay.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the id is unknown or owned by another user.
    pub async fn delete(&self, user_id: i64, credential_id: i64) -> Result<(), StoreError> {
        let done = sqlx::query(DELETE)
            .bind(credential_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Unseals the user's credential to check it with its provider. No use row is written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the id is unknown or owned by another user and
    /// [`StoreError::Seal`] when the value cannot be opened.
    pub async fn open_for_verify(
        &self,
        user_id: i64,
        credential_id: i64,
    ) -> Result<(CredentialKind, Secret), StoreError> {
        let mut tx = self.pool.begin().await?;
        let (kind, secret) = self.unseal(&mut tx, user_id, credential_id).await?;
        tx.commit().await?;
        Ok((kind, secret))
    }

    async fn unseal(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: i64,
        credential_id: i64,
    ) -> Result<(CredentialKind, Secret), StoreError> {
        let row = sqlx::query(SELECT_FOR_USE)
            .bind(credential_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        let name: String = row.try_get("kind")?;
        let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
        let key_id: String = row.try_get("key_id")?;
        let kind = kind_of(&name)?;
        let aad = Aad::new(&user_id.to_string(), &credential_id.to_string(), kind);
        let mut plain = self.sealer.open(&aad, &key_id, &ciphertext)?;
        let text = String::from_utf8(std::mem::take(&mut *plain))
            .map_err(|_| StoreError::Seal(SealError::Open))?;
        Ok((kind, Secret::new(text)))
    }

    /// Releases the credentials of the owner of a leased job and records each use.
    ///
    /// The lease must match on job, attempt and box, and the job must be `RUNNING` with an
    /// unexpired lease. The owner and the agent come from the job row, never from the request.
    /// The reply holds every stored credential of a kind the agent accepts, plus the GitHub
    /// token. One use row is written per credential, in the same transaction as the reads.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LeaseDenied`] when no job matches the lease,
    /// [`StoreError::NoGithub`] when the owner has no GitHub credential,
    /// [`StoreError::Expired`] when a needed credential is past its expiry,
    /// [`StoreError::NoAgentCredential`] when the owner has none the agent accepts,
    /// [`StoreError::Seal`] when a value cannot be opened and [`StoreError::Db`] for a
    /// database failure. No use row is written on any error.
    pub async fn release_for_job(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<Vec<ReleasedCredential>, StoreError> {
        let attempt = i32::try_from(attempt).map_err(|_| StoreError::LeaseDenied)?;
        let mut tx = self.pool.begin().await?;
        let lease = sqlx::query(SELECT_LEASE)
            .bind(job_id)
            .bind(attempt)
            .bind(box_name)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::LeaseDenied)?;
        let user_id: i64 = lease.try_get("user_id")?;
        let agent: String = lease.try_get("agent")?;
        let mut wanted: Vec<&str> = agent_kinds(&agent)
            .iter()
            .map(|kind| kind.wire_name())
            .collect();
        wanted.push(CredentialKind::GithubPat.wire_name());
        let rows = sqlx::query(SELECT_RELEASABLE)
            .bind(user_id)
            .bind(&wanted)
            .fetch_all(&mut *tx)
            .await?;
        let mut found = Vec::with_capacity(rows.len());
        for row in &rows {
            let name: String = row.try_get("kind")?;
            let expired: bool = row.try_get("expired")?;
            found.push((row.try_get::<i64, _>("id")?, kind_of(&name)?, expired));
        }
        if !found
            .iter()
            .any(|(_, kind, _)| *kind == CredentialKind::GithubPat)
        {
            return Err(StoreError::NoGithub);
        }
        if found
            .iter()
            .all(|(_, kind, _)| *kind == CredentialKind::GithubPat)
        {
            return Err(StoreError::NoAgentCredential);
        }
        if found.iter().any(|(_, _, expired)| *expired) {
            return Err(StoreError::Expired);
        }
        let mut released = Vec::with_capacity(found.len());
        for (id, _, _) in found {
            let (kind, value) = self.unseal(&mut tx, user_id, id).await?;
            sqlx::query(INSERT_USE)
                .bind(id)
                .bind(job_id)
                .execute(&mut *tx)
                .await?;
            released.push(ReleasedCredential {
                kind,
                shape: CredentialShape::StaticSecret,
                value,
            });
        }
        tx.commit().await?;
        Ok(released)
    }

    /// Unseals the user's credential for `job_id` and records the use in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the id is unknown or owned by another user and
    /// [`StoreError::Seal`] when the value cannot be opened. No use row is written then.
    pub async fn open_for_use(
        &self,
        user_id: i64,
        credential_id: i64,
        job_id: &str,
    ) -> Result<Secret, StoreError> {
        let mut tx = self.pool.begin().await?;
        let (_, secret) = self.unseal(&mut tx, user_id, credential_id).await?;
        sqlx::query(INSERT_USE)
            .bind(credential_id)
            .bind(job_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(secret)
    }
}

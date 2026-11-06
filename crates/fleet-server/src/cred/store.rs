//! Postgres credential store over a [`Sealer`] (ADR-0040).
//!
//! Plaintext exists only inside [`Secret`] values. No error or `Debug` output carries it.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fleet_core::capability::Capability;
use fleet_core::credential::{
    BotIdentity, CredentialError, CredentialKind, CredentialShape, Secret, fingerprint, validate,
};
use fleet_proto::MAX_CREDENTIALS_PER_USER;
use sqlx::{PgPool, Row};

use super::app_jwt::AppKey;
use super::app_mint::{AppClient, InstallationToken};
use super::capability::ERR_CAPABILITY_NOT_GRANTED;
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
FROM credentials WHERE user_id = $1 AND tombstoned_at IS NULL ORDER BY id";

const DELETE: &str = "DELETE FROM credentials WHERE id = $1 AND user_id = $2";

const SELECT_FOR_USE: &str = "\
SELECT kind, ciphertext, key_id FROM credentials WHERE id = $1 AND user_id = $2 AND tombstoned_at IS NULL FOR SHARE";

const SELECT_LEASE: &str = "\
SELECT user_id, agent, repo FROM jobs \
WHERE job_id = $1 AND attempt = $2 AND box = $3 AND state = 'RUNNING' \
AND lease_expires_at > now() FOR SHARE";

const SELECT_RELEASABLE: &str = "\
SELECT id, kind, (expires_at IS NOT NULL AND expires_at <= now()) AS expired \
FROM credentials WHERE user_id = $1 AND kind = ANY($2) AND tombstoned_at IS NULL ORDER BY id";

const LATEST_JOB_REPO: &str =
    "SELECT repo FROM jobs WHERE user_id = $1 ORDER BY created_at DESC, job_id DESC LIMIT 1";

const READ_CAPABILITY: &str =
    "SELECT user_id FROM user_capabilities WHERE user_id = $1 AND capability = $2 FOR SHARE";

const INSERT_USE: &str = "INSERT INTO credential_use (credential_id, job_id) VALUES ($1, $2)";

/// The GitHub App mint lane: the parsed key, the App id, the token client and the bot identity
/// a Job commits under (ADR-0058).
pub struct AppLane {
    key: AppKey,
    app_id: String,
    client: AppClient,
    identity: BotIdentity,
}

impl AppLane {
    async fn mint(
        &self,
        released: &[ReleasedCredential],
        repo: &str,
    ) -> Result<InstallationToken, StoreError> {
        let installation = released
            .iter()
            .find(|c| c.kind == CredentialKind::GithubApp)
            .and_then(|c| std::str::from_utf8(c.value.expose()).ok())
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(StoreError::MintFailed)?;
        self.mint_installation(installation, repo).await
    }

    async fn mint_installation(
        &self,
        installation: u64,
        repo: &str,
    ) -> Result<InstallationToken, StoreError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::MintFailed)?
            .as_secs();
        let jwt = self
            .key
            .sign(&self.app_id, now)
            .map_err(|_| StoreError::MintFailed)?;
        match self
            .client
            .mint(&jwt, installation, repo_name(repo), now)
            .await
        {
            Ok(token) => Ok(token),
            Err(err) => {
                tracing::warn!(error = %err, "github app token mint failed");
                Err(StoreError::MintFailed)
            }
        }
    }

    async fn revoke(&self, token: &InstallationToken) {
        if let Err(err) = self.client.revoke(token).await {
            tracing::warn!(error = %err, "github app token revoke failed");
        }
    }

    /// Builds the lane. `app_id` is the JWT `iss` text and `identity` is what the Box commits
    /// under.
    pub fn new(key: AppKey, app_id: String, client: AppClient, identity: BotIdentity) -> Self {
        Self {
            key,
            app_id,
            client,
            identity,
        }
    }
}

impl fmt::Debug for AppLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppLane(..)")
    }
}

pub(super) fn repo_name(repo: &str) -> &str {
    let last = repo
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(repo);
    last.strip_suffix(".git").unwrap_or(last)
}

async fn record_uses(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ids: &[i64],
    job_id: &str,
) -> Result<(), StoreError> {
    for id in ids {
        sqlx::query(INSERT_USE)
            .bind(id)
            .bind(job_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// One credential released to a Box for a leased Job.
pub struct ReleasedCredential {
    /// What the credential authenticates against.
    pub kind: CredentialKind,
    /// Storage shape.
    pub shape: CredentialShape,
    /// The secret value.
    pub value: Secret,
    /// Expiry in milliseconds since the Unix epoch, set on a minted installation token.
    pub expires_at_ms: Option<u64>,
    /// The git identity to commit under, set on the `github_app` credential only.
    pub git_identity: Option<BotIdentity>,
}

impl fmt::Debug for ReleasedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleasedCredential")
            .field("kind", &self.kind)
            .field("shape", &self.shape)
            .finish_non_exhaustive()
    }
}

/// The capability a User must hold to store or have released a credential of `kind`.
///
/// Only the `github_app` kind needs one: [`Capability::ForgeGithubApp`] (ADR-0058). `put`
/// checks it at save, and the release and verify paths check it again.
pub const fn required_capability(kind: CredentialKind) -> Option<Capability> {
    match kind {
        CredentialKind::GithubApp => Some(Capability::ForgeGithubApp),
        CredentialKind::AnthropicApiKey
        | CredentialKind::ClaudeSubscriptionToken
        | CredentialKind::GithubPat
        | CredentialKind::KimiMembershipKey
        | CredentialKind::KimiPlatformKey
        | CredentialKind::CodexApiKey => None,
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
    /// The owner lacks the capability the credential kind needs.
    CapabilityDenied,
    /// The GitHub App token could not be minted. One fixed error covers every cause.
    MintFailed,
    /// The owner has no Job whose repository a verify mint can be scoped to.
    NoJobRepo,
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
            Self::CapabilityDenied => f.write_str(ERR_CAPABILITY_NOT_GRANTED),
            Self::MintFailed => f.write_str(fleet_proto::PRECONDITION_APP_MINT),
            Self::NoJobRepo => f.write_str(fleet_proto::PRECONDITION_NO_VERIFY_REPO),
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
    gate: fn(CredentialKind) -> Option<Capability>,
    app: Option<Arc<AppLane>>,
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
            gate: required_capability,
            app: None,
        }
    }

    /// Attaches the GitHub App mint lane. Without it a release for a User holding a
    /// `github_app` credential fails with [`StoreError::MintFailed`], and a verify without it yields the same error, shown as
    /// `valid: false`.
    #[must_use]
    pub fn with_github_app(mut self, lane: AppLane) -> Self {
        self.app = Some(Arc::new(lane));
        self
    }

    /// Replaces the map from credential kind to the capability it needs.
    ///
    /// A seam for tests: production uses [`required_capability`].
    #[must_use]
    pub fn with_capability_gate(mut self, gate: fn(CredentialKind) -> Option<Capability>) -> Self {
        self.gate = gate;
        self
    }

    async fn require_capability(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: i64,
        kind: CredentialKind,
    ) -> Result<(), StoreError> {
        let Some(capability) = (self.gate)(kind) else {
            return Ok(());
        };
        let held = sqlx::query(READ_CAPABILITY)
            .bind(user_id)
            .bind(capability.as_str())
            .fetch_optional(&mut **tx)
            .await?;
        held.map(|_| ()).ok_or(StoreError::CapabilityDenied)
    }

    /// Validates, seals and stores `value`, replacing the user's credential of the same kind.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Invalid`] for a rejected value, [`StoreError::InvalidExpiry`] for an
    /// expiry outside `0..=MAX_EXPIRY_MS`, [`StoreError::TooMany`] when a new kind would pass
    /// the per-user cap, [`StoreError::CapabilityDenied`] when the kind needs a capability the
    /// user lacks (checked before any write), [`StoreError::Seal`] when sealing fails and
    /// [`StoreError::Db`] for a database failure.
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
        self.require_capability(&mut tx, user_id, kind).await?;
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
    /// The reply holds every stored credential of a kind the agent accepts, plus one forge
    /// credential. One use row is written per credential, in the same transaction as the reads
    /// on the PAT path.
    ///
    /// The lease read takes `FOR SHARE` on the job row. A reclaim, a finish or any other write
    /// to that row waits until this transaction commits or rolls back, so the credentials are
    /// released against a lease that stays valid for the whole transaction. The lease expiring
    /// by the clock is not prevented: it is checked once, when the row is read.
    ///
    /// The forge kinds are `github_pat` and `github_app`. When the owner holds both, the App wins
    /// and the PAT is never released, even when the App path fails (ADR-0058, SEC-008). The App
    /// token is minted after the capability check and after the first transaction commits, so no
    /// row lock is held across the network call. A second transaction then re-reads the lease
    /// and the capability and writes the use rows, only after the mint succeeded. If that fails
    /// the token is revoked best effort. Any mint failure returns [`StoreError::MintFailed`]
    /// and writes no use row. A wrong lease never reaches the mint.
    ///
    /// Expired credentials of an agent kind are skipped. The release fails with
    /// [`StoreError::Expired`] only when the GitHub credential is expired or when every
    /// credential of a kind the agent accepts is expired. Checks run in this order: lease,
    /// GitHub, agent, expiry.
    ///
    /// The opened plaintext is copied into a [`Secret`] and the intermediate buffers are not
    /// zeroed. This is accepted: the value is also in the reply sent to the Box, so zeroing the
    /// server copy would not shrink the exposure.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LeaseDenied`] when no job matches the lease (also after the mint, when the recheck fails),
    /// [`StoreError::NoGithub`] when the owner has no GitHub credential,
    /// [`StoreError::Expired`] when a needed credential is past its expiry,
    /// [`StoreError::CapabilityDenied`] when the owner lacks the capability a stored kind needs (also after the mint, when the recheck fails),
    /// [`StoreError::NoAgentCredential`] when the owner has none the agent accepts,
    /// [`StoreError::MintFailed`] when the App token cannot be minted,
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
        let repo: String = lease.try_get("repo")?;
        let mut wanted: Vec<&str> = agent_kinds(&agent)
            .iter()
            .map(|kind| kind.wire_name())
            .collect();
        wanted.extend(
            CredentialKind::ALL
                .into_iter()
                .filter(|kind| kind.is_forge())
                .map(CredentialKind::wire_name),
        );
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
        for (_, kind, _) in &found {
            self.require_capability(&mut tx, user_id, *kind).await?;
        }
        let forge = found
            .iter()
            .map(|(_, kind, _)| *kind)
            .filter(|kind| kind.is_forge())
            .min_by_key(|kind| *kind != CredentialKind::GithubApp);
        let Some(forge) = forge else {
            return Err(StoreError::NoGithub);
        };
        found.retain(|(_, kind, _)| !kind.is_forge() || *kind == forge);
        if found.iter().all(|(_, kind, _)| kind.is_forge()) {
            return Err(StoreError::NoAgentCredential);
        }
        let forge_expired = found
            .iter()
            .any(|(_, kind, expired)| kind.is_forge() && *expired);
        found.retain(|(_, kind, expired)| kind.is_forge() || !*expired);
        if forge_expired || found.iter().all(|(_, kind, _)| kind.is_forge()) {
            return Err(StoreError::Expired);
        }
        let mut released = Vec::with_capacity(found.len());
        let mut ids = Vec::with_capacity(found.len());
        for (id, _, _) in found {
            let (kind, value) = self.unseal(&mut tx, user_id, id).await?;
            ids.push(id);
            released.push(ReleasedCredential {
                kind,
                shape: CredentialShape::StaticSecret,
                value,
                expires_at_ms: None,
                git_identity: None,
            });
        }
        if forge != CredentialKind::GithubApp {
            record_uses(&mut tx, &ids, job_id).await?;
            tx.commit().await?;
            return Ok(released);
        }
        let lane = self.app.clone().ok_or(StoreError::MintFailed)?;
        tx.commit().await?;
        let token = lane.mint(&released, &repo).await?;
        let rechecked = self
            .record_after_mint(job_id, attempt, box_name, user_id, &ids)
            .await;
        if let Err(err) = rechecked {
            lane.revoke(&token).await;
            return Err(err);
        }
        for credential in &mut released {
            if credential.kind == CredentialKind::GithubApp {
                credential.value = Secret::new(token.expose().to_owned());
                credential.expires_at_ms = token.expires_at().checked_mul(1000);
                credential.git_identity = Some(lane.identity.clone());
            }
        }
        Ok(released)
    }

    async fn record_after_mint(
        &self,
        job_id: &str,
        attempt: i32,
        box_name: &str,
        user_id: i64,
        ids: &[i64],
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(SELECT_LEASE)
            .bind(job_id)
            .bind(attempt)
            .bind(box_name)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::LeaseDenied)?;
        self.require_capability(&mut tx, user_id, CredentialKind::GithubApp)
            .await?;
        record_uses(&mut tx, ids, job_id).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Mints one installation token for a stored `github_app` credential and drops it.
    ///
    /// The token is scoped to the repository of the user's most recent Job (ADR-0058, SEC-009).
    /// The capability is checked in a short transaction under `FOR SHARE`, the transaction
    /// commits, and then the mint runs: no row lock is held across the network call. The token
    /// is revoked best effort and never leaves this function. No use row is written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CapabilityDenied`] when the user lacks the capability,
    /// [`StoreError::NoJobRepo`] when the user has no Job, [`StoreError::MintFailed`] when the
    /// lane is absent, the installation id is malformed or the mint fails, and
    /// [`StoreError::Db`] for a database failure.
    pub async fn probe_app(&self, user_id: i64, installation: &Secret) -> Result<(), StoreError> {
        let installation = std::str::from_utf8(installation.expose())
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(StoreError::MintFailed)?;
        let lane = self.app.clone().ok_or(StoreError::MintFailed)?;
        let mut tx = self.pool.begin().await?;
        self.require_capability(&mut tx, user_id, CredentialKind::GithubApp)
            .await?;
        let repo: String = sqlx::query_scalar(LATEST_JOB_REPO)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NoJobRepo)?;
        tx.commit().await?;
        let token = lane.mint_installation(installation, &repo).await?;
        lane.revoke(&token).await;
        Ok(())
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

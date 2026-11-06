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
use super::app_mint::{AppClient, InstallationToken, REQUESTED_PERMISSIONS};
use super::capability::ERR_CAPABILITY_NOT_GRANTED;
use super::github::MAX_EXPIRY_MS;
use super::seal::{Aad, SealError, Sealer};

const UPSERT: &str = "\
INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint, login, expires_at) \
VALUES ($1, $2, $3, '\\x'::bytea, 'pending', $4, $5, to_timestamp($6::bigint / 1000.0)) \
ON CONFLICT (user_id, kind) DO UPDATE SET shape = EXCLUDED.shape, \
fingerprint = EXCLUDED.fingerprint, login = EXCLUDED.login, expires_at = EXCLUDED.expires_at \
WHERE credentials.tombstoned_at IS NULL RETURNING id";

const LOCK_USER: &str = "SELECT pg_advisory_xact_lock($1)";

const COUNT_OTHERS: &str = "SELECT count(*) FROM credentials WHERE user_id = $1 AND kind <> $2";

const STORE_SEALED: &str = "UPDATE credentials SET ciphertext = $1, key_id = $2 WHERE id = $3";

const LIST: &str = "\
SELECT id, kind, shape, fingerprint, login, \
(EXTRACT(EPOCH FROM expires_at) * 1000)::bigint AS expires_ms \
FROM credentials WHERE user_id = $1 AND tombstoned_at IS NULL ORDER BY id";

const DELETE: &str = "DELETE FROM credentials WHERE id = $1 AND user_id = $2";

const LOCK_FOR_DELETE: &str = "\
SELECT id FROM credentials WHERE id = $1 AND user_id = $2 AND tombstoned_at IS NULL FOR UPDATE";

const HAS_MINT_HISTORY: &str =
    "SELECT EXISTS (SELECT 1 FROM github_app_mint WHERE credential_id = $1)";

const TOMBSTONE: &str =
    "UPDATE credentials SET tombstoned_at = now() WHERE id = $1 AND user_id = $2";

const LIVE_CREDENTIAL: &str =
    "SELECT id FROM credentials WHERE id = $1 AND tombstoned_at IS NULL FOR SHARE";

const SELECT_FOR_USE: &str = "\
SELECT kind, ciphertext, key_id FROM credentials WHERE id = $1 AND user_id = $2 AND tombstoned_at IS NULL FOR SHARE";

const SELECT_LEASE: &str = "\
SELECT user_id, agent, repo FROM jobs \
WHERE job_id = $1 AND attempt = $2 AND box = $3 AND state = 'RUNNING' \
AND lease_expires_at > now() FOR SHARE";

const SELECT_RELEASABLE: &str = "\
SELECT id, kind, (expires_at IS NOT NULL AND expires_at <= now()) AS expired \
FROM credentials WHERE user_id = $1 AND kind = ANY($2) AND tombstoned_at IS NULL ORDER BY id";

const LATEST_JOB: &str = "\
SELECT job_id, repo FROM jobs WHERE user_id = $1 ORDER BY created_at DESC, job_id DESC LIMIT 1";

const READ_CAPABILITY: &str =
    "SELECT user_id FROM user_capabilities WHERE user_id = $1 AND capability = $2 FOR SHARE";

const INSERT_USE: &str = "INSERT INTO credential_use (credential_id, job_id) VALUES ($1, $2)";

const LOCK_CREDENTIAL: &str =
    "SELECT id FROM credentials WHERE id = $1 AND tombstoned_at IS NULL FOR UPDATE";

const COUNT_ATTEMPTS: &str =
    "SELECT count(*) FROM github_app_mint WHERE job_id = $1 AND outcome = 'attempt'";

const COUNT_USER_ATTEMPTS: &str = "\
SELECT count(*) FROM github_app_mint m JOIN credentials c ON c.id = m.credential_id \
WHERE c.user_id = $1 AND m.outcome = 'attempt' AND m.at > clock_timestamp() - $2::bigint * interval '1 second'";

const DENIED_RECENTLY: &str = "\
SELECT EXISTS (SELECT 1 FROM github_app_mint WHERE job_id = $1 AND outcome = 'denied' \
AND reason = $2 AND at > now() - $3::bigint * interval '1 second')";

const INSERT_ROOT: &str = "\
WITH fresh AS (SELECT gen_random_uuid() AS id) \
INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, installation_id, \
requested_permissions, outcome, reason) \
SELECT id, id, $1, $2, $3, $4, $5, $6, $7 FROM fresh RETURNING attempt_id::text";

const INSERT_OUTCOME: &str = "\
INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, installation_id, \
requested_permissions, outcome, reason, expires_at) \
VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, $5, $6, $7, $8, to_timestamp($9::bigint))";

/// The longest a Job may run that the mint cap plans for, in seconds (ADR-0058, SEC-004).
pub const MAX_JOB_DURATION_SECS: u64 = 24 * 60 * 60;

/// Seconds between refreshes: the one-hour token life less the ten-minute refresh window.
pub const REFRESH_INTERVAL_SECS: u64 = 50 * 60;

/// Mints beyond the planned ones, for retries and a re-claimed attempt.
pub const MINT_CAP_MARGIN: u32 = 4;

/// Most `attempt` rows one Job may hold.
///
/// The cap counts the first mint, one refresh per [`REFRESH_INTERVAL_SECS`] across the
/// longest Job of [`MAX_JOB_DURATION_SECS`] (29 refreshes) and a margin of
/// [`MINT_CAP_MARGIN`] (4), which makes 34 (ADR-0058, SEC-004, SEC-011). A release past it fails
/// with [`StoreError::MintCapReached`].
pub const MAX_APP_MINTS_PER_JOB: u32 = 1 + 29 + MINT_CAP_MARGIN;

const _: () = assert!(
    MAX_JOB_DURATION_SECS.div_ceil(REFRESH_INTERVAL_SECS) == 29,
    "MAX_APP_MINTS_PER_JOB assumes 29 refreshes"
);

/// Most mint attempts one User may start in [`MINT_RATE_WINDOW_SECS`] (ADR-0058, SEC-003).
pub const MAX_APP_MINTS_PER_USER_PER_MINUTE: u32 = 20;

/// The window, in seconds, over which [`MAX_APP_MINTS_PER_USER_PER_MINUTE`] counts.
pub const MINT_RATE_WINDOW_SECS: i64 = 60;

/// A `denied` row for a Job is not written again while one with the same reason is younger than
/// this many seconds, so a Box that retries at the cap cannot grow the audit table.
pub const DENIED_DEDUPE_SECS: i64 = 60;

const REASON_CAP: &str = "job mint cap";
const REASON_USER_RATE: &str = "user mint rate";
const REASON_MINT_FAILED: &str = "mint failed";
const REASON_LEASE: &str = "lease lost after mint";
const REASON_CAPABILITY: &str = "capability gone after mint";
const REASON_OUTCOME: &str = "outcome write failed";
const REASON_REVOKE: &str = "revoke refused";
const REASON_CREDENTIAL: &str = "credential gone after mint";

#[derive(Clone)]
struct MintRecord {
    credential_id: i64,
    job_id: String,
    repo: String,
    installation: String,
}

fn requested_permissions_text() -> String {
    REQUESTED_PERMISSIONS
        .iter()
        .map(|(name, level)| format!("{name}:{level}"))
        .collect::<Vec<_>>()
        .join(",")
}

impl MintRecord {
    async fn root(
        &self,
        conn: &mut sqlx::PgConnection,
        outcome: &str,
        reason: Option<&str>,
    ) -> Result<String, sqlx::Error> {
        sqlx::query_scalar(INSERT_ROOT)
            .bind(self.credential_id)
            .bind(&self.job_id)
            .bind(&self.repo)
            .bind(&self.installation)
            .bind(requested_permissions_text())
            .bind(outcome)
            .bind(reason)
            .fetch_one(conn)
            .await
    }

    async fn outcome(
        &self,
        conn: &mut sqlx::PgConnection,
        attempt_id: &str,
        outcome: &str,
        reason: Option<&str>,
        expires_at: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(INSERT_OUTCOME)
            .bind(attempt_id)
            .bind(self.credential_id)
            .bind(&self.job_id)
            .bind(&self.repo)
            .bind(&self.installation)
            .bind(requested_permissions_text())
            .bind(outcome)
            .bind(reason)
            .bind(expires_at.and_then(|at| i64::try_from(at).ok()))
            .execute(conn)
            .await
            .map(|_| ())
    }

    async fn outcome_pooled(
        &self,
        pool: &PgPool,
        attempt_id: &str,
        outcome: &str,
        reason: Option<&str>,
    ) {
        let written = async {
            let mut conn = pool.acquire().await?;
            self.outcome(&mut conn, attempt_id, outcome, reason, None)
                .await
        }
        .await;
        if let Err(err) = written {
            tracing::error!(%err, outcome, "github app mint audit row not written");
        }
    }
}

struct Armed {
    lane: Arc<AppLane>,
    pool: PgPool,
    record: MintRecord,
    attempt_id: String,
    token: InstallationToken,
}

impl Armed {
    async fn revoke(&self) -> bool {
        let revoked = self.lane.revoke(&self.token).await;
        let (outcome, reason) = if revoked {
            ("revoked", None)
        } else {
            ("revoke_failed", Some(REASON_REVOKE))
        };
        self.record
            .outcome_pooled(&self.pool, &self.attempt_id, outcome, reason)
            .await;
        revoked
    }
}

struct RevokeGuard {
    armed: Option<Armed>,
}

impl RevokeGuard {
    async fn revoke(&mut self) -> bool {
        let Some(armed) = &self.armed else {
            return true;
        };
        let revoked = armed.revoke().await;
        self.armed = None;
        revoked
    }

    fn disarm(&mut self) -> Option<InstallationToken> {
        self.armed.take().map(|a| a.token)
    }
}

impl Drop for RevokeGuard {
    fn drop(&mut self) {
        let Some(armed) = self.armed.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                armed.revoke().await;
            });
        } else {
            tracing::error!(
                attempt_id = %armed.attempt_id,
                credential_id = armed.record.credential_id,
                "github app token not revoked: guard dropped outside a runtime"
            );
        }
    }
}

#[cfg(test)]
pub(super) fn armed_guard_for_test(
    lane: AppLane,
    pool: PgPool,
    token: InstallationToken,
) -> impl Drop {
    RevokeGuard {
        armed: Some(Armed {
            lane: Arc::new(lane),
            pool,
            record: MintRecord {
                credential_id: 1,
                job_id: "job".to_owned(),
                repo: "o/widget".to_owned(),
                installation: "1".to_owned(),
            },
            attempt_id: "attempt-under-test".to_owned(),
            token,
        }),
    }
}

fn wanted_kinds(agent: &str) -> Vec<&'static str> {
    let mut wanted: Vec<&'static str> = agent_kinds(agent)
        .iter()
        .map(|kind| kind.wire_name())
        .collect();
    wanted.extend(
        CredentialKind::ALL
            .into_iter()
            .filter(|kind| kind.is_forge())
            .map(CredentialKind::wire_name),
    );
    wanted
}

struct AppCredential {
    lane: Arc<AppLane>,
    id: i64,
}

struct Minted<'a> {
    record: &'a MintRecord,
    attempt_id: &'a str,
    expires_at: u64,
}

struct Release<'a> {
    job_id: &'a str,
    attempt: i32,
    box_name: &'a str,
    user_id: i64,
    repo: &'a str,
}

/// The result of comparing the configured App id with the one GitHub reports for the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppIdCheck {
    /// GitHub reports the configured App id.
    Match,
    /// GitHub reports a different App id: the key belongs to another App.
    Mismatch,
    /// GitHub could not answer, so the key was not compared.
    Unchecked,
}

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

    /// Compares the configured App id with the one GitHub reports for the key.
    pub async fn check_app_id(&self) -> AppIdCheck {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return AppIdCheck::Unchecked;
        };
        let Ok(jwt) = self.key.sign(&self.app_id, now.as_secs()) else {
            return AppIdCheck::Unchecked;
        };
        match self.client.app_id(&jwt).await {
            Ok(id) if id.to_string() == self.app_id => AppIdCheck::Match,
            Ok(_) => AppIdCheck::Mismatch,
            Err(err) => {
                tracing::warn!(error = %err, "github app id check failed");
                AppIdCheck::Unchecked
            }
        }
    }

    async fn revoke(&self, token: &InstallationToken) -> bool {
        match self.client.revoke(token).await {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(error = %err, "github app token revoke failed");
                false
            }
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
    /// The Job already holds [`MAX_APP_MINTS_PER_JOB`] mint attempts (ADR-0058, SEC-011), or its
    /// User started [`MAX_APP_MINTS_PER_USER_PER_MINUTE`] in the last minute (SEC-003). Both
    /// share one fixed message.
    MintCapReached,
    /// The owner has no Job whose repository a verify mint can be scoped to.
    NoJobRepo,
    /// The credential was deleted and kept as a tombstone because it has mint history. A
    /// `put` cannot replace it (ADR-0058, SEC-022).
    Tombstoned,
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
            Self::MintCapReached => f.write_str(fleet_proto::PRECONDITION_APP_MINT_CAP),
            Self::NoJobRepo => f.write_str(fleet_proto::PRECONDITION_NO_VERIFY_REPO),
            Self::Tombstoned => f.write_str(fleet_proto::PRECONDITION_CREDENTIAL_TOMBSTONED),
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
    mint_cap: u32,
    user_rate: u32,
    denied_dedupe_secs: i64,
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
            mint_cap: MAX_APP_MINTS_PER_JOB,
            user_rate: MAX_APP_MINTS_PER_USER_PER_MINUTE,
            denied_dedupe_secs: DENIED_DEDUPE_SECS,
        }
    }

    /// Replaces the per-User mint limit, [`MAX_APP_MINTS_PER_USER_PER_MINUTE`] by default.
    ///
    /// A seam for tests, which cross the limit with a small value.
    #[must_use]
    pub const fn with_user_mint_limit(mut self, limit: u32) -> Self {
        self.user_rate = limit;
        self
    }

    /// Replaces the `denied` row dedupe window, [`DENIED_DEDUPE_SECS`] by default. Zero writes
    /// every denial.
    ///
    /// A seam for tests.
    #[must_use]
    pub const fn with_denied_dedupe_secs(mut self, secs: i64) -> Self {
        self.denied_dedupe_secs = secs;
        self
    }

    /// Replaces the per-Job mint cap, [`MAX_APP_MINTS_PER_JOB`] by default.
    ///
    /// A seam for tests, which cross the cap with a small value.
    #[must_use]
    pub const fn with_mint_cap(mut self, cap: u32) -> Self {
        self.mint_cap = cap;
        self
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
    /// [`StoreError::Tombstoned`] when the user's credential of this kind was deleted and kept
    /// as a tombstone, and [`StoreError::Db`] for a database failure.
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
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::Tombstoned)?;
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

    /// Deletes the user's credential. Use rows stay.
    ///
    /// A credential with mint history in `github_app_mint` is tombstoned instead of removed:
    /// the row stays, no read returns it and a `put` of the same kind is refused (ADR-0058,
    /// SEC-022). The history check runs under `FOR UPDATE` on the row, the lock every mint
    /// takes before it writes its first audit row. Any other credential is removed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the id is unknown, owned by another user or
    /// already tombstoned, and [`StoreError::Db`] for a database failure.
    pub async fn delete(&self, user_id: i64, credential_id: i64) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_FOR_DELETE)
            .bind(credential_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        let history: bool = sqlx::query_scalar(HAS_MINT_HISTORY)
            .bind(credential_id)
            .fetch_one(&mut *tx)
            .await?;
        let statement = if history { TOMBSTONE } else { DELETE };
        sqlx::query(statement)
            .bind(credential_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Unseals the user's credential to check it with its provider. No use row is written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the id is unknown, owned by another user or tombstoned
    /// and [`StoreError::Seal`] when the value cannot be opened.
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
    /// Every call that reaches the mint step is a mint, the first fetch and each refresh alike
    /// (ADR-0058, SEC-004). The first transaction takes `FOR UPDATE` on the `github_app`
    /// credential row (SEC-021) and counts the Job's `attempt` rows in `github_app_mint`. The
    /// Job count must stay under [`MAX_APP_MINTS_PER_JOB`], or under the cap set with
    /// [`CredentialStore::with_mint_cap`]. The transaction also counts the User's `attempt`
    /// rows of the last [`MINT_RATE_WINDOW_SECS`] across every Job and credential row of the
    /// User. That count must stay under [`MAX_APP_MINTS_PER_USER_PER_MINUTE`], or under the
    /// limit set with [`CredentialStore::with_user_mint_limit`]. Under both limits the
    /// transaction inserts a fresh `attempt` row and commits before the mint (SEC-003,
    /// SEC-011, SEC-022). At either limit it writes a `denied` row, unless one with the same
    /// reason younger than [`DENIED_DEDUPE_SECS`] exists for the Job. It then commits and fails
    /// with [`StoreError::MintCapReached`] without a mint. After the mint the second
    /// transaction writes the `minted` row with the token expiry together with the use rows.
    /// A mint failure writes `failed`. A failed recheck writes `denied` or `failed`, the token
    /// is revoked and a `revoked` or `revoke_failed` row follows. A guard revokes the token on
    /// a task when this future is dropped between the mint and the reply.
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
    /// Returns [`StoreError::LeaseDenied`] when no job matches the lease, which also happens
    /// after the mint when the recheck fails. Returns [`StoreError::NoGithub`] when the owner
    /// has no GitHub credential. Returns [`StoreError::Expired`] when a needed credential is
    /// past its expiry. Returns [`StoreError::CapabilityDenied`] when the owner lacks the
    /// capability a stored kind needs, which also happens after the mint when the recheck
    /// fails. Returns [`StoreError::NoAgentCredential`] when the owner has none the agent
    /// accepts. Returns [`StoreError::NotFound`] when the credential row is gone or tombstoned
    /// after the mint. Returns [`StoreError::MintFailed`] when the App token cannot be minted.
    /// Returns [`StoreError::MintCapReached`] when the Job already holds the cap of mint
    /// attempts or the User started the per-minute limit of them. Returns
    /// [`StoreError::Seal`] when a value cannot be opened and [`StoreError::Db`] for a
    /// database failure, which includes an audit row that cannot be written before the mint.
    /// No use row is written on any error.
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
        let wanted = wanted_kinds(&agent);
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
        let lane = if forge == CredentialKind::GithubApp {
            let lane = self.app.clone().ok_or(StoreError::MintFailed)?;
            let app_id = found
                .iter()
                .find(|(_, kind, _)| *kind == CredentialKind::GithubApp)
                .map(|(id, _, _)| *id)
                .ok_or(StoreError::MintFailed)?;
            sqlx::query(LOCK_CREDENTIAL)
                .bind(app_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::MintFailed)?;
            Some(AppCredential { lane, id: app_id })
        } else {
            None
        };
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
        let Some(app) = lane else {
            record_uses(&mut tx, &ids, job_id).await?;
            tx.commit().await?;
            return Ok(released);
        };
        self.mint_released(
            tx,
            &Release {
                job_id,
                attempt,
                box_name,
                user_id,
                repo: &repo,
            },
            app,
            released,
            ids,
        )
        .await
    }

    async fn mint_released(
        &self,
        tx: sqlx::Transaction<'_, sqlx::Postgres>,
        release: &Release<'_>,
        app: AppCredential,
        mut released: Vec<ReleasedCredential>,
        ids: Vec<i64>,
    ) -> Result<Vec<ReleasedCredential>, StoreError> {
        let Release {
            job_id,
            attempt,
            box_name,
            user_id,
            repo,
        } = *release;
        let AppCredential { lane, id: app_id } = app;
        let installation = released
            .iter()
            .find(|c| c.kind == CredentialKind::GithubApp)
            .and_then(|c| std::str::from_utf8(c.value.expose()).ok())
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(StoreError::MintFailed)?;
        let record = MintRecord {
            credential_id: app_id,
            job_id: job_id.to_owned(),
            repo: repo.to_owned(),
            installation: installation.to_string(),
        };
        let attempt_id = self.admit(tx, &record, user_id).await?;
        let token = match lane.mint(&released, repo).await {
            Ok(token) => token,
            Err(err) => {
                record
                    .outcome_pooled(&self.pool, &attempt_id, "failed", Some(REASON_MINT_FAILED))
                    .await;
                return Err(err);
            }
        };
        let expires_at = token.expires_at();
        let mut guard = RevokeGuard {
            armed: Some(Armed {
                lane: Arc::clone(&lane),
                pool: self.pool.clone(),
                record: record.clone(),
                attempt_id: attempt_id.clone(),
                token,
            }),
        };
        let rechecked = self
            .record_after_mint(
                job_id,
                attempt,
                box_name,
                user_id,
                &ids,
                &Minted {
                    record: &record,
                    attempt_id: &attempt_id,
                    expires_at,
                },
            )
            .await;
        if let Err(err) = rechecked {
            let (outcome, reason) = match err {
                StoreError::LeaseDenied => ("denied", REASON_LEASE),
                StoreError::CapabilityDenied => ("denied", REASON_CAPABILITY),
                StoreError::NotFound => ("denied", REASON_CREDENTIAL),
                _ => ("failed", REASON_OUTCOME),
            };
            record
                .outcome_pooled(&self.pool, &attempt_id, outcome, Some(reason))
                .await;
            guard.revoke().await;
            return Err(err);
        }
        let token = guard.disarm().ok_or(StoreError::MintFailed)?;
        for credential in &mut released {
            if credential.kind == CredentialKind::GithubApp {
                credential.value = Secret::new(token.expose().to_owned());
                credential.expires_at_ms = token.expires_at().checked_mul(1000);
                credential.git_identity = Some(lane.identity.clone());
            }
        }
        Ok(released)
    }

    async fn admit(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        record: &MintRecord,
        user_id: i64,
    ) -> Result<String, StoreError> {
        let attempts: i64 = sqlx::query_scalar(COUNT_ATTEMPTS)
            .bind(&record.job_id)
            .fetch_one(&mut *tx)
            .await?;
        if attempts >= i64::from(self.mint_cap) {
            self.deny(&mut tx, record, REASON_CAP).await?;
            tx.commit().await?;
            return Err(StoreError::MintCapReached);
        }
        let recent: i64 = sqlx::query_scalar(COUNT_USER_ATTEMPTS)
            .bind(user_id)
            .bind(MINT_RATE_WINDOW_SECS)
            .fetch_one(&mut *tx)
            .await?;
        if recent >= i64::from(self.user_rate) {
            self.deny(&mut tx, record, REASON_USER_RATE).await?;
            tx.commit().await?;
            return Err(StoreError::MintCapReached);
        }
        let attempt_id = record.root(&mut tx, "attempt", None).await?;
        tx.commit().await?;
        Ok(attempt_id)
    }

    async fn deny(
        &self,
        tx: &mut sqlx::PgConnection,
        record: &MintRecord,
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        let recent: bool = sqlx::query_scalar(DENIED_RECENTLY)
            .bind(&record.job_id)
            .bind(reason)
            .bind(self.denied_dedupe_secs)
            .fetch_one(&mut *tx)
            .await?;
        if !recent {
            record.root(tx, "denied", Some(reason)).await?;
        }
        Ok(())
    }

    async fn record_after_mint(
        &self,
        job_id: &str,
        attempt: i32,
        box_name: &str,
        user_id: i64,
        ids: &[i64],
        minted: &Minted<'_>,
    ) -> Result<(), StoreError> {
        let Minted {
            record,
            attempt_id,
            expires_at,
        } = *minted;
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
        sqlx::query(LIVE_CREDENTIAL)
            .bind(record.credential_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        record_uses(&mut tx, ids, job_id).await?;
        record
            .outcome(&mut tx, attempt_id, "minted", None, Some(expires_at))
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Mints one installation token for a stored `github_app` credential and drops it.
    ///
    /// The token is scoped to the repository of the user's most recent Job (ADR-0058, SEC-009).
    /// A probe is a mint like any other and takes the same gate as a release. A short
    /// transaction checks the capability under `FOR SHARE`, takes `FOR UPDATE` on the credential
    /// row and counts attempts against the cap of that Job and against the per-User rate limit.
    /// Under both limits it writes an `attempt` row and commits, and then the mint runs: no row
    /// lock is held across the network call. A mint failure writes `failed`. A mint writes
    /// `minted`, and the revoke then writes `revoked` or `revoke_failed`. A guard revokes the
    /// token when this future is dropped between the mint and the revoke. The token never
    /// leaves this function. No use row is written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CapabilityDenied`] when the user lacks the capability,
    /// [`StoreError::NotFound`] when the credential is gone or tombstoned,
    /// [`StoreError::NoJobRepo`] when the user has no Job, [`StoreError::MintCapReached`] when
    /// that Job holds the cap of attempts or the User started the per-minute limit of them,
    /// [`StoreError::MintFailed`] when the lane is absent, the installation id is malformed,
    /// the mint fails or GitHub refuses the revoke, and [`StoreError::Db`] for a database
    /// failure.
    pub async fn probe_app(
        &self,
        user_id: i64,
        credential_id: i64,
        installation: &Secret,
    ) -> Result<(), StoreError> {
        let installation = std::str::from_utf8(installation.expose())
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(StoreError::MintFailed)?;
        let lane = self.app.clone().ok_or(StoreError::MintFailed)?;
        let mut tx = self.pool.begin().await?;
        self.require_capability(&mut tx, user_id, CredentialKind::GithubApp)
            .await?;
        sqlx::query(LOCK_CREDENTIAL)
            .bind(credential_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        let (job_id, repo): (String, String) = sqlx::query_as(LATEST_JOB)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NoJobRepo)?;
        let record = MintRecord {
            credential_id,
            job_id,
            repo,
            installation: installation.to_string(),
        };
        let attempt_id = self.admit(tx, &record, user_id).await?;
        let token = match lane.mint_installation(installation, &record.repo).await {
            Ok(token) => token,
            Err(err) => {
                record
                    .outcome_pooled(&self.pool, &attempt_id, "failed", Some(REASON_MINT_FAILED))
                    .await;
                return Err(err);
            }
        };
        let expires_at = token.expires_at();
        let mut guard = RevokeGuard {
            armed: Some(Armed {
                lane,
                pool: self.pool.clone(),
                record: record.clone(),
                attempt_id: attempt_id.clone(),
                token,
            }),
        };
        let minted = async {
            let mut conn = self.pool.acquire().await?;
            record
                .outcome(&mut conn, &attempt_id, "minted", None, Some(expires_at))
                .await
        }
        .await;
        let revoked = guard.revoke().await;
        minted?;
        if revoked {
            Ok(())
        } else {
            Err(StoreError::MintFailed)
        }
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

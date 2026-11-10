//! Environment storage and secret sealing (ADR-0067).
//!
//! Secrets are sealed with the credential [`Sealer`] and key ring. The associated data binds the
//! user, the Environment id and the secret name ([`Aad::for_environment_secret`]), so a row moved
//! to another owner, Environment or name does not open, and a credential ciphertext never opens
//! here. No error, `Debug` output or log line carries a secret value.

use std::fmt;
use std::sync::Arc;

use fleet_core::credential::{Secret, fingerprint};
use fleet_core::environment::{
    DEFAULT_TIMEOUT_S, Delivery, EgressHost, Entry, EntryName, EnvironmentError, EnvironmentName,
    EnvironmentSpec, MAX_ENTRIES, MAX_TOTAL_BYTES, OnFail, ScriptBody, ScriptSpec, SecretSpec,
    SecretValue,
};
use sqlx::{PgConnection, PgPool};
use zeroize::Zeroizing;

use crate::cred::seal::{Aad, SealError, Sealer};

/// Environments one user may own. ADR-0067 states no number, so this is the chosen cap.
pub const MAX_ENVIRONMENTS_PER_USER: usize = 64;

/// The `INVALID_ARGUMENT` message for an entry that names neither a secret nor a script.
pub const REASON_ENTRY_KIND: &str = "entry names no kind";

/// The `INVALID_ARGUMENT` message for a version number of zero.
pub const REASON_VERSION_REQUIRED: &str = "version is required";

/// The `INVALID_ARGUMENT` message for an enum field holding a number the schema does not name.
pub const REASON_ENUM: &str = "enum value is unknown";

const SHARE_CAPABILITY: &str =
    "SELECT user_id FROM user_capabilities WHERE user_id = $1 AND capability = $2 FOR SHARE";

const RESOLVE_ENVIRONMENT: &str =
    "SELECT id FROM environment WHERE user_id = $1 AND lower(name) = lower($2)";

const LIST_SECRETS: &str = "\
SELECT s.name, s.fingerprint FROM environment_secret s \
JOIN environment e ON e.id = s.environment_id \
WHERE s.environment_id = $1 AND e.user_id = $2 ORDER BY lower(s.name)";

const VERSION_HEAD: &str = "\
SELECT v.hash, v.egress_hosts FROM environment_version v \
JOIN environment e ON e.id = v.environment_id \
WHERE v.environment_id = $1 AND v.version = $2 AND e.user_id = $3";

const VERSION_ENTRIES: &str = "\
SELECT name, kind, agent_visible, delivery, body, on_fail, timeout_s FROM environment_entry \
WHERE environment_id = $1 AND version = $2 ORDER BY position";

const LIST_VERSIONS: &str = "\
SELECT v.version, v.hash FROM environment_version v \
JOIN environment e ON e.id = v.environment_id \
WHERE v.environment_id = $1 AND e.user_id = $2 ORDER BY v.version";

const SHARE_REPO_KEY: &str =
    "SELECT id FROM user_repos WHERE user_id = $1 AND host = $2 AND path = $3 FOR SHARE";

const SHARE_PROFILE_KEY: &str = "\
SELECT id FROM profile WHERE name = $1 AND (owner_user_id = $2 OR visibility = 'shared') \
ORDER BY (owner_user_id = $2) DESC NULLS LAST, id LIMIT 1 FOR SHARE";

const UPSERT_REPO_DEFAULT: &str = "\
INSERT INTO environment_default (user_id, environment_id, repo_id) VALUES ($1, $2, $3) \
ON CONFLICT (user_id, repo_id) DO UPDATE SET environment_id = EXCLUDED.environment_id";

const UPSERT_PROFILE_DEFAULT: &str = "\
INSERT INTO environment_default (user_id, environment_id, profile_id) VALUES ($1, $2, $3) \
ON CONFLICT (user_id, profile_id) DO UPDATE SET environment_id = EXCLUDED.environment_id";

const REPO_DEFAULT_ID: &str =
    "SELECT environment_id FROM environment_default WHERE user_id = $1 AND repo_id = $2";

const PROFILE_DEFAULT_ID: &str =
    "SELECT environment_id FROM environment_default WHERE user_id = $1 AND profile_id = $2";

const REPO_DEFAULT_NAME: &str = "\
SELECT e.name FROM environment_default d JOIN environment e ON e.id = d.environment_id \
AND e.user_id = d.user_id WHERE d.user_id = $1 AND d.repo_id = $2";

const PROFILE_DEFAULT_NAME: &str = "\
SELECT e.name FROM environment_default d JOIN environment e ON e.id = d.environment_id \
AND e.user_id = d.user_id WHERE d.user_id = $1 AND d.profile_id = $2";

const DELETE_REPO_DEFAULT: &str =
    "DELETE FROM environment_default WHERE user_id = $1 AND repo_id = $2";

const DELETE_PROFILE_DEFAULT: &str =
    "DELETE FROM environment_default WHERE user_id = $1 AND profile_id = $2";

const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR UPDATE";

const COUNT_ENVIRONMENTS: &str = "SELECT count(*) FROM environment WHERE user_id = $1";

const LIST_ENVIRONMENTS: &str = "\
SELECT e.id, e.name, \
(SELECT max(v.version) FROM environment_version v WHERE v.environment_id = e.id) \
FROM environment e WHERE e.user_id = $1 ORDER BY lower(e.name), e.id";

const GET_ENVIRONMENT: &str = "\
SELECT e.id, e.name, \
(SELECT max(v.version) FROM environment_version v WHERE v.environment_id = e.id) \
FROM environment e WHERE e.id = $1 AND e.user_id = $2";

const DELETE_ENVIRONMENT: &str = "DELETE FROM environment WHERE id = $1";

const DELETE_SECRET: &str =
    "DELETE FROM environment_secret WHERE environment_id = $1 AND lower(name) = lower($2)";

const OTHER_SECRETS: &str = "\
SELECT name, ciphertext, key_id FROM environment_secret \
WHERE environment_id = $1 AND lower(name) <> lower($2)";

const LATEST_SCRIPTS: &str = "\
SELECT count(*), coalesce(sum(octet_length(body)), 0)::bigint FROM environment_entry \
WHERE environment_id = $1 AND kind = 'script' \
AND version = (SELECT max(version) FROM environment_version WHERE environment_id = $1)";

const SCRIPTS_IN_VERSION: &str = "\
SELECT EXISTS (SELECT 1 FROM environment_entry \
WHERE environment_id = $1 AND version = $2 AND kind = 'script')";

const LATEST_PIN: &str = "\
SELECT e.id, (SELECT max(version) FROM environment_version v WHERE v.environment_id = e.id) \
FROM environment e WHERE e.user_id = $1 AND lower(e.name) = lower($2)";

const LATEST_VERSION: &str = "\
SELECT version, hash FROM environment_version WHERE environment_id = $1 \
ORDER BY version DESC LIMIT 1";

const INSERT_VERSION: &str = "\
INSERT INTO environment_version (environment_id, user_id, version, hash, egress_hosts) \
VALUES ($1, $2, $3, $4, $5)";

const INSERT_SECRET_ENTRY: &str = "\
INSERT INTO environment_entry (environment_id, version, position, name, kind, agent_visible, delivery) \
VALUES ($1, $2, $3, $4, 'secret', $5, $6)";

const INSERT_SCRIPT_ENTRY: &str = "\
INSERT INTO environment_entry (environment_id, version, position, name, kind, body, on_fail, timeout_s) \
VALUES ($1, $2, $3, $4, 'script', $5, $6, $7)";

const INSERT_USE: &str = "\
INSERT INTO environment_use (environment_id, version, job_id, name, fingerprint) \
VALUES ($1, $2, $3, $4, $5)";

const INSERT_ENVIRONMENT: &str = "\
INSERT INTO environment (user_id, name) VALUES ($1, $2) \
ON CONFLICT (user_id, lower(name)) DO NOTHING RETURNING id";

const LOCK_ENVIRONMENT: &str =
    "SELECT id FROM environment WHERE id = $1 AND user_id = $2 FOR UPDATE";

const SHARE_ENVIRONMENT: &str =
    "SELECT id FROM environment WHERE id = $1 AND user_id = $2 FOR SHARE";

const UPSERT_SECRET: &str = "\
INSERT INTO environment_secret (environment_id, name, ciphertext, key_id, fingerprint) \
VALUES ($1, $2, $3, $4, $5) \
ON CONFLICT (environment_id, lower(name)) DO UPDATE SET name = EXCLUDED.name, \
ciphertext = EXCLUDED.ciphertext, key_id = EXCLUDED.key_id, \
fingerprint = EXCLUDED.fingerprint, updated_at = now()";

const LOCK_JOB_LEASE: &str = "\
SELECT user_id, environment_id, environment_version FROM jobs \
WHERE job_id = $1 AND attempt = $2 AND box = $3 AND state = 'RUNNING' \
AND lease_expires_at > now() FOR SHARE";

const SHARE_OWNED_ENVIRONMENT: &str =
    "SELECT name FROM environment WHERE id = $1 AND user_id = $2 FOR SHARE";

const SHARE_RELEASE_SECRETS: &str =
    "SELECT name, ciphertext, key_id FROM environment_secret WHERE environment_id = $1 FOR SHARE";

const SELECT_SECRET: &str =
    "SELECT ciphertext, key_id FROM environment_secret WHERE environment_id = $1 AND name = $2";

/// Secrets, scripts and audit entries of one release.
type ReleaseParts = (
    Vec<JobEnvironmentSecret>,
    Vec<EnvironmentScriptSpec>,
    Vec<ReleasedSecret>,
);

/// What a submit asks of the Environment layer (ADR-0067 decision 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvRequest {
    /// The field was empty: the repository binding, then the Profile binding, then none.
    Default,
    /// The field was `-`: the submitter wants no Environment.
    Bare,
    /// The submitter named an Environment.
    Named(EnvironmentName),
}

/// The pin a Job stores: both columns or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvPin {
    /// The Environment row.
    pub environment_id: i64,
    /// The latest version at submit.
    pub version: i32,
}

/// Why a submit could not take a pin. No variant tells a foreign name from an unknown one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRefusal {
    /// The name is unknown, belongs to another user, or the Environment vanished mid-submit.
    UnknownName,
    /// The Environment has no version to pin.
    NoVersion,
    /// The latest version holds a script and the submitter does not hold `env:scripts`.
    ScriptsNotGranted,
}

/// The outcome of [`resolve_pin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinResult {
    /// The Job gets no Environment.
    None,
    /// The Job pins this Environment version.
    Pinned(EnvPin),
    /// The submit is refused and writes nothing.
    Refused(PinRefusal),
}

impl PinResult {
    /// The pin to store, or the refusal that stops the submit.
    ///
    /// # Errors
    ///
    /// Returns the [`PinRefusal`] of a refused result.
    pub const fn into_pin(self) -> Result<Option<EnvPin>, PinRefusal> {
        match self {
            Self::None => Ok(None),
            Self::Pinned(pin) => Ok(Some(pin)),
            Self::Refused(refusal) => Err(refusal),
        }
    }
}

/// Resolves the pin of a submit inside the submit transaction.
///
/// The Environment row is taken `FOR SHARE` first, the latest version is read after the lock,
/// and `env:scripts` is read `FOR SHARE` after the Environment lock when that version holds a
/// script, so a revoke in flight either lands first and refuses the submit or waits for it.
/// A secrets-only version needs no capability. [`EnvRequest::Default`] and
/// [`EnvRequest::Bare`] pin nothing and touch no row.
///
/// # Errors
///
/// Returns the [`sqlx::Error`] of a failed query.
pub async fn resolve_pin(
    tx: &mut PgConnection,
    user_id: i64,
    request: &EnvRequest,
) -> Result<PinResult, sqlx::Error> {
    let EnvRequest::Named(name) = request else {
        return Ok(PinResult::None);
    };
    let Some(environment_id) = sqlx::query_scalar::<_, i64>(RESOLVE_ENVIRONMENT)
        .bind(user_id)
        .bind(name.as_str())
        .fetch_optional(&mut *tx)
        .await?
    else {
        return Ok(PinResult::Refused(PinRefusal::UnknownName));
    };
    pin_environment(tx, user_id, environment_id).await
}

/// The repository and Profile a submit resolves default bindings for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DefaultKeys {
    /// The registered repository row of the job target, when it is registered.
    pub repo_id: Option<i64>,
    /// The Profile the job runs, when it names one.
    pub profile_id: Option<i64>,
}

/// Resolves the pin of a submit with default bindings (ADR-0067 decision 10).
///
/// An explicit name pins that Environment and [`EnvRequest::Bare`] pins none, and neither reads
/// a binding. [`EnvRequest::Default`] takes the repository binding, then the Profile binding,
/// then none. A binding whose Environment vanished is skipped. A binding to an Environment
/// without a version, or to one with scripts after `env:scripts` was revoked, refuses the
/// submit and never falls through to the next binding.
///
/// # Errors
///
/// Returns the [`sqlx::Error`] of a failed query.
pub async fn resolve_pin_with_defaults(
    tx: &mut PgConnection,
    user_id: i64,
    request: &EnvRequest,
    keys: DefaultKeys,
) -> Result<PinResult, sqlx::Error> {
    if !matches!(request, EnvRequest::Default) {
        return resolve_pin(tx, user_id, request).await;
    }
    let candidates = [
        (REPO_DEFAULT_ID, keys.repo_id),
        (PROFILE_DEFAULT_ID, keys.profile_id),
    ];
    for (sql, key) in candidates {
        let Some(key) = key else { continue };
        let Some(environment_id) = sqlx::query_scalar::<_, i64>(sql)
            .bind(user_id)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
        else {
            continue;
        };
        match pin_environment(tx, user_id, environment_id).await? {
            PinResult::Refused(PinRefusal::UnknownName) => {}
            settled => return Ok(settled),
        }
    }
    Ok(PinResult::None)
}

async fn pin_environment(
    tx: &mut PgConnection,
    user_id: i64,
    environment_id: i64,
) -> Result<PinResult, sqlx::Error> {
    if sqlx::query_scalar::<_, i64>(SHARE_ENVIRONMENT)
        .bind(environment_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
    {
        return Ok(PinResult::Refused(PinRefusal::UnknownName));
    }
    let Some((version, _)) = sqlx::query_as::<_, (i32, Vec<u8>)>(LATEST_VERSION)
        .bind(environment_id)
        .fetch_optional(&mut *tx)
        .await?
    else {
        return Ok(PinResult::Refused(PinRefusal::NoVersion));
    };
    let pin = EnvPin {
        environment_id,
        version,
    };
    if !scripts_granted(tx, user_id, pin).await? {
        return Ok(PinResult::Refused(PinRefusal::ScriptsNotGranted));
    }
    Ok(PinResult::Pinned(pin))
}

async fn scripts_granted(
    tx: &mut PgConnection,
    user_id: i64,
    pin: EnvPin,
) -> Result<bool, sqlx::Error> {
    let scripts: bool = sqlx::query_scalar(SCRIPTS_IN_VERSION)
        .bind(pin.environment_id)
        .bind(pin.version)
        .fetch_one(&mut *tx)
        .await?;
    if !scripts {
        return Ok(true);
    }
    Ok(sqlx::query_scalar::<_, i64>(SHARE_CAPABILITY)
        .bind(user_id)
        .bind(crate::cred::capability::ENV_SCRIPTS)
        .fetch_optional(&mut *tx)
        .await?
        .is_some())
}

/// Whether a pin a Job already holds can still be inherited by a CI retry.
///
/// The Environment row is taken `FOR SHARE` first, then `env:scripts` `FOR SHARE` when the
/// pinned version holds a script, the order of [`resolve_pin`]. A deleted Environment or a
/// revoked capability answers `false`. The pinned version is read, never the latest.
///
/// # Errors
///
/// Returns the [`sqlx::Error`] of a failed query.
pub async fn pin_inheritable(
    tx: &mut PgConnection,
    user_id: i64,
    pin: EnvPin,
) -> Result<bool, sqlx::Error> {
    if sqlx::query_scalar::<_, i64>(SHARE_ENVIRONMENT)
        .bind(pin.environment_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
    {
        return Ok(false);
    }
    scripts_granted(tx, user_id, pin).await
}

/// Whether the pin stored on a Job equals what `request` asks for now.
///
/// [`EnvRequest::Default`] and [`EnvRequest::Bare`] equal a Job with no pin. A named request
/// equals a Job pinned to the same Environment at the version that is latest now, so an
/// Environment edited between two submits under one key is a conflict (ADR-0067 decision 11
/// compares the name and the resolved version). An Environment that no longer exists equals
/// no pin.
///
/// # Errors
///
/// Returns the [`sqlx::Error`] of a failed query.
pub async fn pin_matches(
    conn: &mut PgConnection,
    user_id: i64,
    request: &EnvRequest,
    stored: Option<EnvPin>,
) -> Result<bool, sqlx::Error> {
    let EnvRequest::Named(name) = request else {
        return Ok(stored.is_none());
    };
    let current: Option<(i64, Option<i32>)> = sqlx::query_as(LATEST_PIN)
        .bind(user_id)
        .bind(name.as_str())
        .fetch_optional(&mut *conn)
        .await?;
    Ok(match (current, stored) {
        (Some((id, Some(version))), Some(pin)) => {
            pin.environment_id == id && pin.version == version
        }
        _ => false,
    })
}

/// What a default Environment binds to, already validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingKey {
    /// A registered repository: lowercase host and `owner/name` path.
    Repo {
        /// The forge host.
        host: String,
        /// The repository path.
        path: String,
    },
    /// A Profile name the caller can see.
    Profile(String),
}

/// Why an Environment store call failed. Messages are fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvError {
    /// The Environment or secret is unknown, or belongs to another user.
    NotFound,
    /// A default binding names a repository or Profile the user cannot see.
    KeyNotFound,
    /// The user already has an Environment of this name.
    Exists,
    /// The secret could not be sealed.
    Seal,
    /// The stored ciphertext did not authenticate for this owner, Environment and name.
    Open,
    /// The key that sealed the row is not in the key ring.
    UnknownKey,
    /// The database failed.
    Database,
    /// The user owns the most Environments allowed.
    TooManyEnvironments,
    /// The version would hold more entries than allowed.
    TooManyEntries,
    /// Script bodies plus secret values would pass the size cap.
    TooLarge,
    /// The version holds a script and the user does not hold the `env:scripts` capability.
    ScriptsNotAllowed,
    /// A release was refused: no running job holds the lease the caller named, the pin does not
    /// resolve for the job owner, or `env:scripts` is no longer granted. One variant for every
    /// cause, so no caller can tell them apart.
    Denied,
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such environment secret",
            Self::KeyNotFound => fleet_proto::ERR_ENV_KEY_NOT_FOUND,
            Self::Exists => "environment already exists",
            Self::Seal => "environment secret could not be sealed",
            Self::Open => "environment secret could not be opened",
            Self::UnknownKey => "environment secret key is unknown",
            Self::Database => "environment store database error",
            Self::TooManyEnvironments => "too many environments",
            Self::TooManyEntries => "too many environment entries",
            Self::TooLarge => "environment is too large",
            Self::ScriptsNotAllowed => "environment scripts are not granted",
            Self::Denied => fleet_proto::ERR_ENV_RELEASE_DENIED,
        })
    }
}

impl std::error::Error for EnvError {}

impl From<sqlx::Error> for EnvError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

/// Caps the store enforces. The defaults come from ADR-0067 and
/// [`MAX_ENVIRONMENTS_PER_USER`]; a test shrinks one to cross it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Environments per user.
    pub max_environments: usize,
    /// Entries per version, secrets and scripts together.
    pub max_entries: usize,
    /// Bytes of script bodies plus current secret values.
    pub max_total_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_environments: MAX_ENVIRONMENTS_PER_USER,
            max_entries: MAX_ENTRIES,
            max_total_bytes: MAX_TOTAL_BYTES,
        }
    }
}

/// An Environment as its owner sees it. It holds no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentInfo {
    /// The Environment id.
    pub id: i64,
    /// The Environment name.
    pub name: String,
    /// The newest version number, if any version exists.
    pub latest_version: Option<i32>,
}

/// The outcome of [`EnvironmentStore::save_version`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SavedVersion {
    /// The version the structure now has.
    pub version: i32,
    /// False when the structure equalled the latest version and nothing was written.
    pub created: bool,
}

/// One entry of a stored version, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredEntry {
    /// A secret slot. The value lives outside the version.
    Secret {
        /// The secret name.
        name: String,
        /// Whether the agent may see the value.
        agent_visible: bool,
        /// `file` or `env`.
        delivery: String,
    },
    /// A setup script.
    Script {
        /// The script name.
        name: String,
        /// The script text.
        body: String,
        /// `abort` or `continue`.
        on_fail: String,
        /// The timeout in seconds.
        timeout_s: i32,
    },
}

/// One stored version: its hash, egress hosts and entries in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVersion {
    /// The SHA-256 structure hash.
    pub hash: Vec<u8>,
    /// The egress hosts.
    pub egress_hosts: Vec<String>,
    /// The entries in position order.
    pub entries: Vec<StoredEntry>,
}

/// One secret a release handed to a Job, as recorded in `environment_use`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedSecret {
    /// The secret name.
    pub name: String,
    /// The fingerprint of the value released.
    pub fingerprint: String,
}

/// Inserts the `environment_use` rows of one release and returns the count.
///
/// One row per secret, or one row with an empty name and fingerprint when the Environment holds
/// no secret. Run it in the transaction that reads the values so a failed insert fails the
/// release.
///
/// # Errors
///
/// Returns [`EnvError::Database`] on a database failure.
pub async fn record_environment_use(
    conn: &mut PgConnection,
    environment_id: i64,
    version: i32,
    job_id: &str,
    released: &[ReleasedSecret],
) -> Result<u64, EnvError> {
    let none = ReleasedSecret {
        name: String::new(),
        fingerprint: String::new(),
    };
    let rows = if released.is_empty() {
        std::slice::from_ref(&none)
    } else {
        released
    };
    let mut written = 0;
    for row in rows {
        written += sqlx::query(INSERT_USE)
            .bind(environment_id)
            .bind(version)
            .bind(job_id)
            .bind(&row.name)
            .bind(&row.fingerprint)
            .execute(&mut *conn)
            .await?
            .rows_affected();
    }
    Ok(written)
}

/// Postgres store for Environments and their sealed secrets.
///
/// The `environment` row has two writers: [`EnvironmentStore::create_environment`] inserts it
/// and [`EnvironmentStore::delete_environment`] deletes it. Nothing updates it. Every write that
/// checks before it acts locks the row `FOR UPDATE` first.
pub struct EnvironmentStore {
    pool: PgPool,
    sealer: Arc<dyn Sealer>,
    limits: Limits,
    reply_cap: usize,
}

impl fmt::Debug for EnvironmentStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnvironmentStore(..)")
    }
}

impl EnvironmentStore {
    /// Builds a store over `pool` that seals with `sealer`.
    pub fn new(pool: PgPool, sealer: Arc<dyn Sealer>) -> Self {
        Self {
            pool,
            sealer,
            limits: Limits::default(),
            reply_cap: fleet_proto::MAX_JOB_ENVIRONMENT_REPLY_BYTES,
        }
    }

    /// Replaces the largest release reply, [`fleet_proto::MAX_JOB_ENVIRONMENT_REPLY_BYTES`]
    /// otherwise. A test seam.
    #[must_use]
    pub fn with_reply_cap(mut self, cap: usize) -> Self {
        self.reply_cap = cap;
        self
    }

    /// Replaces the caps.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    async fn lock_owned(
        tx: &mut PgConnection,
        user_id: i64,
        environment_id: i64,
    ) -> Result<(), EnvError> {
        sqlx::query_scalar::<_, i64>(LOCK_ENVIRONMENT)
            .bind(environment_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .map(|_| ())
            .ok_or(EnvError::NotFound)
    }

    async fn other_secrets(
        &self,
        tx: &mut PgConnection,
        user_id: i64,
        environment_id: i64,
        except: &str,
    ) -> Result<(usize, usize), EnvError> {
        let rows: Vec<(String, Vec<u8>, String)> = sqlx::query_as(OTHER_SECRETS)
            .bind(environment_id)
            .bind(except)
            .fetch_all(&mut *tx)
            .await?;
        let mut bytes = 0_usize;
        for (name, ciphertext, key_id) in &rows {
            let aad = Aad::for_environment_secret(user_id, environment_id, name);
            let opened = self
                .sealer
                .open(&aad, key_id, ciphertext)
                .map_err(|e| match e {
                    SealError::UnknownKey => EnvError::UnknownKey,
                    SealError::Open | SealError::Seal => EnvError::Open,
                })?;
            bytes = bytes.saturating_add(opened.len());
        }
        Ok((rows.len(), bytes))
    }

    /// Resolves `name` to the id of the user's Environment after case fold. A name another user
    /// owns resolves exactly as an unknown name.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] when the user owns no such Environment and
    /// [`EnvError::Database`] on a database failure.
    pub async fn resolve_environment(
        &self,
        user_id: i64,
        name: &EnvironmentName,
    ) -> Result<i64, EnvError> {
        sqlx::query_scalar(RESOLVE_ENVIRONMENT)
            .bind(user_id)
            .bind(name.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(EnvError::NotFound)
    }

    async fn share_key(
        tx: &mut PgConnection,
        user_id: i64,
        key: &BindingKey,
    ) -> Result<(bool, i64), EnvError> {
        let found = match key {
            BindingKey::Repo { host, path } => {
                sqlx::query_scalar::<_, i64>(SHARE_REPO_KEY)
                    .bind(user_id)
                    .bind(host)
                    .bind(path)
                    .fetch_optional(&mut *tx)
                    .await?
            }
            BindingKey::Profile(name) => {
                sqlx::query_scalar::<_, i64>(SHARE_PROFILE_KEY)
                    .bind(name)
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await?
            }
        };
        let id = found.ok_or(EnvError::KeyNotFound)?;
        Ok((matches!(key, BindingKey::Repo { .. }), id))
    }

    /// Binds the user's Environment as the default of `key`, replacing an earlier binding.
    ///
    /// The Environment row is taken `FOR UPDATE` first, then the key row `FOR SHARE`.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] when the user owns no such Environment,
    /// [`EnvError::KeyNotFound`] when the key names no repository or Profile the user can see and
    /// [`EnvError::Database`] on a database failure.
    pub async fn set_default(
        &self,
        user_id: i64,
        environment_id: i64,
        key: &BindingKey,
    ) -> Result<(), EnvError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owned(&mut tx, user_id, environment_id).await?;
        let (is_repo, key_id) = Self::share_key(&mut tx, user_id, key).await?;
        sqlx::query(if is_repo {
            UPSERT_REPO_DEFAULT
        } else {
            UPSERT_PROFILE_DEFAULT
        })
        .bind(user_id)
        .bind(environment_id)
        .bind(key_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Reads the name of the Environment bound to `key`, or `None` when nothing is bound.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::KeyNotFound`] when the key names no repository or Profile the user
    /// can see and [`EnvError::Database`] on a database failure.
    pub async fn get_default(
        &self,
        user_id: i64,
        key: &BindingKey,
    ) -> Result<Option<String>, EnvError> {
        let mut tx = self.pool.begin().await?;
        let (is_repo, key_id) = Self::share_key(&mut tx, user_id, key).await?;
        let name = sqlx::query_scalar(if is_repo {
            REPO_DEFAULT_NAME
        } else {
            PROFILE_DEFAULT_NAME
        })
        .bind(user_id)
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(name)
    }

    /// Removes the binding of `key`. Clearing an unbound key succeeds.
    ///
    /// The bound Environment row is taken `FOR UPDATE` before the delete.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::KeyNotFound`] when the key names no repository or Profile the user
    /// can see and [`EnvError::Database`] on a database failure.
    pub async fn clear_default(&self, user_id: i64, key: &BindingKey) -> Result<(), EnvError> {
        let mut tx = self.pool.begin().await?;
        let (is_repo, key_id) = Self::share_key(&mut tx, user_id, key).await?;
        let bound: Option<i64> = sqlx::query_scalar(if is_repo {
            REPO_DEFAULT_ID
        } else {
            PROFILE_DEFAULT_ID
        })
        .bind(user_id)
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(environment_id) = bound {
            match Self::lock_owned(&mut tx, user_id, environment_id).await {
                Ok(()) | Err(EnvError::NotFound) => {}
                Err(other) => return Err(other),
            }
            sqlx::query(if is_repo {
                DELETE_REPO_DEFAULT
            } else {
                DELETE_PROFILE_DEFAULT
            })
            .bind(user_id)
            .bind(key_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Lists the secret names of the user's Environment with the fingerprint of each value.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Database`] on a database failure.
    pub async fn list_secrets(
        &self,
        user_id: i64,
        environment_id: i64,
    ) -> Result<Vec<(String, String)>, EnvError> {
        Ok(sqlx::query_as(LIST_SECRETS)
            .bind(environment_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?)
    }

    /// Reads version `version` of the user's Environment, or `None` when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Database`] on a database failure.
    pub async fn get_version(
        &self,
        user_id: i64,
        environment_id: i64,
        version: i32,
    ) -> Result<Option<StoredVersion>, EnvError> {
        let head: Option<(Vec<u8>, Vec<String>)> = sqlx::query_as(VERSION_HEAD)
            .bind(environment_id)
            .bind(version)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some((hash, egress_hosts)) = head else {
            return Ok(None);
        };
        let rows: Vec<StoredEntryRow> = sqlx::query_as(VERSION_ENTRIES)
            .bind(environment_id)
            .bind(version)
            .fetch_all(&self.pool)
            .await?;
        let entries = rows
            .into_iter()
            .map(StoredEntry::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(StoredVersion {
            hash,
            egress_hosts,
            entries,
        }))
    }

    /// Lists the version numbers and hashes of the user's Environment, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Database`] on a database failure.
    pub async fn list_versions(
        &self,
        user_id: i64,
        environment_id: i64,
    ) -> Result<Vec<(i32, Vec<u8>)>, EnvError> {
        Ok(sqlx::query_as(LIST_VERSIONS)
            .bind(environment_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?)
    }

    /// Lists the user's Environments by name.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Database`] on a database failure.
    pub async fn list_environments(&self, user_id: i64) -> Result<Vec<EnvironmentInfo>, EnvError> {
        let rows: Vec<(i64, String, Option<i32>)> = sqlx::query_as(LIST_ENVIRONMENTS)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name, latest_version)| EnvironmentInfo {
                id,
                name,
                latest_version,
            })
            .collect())
    }

    /// Reads one Environment of the user.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] for an unknown or foreign id and [`EnvError::Database`] on
    /// a database failure.
    pub async fn get_environment(
        &self,
        user_id: i64,
        environment_id: i64,
    ) -> Result<EnvironmentInfo, EnvError> {
        let row: Option<(i64, String, Option<i32>)> = sqlx::query_as(GET_ENVIRONMENT)
            .bind(environment_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|(id, name, latest_version)| EnvironmentInfo {
            id,
            name,
            latest_version,
        })
        .ok_or(EnvError::NotFound)
    }

    /// Deletes the Environment and its secrets. Versions, entries and `environment_use` rows
    /// stay, so a pinned Job still resolves and the audit trail holds.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] for an unknown or foreign id and [`EnvError::Database`] on
    /// a database failure.
    pub async fn delete_environment(
        &self,
        user_id: i64,
        environment_id: i64,
    ) -> Result<(), EnvError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owned(&mut tx, user_id, environment_id).await?;
        sqlx::query(DELETE_ENVIRONMENT)
            .bind(environment_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes secret `name` of the Environment.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] for an unknown or foreign Environment or an unknown name
    /// and [`EnvError::Database`] on a database failure.
    pub async fn delete_secret(
        &self,
        user_id: i64,
        environment_id: i64,
        name: &EntryName,
    ) -> Result<(), EnvError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owned(&mut tx, user_id, environment_id).await?;
        let gone = sqlx::query(DELETE_SECRET)
            .bind(environment_id)
            .bind(name.as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if gone == 0 {
            return Err(EnvError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Stores `spec` as the next version unless it hashes equal to the latest one.
    ///
    /// The Environment row is locked `FOR UPDATE` first, and the latest hash is read after the
    /// lock, so two equal concurrent writes make one version. The hash covers no secret value,
    /// so a value-only secret update never reaches this call.
    ///
    /// A spec with a script entry also needs the `env:scripts` grant. The grant row is read
    /// `FOR SHARE` after the Environment lock and in the same transaction as the version write,
    /// so a revoke in flight either lands first and refuses the save or waits for it. A dedupe
    /// hit is refused too.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::ScriptsNotAllowed`] when the spec holds a script and the grant is
    /// missing, [`EnvError::NotFound`] for an unknown or foreign Environment,
    /// [`EnvError::TooManyEntries`] and [`EnvError::TooLarge`] past the caps and
    /// [`EnvError::Database`] on a database failure.
    pub async fn save_version(
        &self,
        user_id: i64,
        environment_id: i64,
        spec: &EnvironmentSpec,
    ) -> Result<SavedVersion, EnvError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owned(&mut tx, user_id, environment_id).await?;
        if spec
            .entries()
            .iter()
            .any(|entry| matches!(entry, Entry::Script(_)))
        {
            sqlx::query_scalar::<_, i64>(SHARE_CAPABILITY)
                .bind(user_id)
                .bind(crate::cred::capability::ENV_SCRIPTS)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(EnvError::ScriptsNotAllowed)?;
        }
        if spec.entries().len() > self.limits.max_entries {
            return Err(EnvError::TooManyEntries);
        }
        let (_, secret_bytes) = self
            .other_secrets(&mut tx, user_id, environment_id, "")
            .await?;
        if spec.script_bytes().saturating_add(secret_bytes) > self.limits.max_total_bytes {
            return Err(EnvError::TooLarge);
        }
        let hash = spec.version_hash();
        let latest: Option<(i32, Vec<u8>)> = sqlx::query_as(LATEST_VERSION)
            .bind(environment_id)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some((version, stored)) = &latest
            && stored.as_slice() == hash.as_bytes()
        {
            return Ok(SavedVersion {
                version: *version,
                created: false,
            });
        }
        let version = latest.map_or(1, |(v, _)| v.saturating_add(1));
        let hosts: Vec<&str> = spec.egress_hosts().iter().map(EgressHost::as_str).collect();
        sqlx::query(INSERT_VERSION)
            .bind(environment_id)
            .bind(user_id)
            .bind(version)
            .bind(hash.as_bytes().as_slice())
            .bind(&hosts)
            .execute(&mut *tx)
            .await?;
        for (index, item) in spec.entries().iter().enumerate() {
            let position = i32::try_from(index).map_err(|_| EnvError::Database)?;
            match item {
                Entry::Secret(s) => {
                    sqlx::query(INSERT_SECRET_ENTRY)
                        .bind(environment_id)
                        .bind(version)
                        .bind(position)
                        .bind(s.name().as_str())
                        .bind(s.agent_visible())
                        .bind(match s.delivery() {
                            Delivery::File => "file",
                            Delivery::Env => "env",
                        })
                        .execute(&mut *tx)
                        .await?;
                }
                Entry::Script(s) => {
                    sqlx::query(INSERT_SCRIPT_ENTRY)
                        .bind(environment_id)
                        .bind(version)
                        .bind(position)
                        .bind(s.name().as_str())
                        .bind(s.body().as_str())
                        .bind(match s.on_fail() {
                            OnFail::Abort => "abort",
                            OnFail::Continue => "continue",
                        })
                        .bind(i32::try_from(s.timeout_s()).map_err(|_| EnvError::Database)?)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }
        tx.commit().await?;
        Ok(SavedVersion {
            version,
            created: true,
        })
    }

    /// Creates an empty Environment for `user_id` and returns its id.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Exists`] when the user has an Environment of this name after case
    /// fold, [`EnvError::TooManyEnvironments`] at the cap, [`EnvError::NotFound`] for an unknown
    /// user and [`EnvError::Database`] on a database failure.
    pub async fn create_environment(
        &self,
        user_id: i64,
        name: &EnvironmentName,
    ) -> Result<i64, EnvError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query_scalar::<_, i64>(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(EnvError::NotFound)?;
        let owned: i64 = sqlx::query_scalar(COUNT_ENVIRONMENTS)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if usize::try_from(owned).unwrap_or(usize::MAX) >= self.limits.max_environments {
            return Err(EnvError::TooManyEnvironments);
        }
        let id = sqlx::query_scalar(INSERT_ENVIRONMENT)
            .bind(user_id)
            .bind(name.as_str())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(EnvError::Exists)?;
        tx.commit().await?;
        Ok(id)
    }

    /// Seals `value` under the active key and stores it as secret `name` of the Environment,
    /// replacing any earlier value. Returns the value fingerprint.
    ///
    /// The Environment row is locked `FOR UPDATE` before anything else, and sealing happens
    /// before the write, so a failed seal leaves the earlier row, if any, as it was.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] when the user does not own the Environment,
    /// [`EnvError::TooManyEntries`] and [`EnvError::TooLarge`] past the caps,
    /// [`EnvError::Seal`] when sealing fails and [`EnvError::Database`] on a database failure.
    pub async fn put_secret(
        &self,
        user_id: i64,
        environment_id: i64,
        name: &EntryName,
        value: &SecretValue,
    ) -> Result<String, EnvError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_owned(&mut tx, user_id, environment_id).await?;
        let (others, other_bytes) = self
            .other_secrets(&mut tx, user_id, environment_id, name.as_str())
            .await?;
        let (scripts, script_bytes): (i64, i64) = sqlx::query_as(LATEST_SCRIPTS)
            .bind(environment_id)
            .fetch_one(&mut *tx)
            .await?;
        let scripts = usize::try_from(scripts).unwrap_or(usize::MAX);
        let script_bytes = usize::try_from(script_bytes).unwrap_or(usize::MAX);
        if others.saturating_add(scripts).saturating_add(1) > self.limits.max_entries {
            return Err(EnvError::TooManyEntries);
        }
        let total = other_bytes
            .saturating_add(script_bytes)
            .saturating_add(value.len());
        if total > self.limits.max_total_bytes {
            return Err(EnvError::TooLarge);
        }
        let aad = Aad::for_environment_secret(user_id, environment_id, name.as_str());
        let sealed = self.sealer.seal(&aad, value.expose()).map_err(|_| {
            tracing::warn!(environment_id, "environment secret seal failed");
            EnvError::Seal
        })?;
        let fp = fingerprint(&Secret::new(
            String::from_utf8(value.expose().to_vec()).map_err(|_| EnvError::Seal)?,
        ));
        sqlx::query(UPSERT_SECRET)
            .bind(environment_id)
            .bind(name.as_str())
            .bind(&sealed.ciphertext)
            .bind(&sealed.key_id)
            .bind(&fp)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(fp)
    }

    /// Releases the Environment pinned by the job to the box that holds its lease.
    ///
    /// One transaction takes the job row `FOR SHARE` first, so the lease guards (box, attempt,
    /// `RUNNING`, unexpired) are evaluated against the locked row and a reaper or cancel cannot
    /// slip between check and release. The Environment and its secret rows are then taken
    /// `FOR SHARE`, `env:scripts` is read `FOR SHARE` when the pinned version holds a script,
    /// every value is opened, and the `environment_use` rows are written before commit. A job
    /// with no pin gets an empty reply and writes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Denied`] for a wrong box, wrong attempt, a job that is not running,
    /// an expired lease, an unknown job, a pin that does not resolve for the job owner, a secret
    /// the pinned version names that no longer exists and a revoked `env:scripts`.
    /// Returns [`EnvError::TooLarge`] when the reply would pass the reply cap,
    /// [`EnvError::Open`] and [`EnvError::UnknownKey`] when a value cannot be opened and
    /// [`EnvError::Database`] on a database failure, which includes a failed audit insert. No use
    /// row is written on any error.
    pub async fn release_for_job(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<GetJobEnvironmentReply, EnvError> {
        let attempt = i32::try_from(attempt).map_err(|_| EnvError::Denied)?;
        let mut tx = self.pool.begin().await?;
        let lease: Option<(i64, Option<i64>, Option<i32>)> = sqlx::query_as(LOCK_JOB_LEASE)
            .bind(job_id)
            .bind(attempt)
            .bind(box_name)
            .fetch_optional(&mut *tx)
            .await?;
        let (user_id, Some(environment_id), Some(version)) = lease.ok_or(EnvError::Denied)? else {
            return Ok(GetJobEnvironmentReply::default());
        };
        let (name,): (String,) = sqlx::query_as(SHARE_OWNED_ENVIRONMENT)
            .bind(environment_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(EnvError::Denied)?;
        let head: (Vec<u8>, Vec<String>) = sqlx::query_as(VERSION_HEAD)
            .bind(environment_id)
            .bind(version)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(EnvError::Denied)?;
        let rows: Vec<StoredEntryRow> = sqlx::query_as(VERSION_ENTRIES)
            .bind(environment_id)
            .bind(version)
            .fetch_all(&mut *tx)
            .await?;
        let entries = rows
            .into_iter()
            .map(StoredEntry::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if entries
            .iter()
            .any(|entry| matches!(entry, StoredEntry::Script { .. }))
        {
            sqlx::query_scalar::<_, i64>(SHARE_CAPABILITY)
                .bind(user_id)
                .bind(crate::cred::capability::ENV_SCRIPTS)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(EnvError::Denied)?;
        }
        let sealed: Vec<(String, Vec<u8>, String)> = sqlx::query_as(SHARE_RELEASE_SECRETS)
            .bind(environment_id)
            .fetch_all(&mut *tx)
            .await?;
        let (secrets, scripts, released) =
            self.open_entries(user_id, environment_id, entries, &sealed)?;
        let reply = GetJobEnvironmentReply {
            environment: name,
            version: u32::try_from(version).map_err(|_| EnvError::Database)?,
            hash: hex(&head.0),
            secrets,
            scripts,
            egress_hosts: head.1,
        };
        if reply.encoded_len() > self.reply_cap {
            return Err(EnvError::TooLarge);
        }
        record_environment_use(&mut tx, environment_id, version, job_id, &released).await?;
        tx.commit().await?;
        Ok(reply)
    }

    /// Opens every secret the pinned version names and maps its scripts, in stored order.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Denied`] when a named secret has no stored row, and
    /// [`EnvError::Open`] or [`EnvError::UnknownKey`] when a value cannot be opened.
    fn open_entries(
        &self,
        user_id: i64,
        environment_id: i64,
        entries: Vec<StoredEntry>,
        sealed: &[(String, Vec<u8>, String)],
    ) -> Result<ReleaseParts, EnvError> {
        let mut secrets = Vec::new();
        let mut scripts = Vec::new();
        let mut released = Vec::new();
        for entry in entries {
            match entry {
                StoredEntry::Secret {
                    name,
                    agent_visible,
                    delivery,
                } => {
                    let (row_name, ciphertext, key_id) = sealed
                        .iter()
                        .find(|(stored, _, _)| stored.eq_ignore_ascii_case(&name))
                        .ok_or(EnvError::Denied)?;
                    let aad = Aad::for_environment_secret(user_id, environment_id, row_name);
                    let opened =
                        self.sealer
                            .open(&aad, key_id, ciphertext)
                            .map_err(|e| match e {
                                SealError::UnknownKey => EnvError::UnknownKey,
                                SealError::Open | SealError::Seal => EnvError::Open,
                            })?;
                    let value = String::from_utf8(opened.to_vec()).map_err(|_| EnvError::Open)?;
                    released.push(ReleasedSecret {
                        name: name.clone(),
                        fingerprint: fingerprint(&Secret::new(value.clone())),
                    });
                    secrets.push(JobEnvironmentSecret {
                        name,
                        value,
                        agent_visible,
                        delivery: delivery_wire(&delivery).into(),
                    });
                }
                StoredEntry::Script {
                    name,
                    body,
                    on_fail,
                    timeout_s,
                } => scripts.push(EnvironmentScriptSpec {
                    name,
                    body,
                    on_fail: on_fail_wire(&on_fail).into(),
                    timeout_s: u32::try_from(timeout_s).ok(),
                }),
            }
        }
        Ok((secrets, scripts, released))
    }

    /// Opens secret `name` of the Environment for its owner.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] for an unknown or foreign Environment or an unknown name,
    /// [`EnvError::Open`] when authentication fails, [`EnvError::UnknownKey`] when the sealing
    /// key left the ring and [`EnvError::Database`] on a database failure.
    pub async fn open_secret(
        &self,
        user_id: i64,
        environment_id: i64,
        name: &EntryName,
    ) -> Result<Zeroizing<Vec<u8>>, EnvError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query_scalar::<_, i64>(SHARE_ENVIRONMENT)
            .bind(environment_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(EnvError::NotFound)?;
        let (ciphertext, key_id): (Vec<u8>, String) = sqlx::query_as(SELECT_SECRET)
            .bind(environment_id)
            .bind(name.as_str())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(EnvError::NotFound)?;
        tx.commit().await?;
        let aad = Aad::for_environment_secret(user_id, environment_id, name.as_str());
        self.sealer
            .open(&aad, &key_id, &ciphertext)
            .map_err(|e| match e {
                SealError::UnknownKey => EnvError::UnknownKey,
                SealError::Open | SealError::Seal => EnvError::Open,
            })
    }
}

type StoredEntryRow = (
    String,
    String,
    Option<bool>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i32>,
);

impl TryFrom<StoredEntryRow> for StoredEntry {
    type Error = EnvError;

    fn try_from(row: StoredEntryRow) -> Result<Self, EnvError> {
        match row {
            (name, kind, Some(agent_visible), Some(delivery), None, None, None)
                if kind == "secret" =>
            {
                Ok(Self::Secret {
                    name,
                    agent_visible,
                    delivery,
                })
            }
            (name, kind, None, None, Some(body), Some(on_fail), Some(timeout_s))
                if kind == "script" =>
            {
                Ok(Self::Script {
                    name,
                    body,
                    on_fail,
                    timeout_s,
                })
            }
            _ => Err(EnvError::Database),
        }
    }
}

use fleet_proto::v1::environment_binding_key as binding_key;
use fleet_proto::v1::environment_entry_spec::Kind;
use fleet_proto::v1::{
    ClearEnvironmentDefaultReply, ClearEnvironmentDefaultRequest, CreateEnvironmentRequest,
    DeleteEnvironmentReply, DeleteEnvironmentRequest, DeleteEnvironmentSecretReply,
    DeleteEnvironmentSecretRequest, EnvironmentBindingKey, EnvironmentDelivery, EnvironmentDetail,
    EnvironmentEntrySpec, EnvironmentInfo as ProtoInfo, EnvironmentOnFail, EnvironmentScriptSpec,
    EnvironmentSecretInfo, EnvironmentSecretSpec, EnvironmentVersion, EnvironmentVersionInfo,
    GetEnvironmentDefaultReply, GetEnvironmentDefaultRequest, GetEnvironmentRequest,
    GetEnvironmentVersionRequest, GetJobEnvironmentReply, JobEnvironmentSecret,
    ListEnvironmentVersionsReply, ListEnvironmentVersionsRequest, ListEnvironmentsReply,
    PutEnvironmentSecretReply, PutEnvironmentSecretRequest, SaveEnvironmentVersionReply,
    SaveEnvironmentVersionRequest, SetEnvironmentDefaultReply, SetEnvironmentDefaultRequest,
};
use tonic::Status;
use tonic_prost::prost::Message;

fn invalid(err: EnvironmentError) -> Status {
    Status::invalid_argument(err.to_string())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn number(value: i32) -> Result<u32, Status> {
    u32::try_from(value).map_err(|_| Status::internal(fleet_proto::ERR_ENV_INTERNAL))
}

fn store_status(err: EnvError) -> Status {
    match err {
        EnvError::NotFound => Status::not_found(fleet_proto::ERR_ENV_NOT_FOUND),
        EnvError::KeyNotFound => Status::not_found(fleet_proto::ERR_ENV_KEY_NOT_FOUND),
        EnvError::Exists => Status::already_exists(fleet_proto::ERR_ENV_EXISTS),
        EnvError::TooManyEnvironments | EnvError::TooManyEntries | EnvError::TooLarge => {
            Status::resource_exhausted(fleet_proto::ERR_ENV_LIMIT)
        }
        EnvError::ScriptsNotAllowed => {
            Status::permission_denied(fleet_proto::ERR_ENV_SCRIPTS_NOT_GRANTED)
        }
        EnvError::Denied => Status::permission_denied(fleet_proto::ERR_ENV_RELEASE_DENIED),
        EnvError::Seal | EnvError::Open | EnvError::UnknownKey | EnvError::Database => {
            tracing::warn!(reason = %err, "environment store call failed");
            Status::internal(fleet_proto::ERR_ENV_INTERNAL)
        }
    }
}

fn delivery_of(raw: i32) -> Result<Delivery, Status> {
    match EnvironmentDelivery::try_from(raw) {
        Ok(EnvironmentDelivery::Unspecified | EnvironmentDelivery::File) => Ok(Delivery::File),
        Ok(EnvironmentDelivery::Env) => Ok(Delivery::Env),
        Err(_) => Err(Status::invalid_argument(REASON_ENUM)),
    }
}

fn on_fail_of(raw: i32) -> Result<OnFail, Status> {
    match EnvironmentOnFail::try_from(raw) {
        Ok(EnvironmentOnFail::Unspecified | EnvironmentOnFail::Abort) => Ok(OnFail::Abort),
        Ok(EnvironmentOnFail::Continue) => Ok(OnFail::Continue),
        Err(_) => Err(Status::invalid_argument(REASON_ENUM)),
    }
}

fn entry_of(item: &EnvironmentEntrySpec) -> Result<Entry, Status> {
    match &item.kind {
        None => Err(Status::invalid_argument(REASON_ENTRY_KIND)),
        Some(Kind::Secret(s)) => {
            let name = EntryName::new(&s.name).map_err(invalid)?;
            SecretSpec::new(name, s.agent_visible, delivery_of(s.delivery)?)
                .map(Entry::Secret)
                .map_err(invalid)
        }
        Some(Kind::Script(s)) => {
            let name = EntryName::new(&s.name).map_err(invalid)?;
            let body = ScriptBody::new(&s.body).map_err(invalid)?;
            ScriptSpec::new(
                name,
                body,
                on_fail_of(s.on_fail)?,
                s.timeout_s.unwrap_or(DEFAULT_TIMEOUT_S),
            )
            .map(Entry::Script)
            .map_err(invalid)
        }
    }
}

fn spec_of(
    entries: &[EnvironmentEntrySpec],
    egress_hosts: &[String],
) -> Result<EnvironmentSpec, Status> {
    let entries = entries
        .iter()
        .map(entry_of)
        .collect::<Result<Vec<_>, _>>()?;
    let hosts = egress_hosts
        .iter()
        .map(|h| EgressHost::new(h))
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    EnvironmentSpec::new(entries, hosts).map_err(invalid)
}

fn env_name_of(raw: &str) -> Result<EnvironmentName, Status> {
    EnvironmentName::new(raw).map_err(invalid)
}

const MAX_REPO_HOST_BYTES: usize = 253;
const MAX_REPO_PATH_BYTES: usize = 141;

fn binding_key_of(key: Option<&EnvironmentBindingKey>) -> Result<BindingKey, Status> {
    let bad = || Status::invalid_argument(fleet_proto::ERR_ENV_KEY_INVALID);
    match key.and_then(|k| k.key.as_ref()).ok_or_else(bad)? {
        binding_key::Key::Repo(repo) => {
            let host = repo.host.to_ascii_lowercase();
            let path = repo.path.to_ascii_lowercase();
            let host_ok = !host.is_empty()
                && host.len() <= MAX_REPO_HOST_BYTES
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
            let path_ok = !path.is_empty()
                && path.len() <= MAX_REPO_PATH_BYTES
                && path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
            if host_ok && path_ok {
                Ok(BindingKey::Repo { host, path })
            } else {
                Err(bad())
            }
        }
        binding_key::Key::Profile(name) => {
            crate::profiles::validate_name(name).map_err(|_| bad())?;
            Ok(BindingKey::Profile(name.clone()))
        }
    }
}

fn entry_name_of(raw: &str) -> Result<EntryName, Status> {
    EntryName::new(raw).map_err(invalid)
}

fn delivery_wire(raw: &str) -> EnvironmentDelivery {
    if raw == "env" {
        EnvironmentDelivery::Env
    } else {
        EnvironmentDelivery::File
    }
}

fn on_fail_wire(raw: &str) -> EnvironmentOnFail {
    if raw == "continue" {
        EnvironmentOnFail::Continue
    } else {
        EnvironmentOnFail::Abort
    }
}

fn detail_of(stored: StoredVersion, version: u32) -> EnvironmentVersion {
    let entries = stored
        .entries
        .into_iter()
        .map(|entry| EnvironmentEntrySpec {
            kind: Some(match entry {
                StoredEntry::Secret {
                    name,
                    agent_visible,
                    delivery,
                } => Kind::Secret(EnvironmentSecretSpec {
                    name,
                    agent_visible,
                    delivery: delivery_wire(&delivery).into(),
                }),
                StoredEntry::Script {
                    name,
                    body,
                    on_fail,
                    timeout_s,
                } => Kind::Script(EnvironmentScriptSpec {
                    name,
                    body,
                    on_fail: on_fail_wire(&on_fail).into(),
                    timeout_s: u32::try_from(timeout_s).ok(),
                }),
            }),
        })
        .collect();
    EnvironmentVersion {
        version,
        hash: hex(&stored.hash),
        entries,
        egress_hosts: stored.egress_hosts,
    }
}

/// The `FleetEnvironments` handlers.
///
/// Every method takes the caller's user id. Inputs are parsed into the core types before any
/// lookup, so a malformed request answers the same for a foreign and an unknown name, and a
/// name that does not resolve to one of the caller's Environments answers
/// [`fleet_proto::ERR_ENV_NOT_FOUND`] whoever owns it.
#[derive(Clone)]
pub struct EnvironmentService {
    store: Arc<EnvironmentStore>,
}

impl fmt::Debug for EnvironmentService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnvironmentService(..)")
    }
}

impl EnvironmentService {
    /// Builds the handlers over `store`.
    pub fn new(store: EnvironmentStore) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    async fn resolve(&self, user_id: i64, name: &EnvironmentName) -> Result<i64, Status> {
        self.store
            .resolve_environment(user_id, name)
            .await
            .map_err(store_status)
    }

    /// Binds an Environment as the default of a repository or Profile.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name or key, `NOT_FOUND` for an unknown or foreign
    /// Environment, repository or Profile and `INTERNAL` for a store failure.
    pub async fn set_default(
        &self,
        user_id: i64,
        request: &SetEnvironmentDefaultRequest,
    ) -> Result<SetEnvironmentDefaultReply, Status> {
        let name = env_name_of(&request.environment)?;
        let key = binding_key_of(request.key.as_ref())?;
        let id = self.resolve(user_id, &name).await?;
        self.store
            .set_default(user_id, id, &key)
            .await
            .map_err(store_status)?;
        Ok(SetEnvironmentDefaultReply {})
    }

    /// Reads the default Environment of a repository or Profile.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad key, `NOT_FOUND` for an unknown or foreign
    /// repository or Profile and `INTERNAL` for a store failure.
    pub async fn get_default(
        &self,
        user_id: i64,
        request: &GetEnvironmentDefaultRequest,
    ) -> Result<GetEnvironmentDefaultReply, Status> {
        let key = binding_key_of(request.key.as_ref())?;
        let environment = self
            .store
            .get_default(user_id, &key)
            .await
            .map_err(store_status)?;
        Ok(GetEnvironmentDefaultReply { environment })
    }

    /// Clears the default Environment of a repository or Profile.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad key, `NOT_FOUND` for an unknown or foreign
    /// repository or Profile and `INTERNAL` for a store failure.
    pub async fn clear_default(
        &self,
        user_id: i64,
        request: &ClearEnvironmentDefaultRequest,
    ) -> Result<ClearEnvironmentDefaultReply, Status> {
        let key = binding_key_of(request.key.as_ref())?;
        self.store
            .clear_default(user_id, &key)
            .await
            .map_err(store_status)?;
        Ok(ClearEnvironmentDefaultReply {})
    }

    /// Releases the Environment pinned by a running job to the box that holds its lease.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` with one fixed message for every lease or capability refusal,
    /// `RESOURCE_EXHAUSTED` when the reply passes the cap and `INTERNAL` otherwise.
    pub async fn job_environment(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<GetJobEnvironmentReply, Status> {
        self.store
            .release_for_job(job_id, attempt, box_name)
            .await
            .map_err(store_status)
    }

    /// Creates an Environment.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name, `ALREADY_EXISTS`, `RESOURCE_EXHAUSTED` at the
    /// cap and `INTERNAL` for a store failure.
    pub async fn create(
        &self,
        user_id: i64,
        request: &CreateEnvironmentRequest,
    ) -> Result<ProtoInfo, Status> {
        let name = env_name_of(&request.name)?;
        self.store
            .create_environment(user_id, &name)
            .await
            .map_err(store_status)?;
        Ok(ProtoInfo {
            name: name.as_str().to_owned(),
            latest_version: None,
        })
    }

    /// Lists the caller's Environments.
    ///
    /// # Errors
    ///
    /// Returns `INTERNAL` for a store failure.
    pub async fn list(&self, user_id: i64) -> Result<ListEnvironmentsReply, Status> {
        let rows = self
            .store
            .list_environments(user_id)
            .await
            .map_err(store_status)?;
        let environments = rows
            .into_iter()
            .map(|row| {
                Ok(ProtoInfo {
                    name: row.name,
                    latest_version: row.latest_version.map(number).transpose()?,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        Ok(ListEnvironmentsReply { environments })
    }

    /// Reads one Environment: secret names with fingerprints and the latest version.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name, `NOT_FOUND` and `INTERNAL`.
    pub async fn get(
        &self,
        user_id: i64,
        request: &GetEnvironmentRequest,
    ) -> Result<EnvironmentDetail, Status> {
        let name = env_name_of(&request.name)?;
        let id = self.resolve(user_id, &name).await?;
        let info = self
            .store
            .get_environment(user_id, id)
            .await
            .map_err(store_status)?;
        let secrets = self
            .store
            .list_secrets(user_id, id)
            .await
            .map_err(store_status)?
            .into_iter()
            .map(|(name, fingerprint)| EnvironmentSecretInfo { name, fingerprint })
            .collect();
        let latest = match info.latest_version {
            Some(version) => self
                .store
                .get_version(user_id, id, version)
                .await
                .map_err(store_status)?
                .map(|stored| number(version).map(|n| detail_of(stored, n)))
                .transpose()?,
            None => None,
        };
        Ok(EnvironmentDetail {
            environment: Some(ProtoInfo {
                name: info.name,
                latest_version: info.latest_version.map(number).transpose()?,
            }),
            secrets,
            latest,
        })
    }

    /// Deletes one Environment.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name, `NOT_FOUND` and `INTERNAL`.
    pub async fn delete(
        &self,
        user_id: i64,
        request: &DeleteEnvironmentRequest,
    ) -> Result<DeleteEnvironmentReply, Status> {
        let name = env_name_of(&request.name)?;
        let id = self.resolve(user_id, &name).await?;
        self.store
            .delete_environment(user_id, id)
            .await
            .map_err(store_status)?;
        Ok(DeleteEnvironmentReply {})
    }

    /// Stores a secret value and returns its fingerprint.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name or value, `NOT_FOUND`, `RESOURCE_EXHAUSTED` past
    /// a cap and `INTERNAL`. No error text carries the value.
    pub async fn put_secret(
        &self,
        user_id: i64,
        request: &PutEnvironmentSecretRequest,
    ) -> Result<PutEnvironmentSecretReply, Status> {
        let environment = env_name_of(&request.environment)?;
        let name = entry_name_of(&request.name)?;
        let value = SecretValue::new(request.value.clone()).map_err(invalid)?;
        let id = self.resolve(user_id, &environment).await?;
        let fingerprint = self
            .store
            .put_secret(user_id, id, &name, &value)
            .await
            .map_err(store_status)?;
        tracing::debug!(environment_id = id, "environment secret stored");
        Ok(PutEnvironmentSecretReply { fingerprint })
    }

    /// Deletes a secret value.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name, `NOT_FOUND` for an unknown Environment or
    /// secret and `INTERNAL`.
    pub async fn delete_secret(
        &self,
        user_id: i64,
        request: &DeleteEnvironmentSecretRequest,
    ) -> Result<DeleteEnvironmentSecretReply, Status> {
        let environment = env_name_of(&request.environment)?;
        let name = entry_name_of(&request.name)?;
        let id = self.resolve(user_id, &environment).await?;
        self.store
            .delete_secret(user_id, id, &name)
            .await
            .map_err(|e| match e {
                EnvError::NotFound => Status::not_found(fleet_proto::ERR_ENV_SECRET_NOT_FOUND),
                other => store_status(other),
            })?;
        Ok(DeleteEnvironmentSecretReply {})
    }

    /// Saves a version of the whole structure.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad spec, `NOT_FOUND`, `PERMISSION_DENIED` for a script
    /// without the `env:scripts` grant, `RESOURCE_EXHAUSTED` past a cap and `INTERNAL`.
    pub async fn save_version(
        &self,
        user_id: i64,
        request: &SaveEnvironmentVersionRequest,
    ) -> Result<SaveEnvironmentVersionReply, Status> {
        let environment = env_name_of(&request.environment)?;
        let spec = spec_of(&request.entries, &request.egress_hosts)?;
        let id = self.resolve(user_id, &environment).await?;
        let saved = self
            .store
            .save_version(user_id, id, &spec)
            .await
            .map_err(store_status)?;
        Ok(SaveEnvironmentVersionReply {
            version: number(saved.version)?,
            created: saved.created,
        })
    }

    /// Reads a version.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name or version zero, `NOT_FOUND` and `INTERNAL`.
    pub async fn get_version(
        &self,
        user_id: i64,
        request: &GetEnvironmentVersionRequest,
    ) -> Result<EnvironmentVersion, Status> {
        let environment = env_name_of(&request.environment)?;
        if request.version == 0 {
            return Err(Status::invalid_argument(REASON_VERSION_REQUIRED));
        }
        let id = self.resolve(user_id, &environment).await?;
        let version = i32::try_from(request.version)
            .map_err(|_| Status::not_found(fleet_proto::ERR_ENV_VERSION_NOT_FOUND))?;
        let stored = self
            .store
            .get_version(user_id, id, version)
            .await
            .map_err(store_status)?
            .ok_or_else(|| Status::not_found(fleet_proto::ERR_ENV_VERSION_NOT_FOUND))?;
        Ok(detail_of(stored, request.version))
    }

    /// Lists versions, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a bad name, `NOT_FOUND` and `INTERNAL`.
    pub async fn list_versions(
        &self,
        user_id: i64,
        request: &ListEnvironmentVersionsRequest,
    ) -> Result<ListEnvironmentVersionsReply, Status> {
        let environment = env_name_of(&request.environment)?;
        let id = self.resolve(user_id, &environment).await?;
        let versions = self
            .store
            .list_versions(user_id, id)
            .await
            .map_err(store_status)?
            .into_iter()
            .map(|(version, hash)| {
                Ok(EnvironmentVersionInfo {
                    version: number(version)?,
                    hash: hex(&hash),
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        Ok(ListEnvironmentVersionsReply { versions })
    }
}

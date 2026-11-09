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
    Delivery, Entry, EntryName, EnvironmentName, EnvironmentSpec, MAX_ENTRIES, MAX_TOTAL_BYTES,
    OnFail, SecretValue,
};
use sqlx::{PgConnection, PgPool};
use zeroize::Zeroizing;

use crate::cred::seal::{Aad, SealError, Sealer};

/// Environments one user may own. ADR-0067 states no number, so this is the chosen cap.
pub const MAX_ENVIRONMENTS_PER_USER: usize = 64;

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

const SELECT_SECRET: &str =
    "SELECT ciphertext, key_id FROM environment_secret WHERE environment_id = $1 AND name = $2";

/// Why an Environment store call failed. Messages are fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvError {
    /// The Environment or secret is unknown, or belongs to another user.
    NotFound,
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
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such environment secret",
            Self::Exists => "environment already exists",
            Self::Seal => "environment secret could not be sealed",
            Self::Open => "environment secret could not be opened",
            Self::UnknownKey => "environment secret key is unknown",
            Self::Database => "environment store database error",
            Self::TooManyEnvironments => "too many environments",
            Self::TooManyEntries => "too many environment entries",
            Self::TooLarge => "environment is too large",
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
        }
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
    /// # Errors
    ///
    /// Returns [`EnvError::NotFound`] for an unknown or foreign Environment,
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
        let hosts: Vec<&str> = spec
            .egress_hosts()
            .iter()
            .map(fleet_core::environment::EgressHost::as_str)
            .collect();
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

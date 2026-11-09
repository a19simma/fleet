//! Environment storage and secret sealing (ADR-0067).
//!
//! Secrets are sealed with the credential [`Sealer`] and key ring. The associated data binds the
//! user, the Environment id and the secret name ([`Aad::for_environment_secret`]), so a row moved
//! to another owner, Environment or name does not open, and a credential ciphertext never opens
//! here. No error, `Debug` output or log line carries a secret value.

use std::fmt;
use std::sync::Arc;

use fleet_core::credential::{Secret, fingerprint};
use fleet_core::environment::{EntryName, EnvironmentName, SecretValue};
use sqlx::PgPool;
use zeroize::Zeroizing;

use crate::cred::seal::{Aad, SealError, Sealer};

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
        })
    }
}

impl std::error::Error for EnvError {}

impl From<sqlx::Error> for EnvError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

/// Postgres store for Environments and their sealed secrets.
pub struct EnvironmentStore {
    pool: PgPool,
    sealer: Arc<dyn Sealer>,
}

impl fmt::Debug for EnvironmentStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnvironmentStore(..)")
    }
}

impl EnvironmentStore {
    /// Builds a store over `pool` that seals with `sealer`.
    pub fn new(pool: PgPool, sealer: Arc<dyn Sealer>) -> Self {
        Self { pool, sealer }
    }

    /// Creates an empty Environment for `user_id` and returns its id.
    ///
    /// # Errors
    ///
    /// Returns [`EnvError::Exists`] when the user has an Environment of this name after case
    /// fold and [`EnvError::Database`] on a database failure.
    pub async fn create_environment(
        &self,
        user_id: i64,
        name: &EnvironmentName,
    ) -> Result<i64, EnvError> {
        sqlx::query_scalar(INSERT_ENVIRONMENT)
            .bind(user_id)
            .bind(name.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(EnvError::Exists)
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
    /// [`EnvError::Seal`] when sealing fails and [`EnvError::Database`] on a database failure.
    pub async fn put_secret(
        &self,
        user_id: i64,
        environment_id: i64,
        name: &EntryName,
        value: &SecretValue,
    ) -> Result<String, EnvError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query_scalar::<_, i64>(LOCK_ENVIRONMENT)
            .bind(environment_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(EnvError::NotFound)?;
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

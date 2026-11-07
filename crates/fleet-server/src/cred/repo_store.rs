//! The user repository registry table (ADR-0059).
//!
//! Every read and write is keyed by the authenticated user in the SQL `WHERE`, so a missing row
//! and another user's row are the same answer. An insert takes `FOR UPDATE` on the user row to
//! serialise the row cap, and `FOR SHARE` on the credential the check used.

use std::fmt;

use fleet_core::credential::CredentialKind;
use sqlx::{PgPool, Row};

use super::repo_verify::RepoCredential;
use super::store::{CredentialStore, StoreError};

const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR UPDATE";

const RECHECK_CREDENTIAL: &str =
    "SELECT id FROM credentials WHERE id = $1 AND user_id = $2 AND tombstoned_at IS NULL FOR SHARE";

const EXISTS: &str =
    "SELECT EXISTS (SELECT 1 FROM user_repos WHERE user_id = $1 AND host = $2 AND path = $3)";

const COUNT: &str = "SELECT count(*) FROM user_repos WHERE user_id = $1";

const UPSERT: &str = "\
INSERT INTO user_repos (user_id, host, path, forge_kind, push) VALUES ($1, $2, $3, $4, $5) \
ON CONFLICT (user_id, host, path) DO UPDATE SET forge_kind = EXCLUDED.forge_kind, \
push = EXCLUDED.push, verified_at = now() \
RETURNING (EXTRACT(EPOCH FROM verified_at) * 1000)::bigint AS verified_ms";

const LIST: &str = "\
SELECT host, path, forge_kind, push, (EXTRACT(EPOCH FROM verified_at) * 1000)::bigint AS verified_ms \
FROM user_repos WHERE user_id = $1 ORDER BY host, path";

const DELETE: &str = "DELETE FROM user_repos WHERE user_id = $1 AND host = $2 AND path = $3";

/// One registered repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRow {
    /// The lowercase forge host.
    pub host: String,
    /// The lowercase `owner/name`.
    pub path: String,
    /// The forge kind name, `github` or `forgejo`.
    pub forge_kind: String,
    /// Whether the forge reported push permission, or `None` when it did not.
    pub push: Option<bool>,
    /// When the repository was last verified, in milliseconds since the Unix epoch.
    pub verified_at_ms: i64,
}

/// A repository to register.
#[derive(Debug, Clone, Copy)]
pub struct NewRepo<'a> {
    /// The lowercase forge host.
    pub host: &'a str,
    /// The lowercase `owner/name`.
    pub path: &'a str,
    /// The forge kind name.
    pub forge_kind: &'a str,
    /// Push permission as the forge reported it.
    pub push: Option<bool>,
    /// The credential the check used.
    pub credential_id: i64,
}

/// Why a registry operation failed. The text is fixed.
#[derive(Debug)]
pub enum RepoStoreError {
    /// The credential the check used is gone or tombstoned, or the user no longer exists.
    CredentialGone,
    /// The user holds the most repositories allowed.
    TooMany,
    /// No such row for this user.
    NotFound,
    /// The credential store failed.
    Credential(StoreError),
    /// The database failed.
    Db(sqlx::Error),
}

impl fmt::Display for RepoStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialGone => f.write_str(fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL),
            Self::TooMany => f.write_str(fleet_proto::ERR_REPO_LIMIT),
            Self::NotFound => f.write_str(fleet_proto::ERR_REPO_NOT_FOUND),
            Self::Credential(err) => err.fmt(f),
            Self::Db(_) => f.write_str("repository store database error"),
        }
    }
}

impl std::error::Error for RepoStoreError {}

impl From<sqlx::Error> for RepoStoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Db(err)
    }
}

/// The registry table plus the credential lookup a check needs.
#[derive(Clone)]
pub struct RepoStore {
    pool: PgPool,
    credentials: CredentialStore,
    max_repos: usize,
}

impl fmt::Debug for RepoStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RepoStore(..)")
    }
}

impl RepoStore {
    /// A store over `pool` and `credentials`, capped at [`fleet_proto::MAX_REPOS_PER_USER`].
    pub fn new(pool: PgPool, credentials: CredentialStore) -> Self {
        Self {
            pool,
            credentials,
            max_repos: fleet_proto::MAX_REPOS_PER_USER,
        }
    }

    /// Replaces the per-user row cap. Tests shrink it.
    #[must_use]
    pub fn with_max_repos(mut self, max_repos: usize) -> Self {
        self.max_repos = max_repos;
        self
    }

    /// The user's GitHub credential and its row id: the `github_app` installation when the user
    /// holds one, else the `github_pat`, with no fallback from one to the other.
    ///
    /// # Errors
    ///
    /// Returns [`RepoStoreError::Credential`] when the value cannot be opened or storage fails.
    pub async fn github_credential(
        &self,
        user_id: i64,
    ) -> Result<Option<(i64, RepoCredential)>, RepoStoreError> {
        let held = self
            .credentials
            .list(user_id)
            .await
            .map_err(RepoStoreError::Credential)?;
        let pick = |kind| held.iter().find(|c| c.kind == kind).map(|c| c.id);
        let Some((id, kind)) = pick(CredentialKind::GithubApp)
            .map(|id| (id, CredentialKind::GithubApp))
            .or_else(|| pick(CredentialKind::GithubPat).map(|id| (id, CredentialKind::GithubPat)))
        else {
            return Ok(None);
        };
        let (_, secret) = match self.credentials.open_for_verify(user_id, id).await {
            Ok(opened) => opened,
            Err(StoreError::NotFound) => return Ok(None),
            Err(err) => return Err(RepoStoreError::Credential(err)),
        };
        let credential = if kind == CredentialKind::GithubApp {
            RepoCredential::App {
                user_id,
                credential_id: id,
                installation: secret,
            }
        } else {
            RepoCredential::Pat(secret)
        };
        Ok(Some((id, credential)))
    }

    /// Registers `repo` for `user_id`, or refreshes `push` and `verified_at` of an existing row.
    ///
    /// # Errors
    ///
    /// Returns [`RepoStoreError::CredentialGone`] when the credential the check used was deleted
    /// after the check, [`RepoStoreError::TooMany`] when a new row would pass the cap, and
    /// [`RepoStoreError::Db`] for a database failure. Nothing is written on any error.
    pub async fn insert(&self, user_id: i64, repo: &NewRepo<'_>) -> Result<i64, RepoStoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RepoStoreError::CredentialGone)?;
        sqlx::query(RECHECK_CREDENTIAL)
            .bind(repo.credential_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RepoStoreError::CredentialGone)?;
        let exists: bool = sqlx::query_scalar(EXISTS)
            .bind(user_id)
            .bind(repo.host)
            .bind(repo.path)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            let held: i64 = sqlx::query_scalar(COUNT)
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
            if usize::try_from(held).map_or(true, |held| held >= self.max_repos) {
                return Err(RepoStoreError::TooMany);
            }
        }
        let verified_ms: i64 = sqlx::query_scalar(UPSERT)
            .bind(user_id)
            .bind(repo.host)
            .bind(repo.path)
            .bind(repo.forge_kind)
            .bind(repo.push)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(verified_ms)
    }

    /// Lists the rows of `user_id`.
    ///
    /// # Errors
    ///
    /// Returns [`RepoStoreError::Db`] for a database failure.
    pub async fn list(&self, user_id: i64) -> Result<Vec<RepoRow>, RepoStoreError> {
        let rows = sqlx::query(LIST)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(RepoRow {
                    host: row.try_get("host")?,
                    path: row.try_get("path")?,
                    forge_kind: row.try_get("forge_kind")?,
                    push: row.try_get("push")?,
                    verified_at_ms: row.try_get("verified_ms")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(RepoStoreError::Db)
    }

    /// Deletes the row `(host, path)` of `user_id`.
    ///
    /// # Errors
    ///
    /// Returns [`RepoStoreError::NotFound`] when the user has no such row, whether it never
    /// existed or belongs to another user, and [`RepoStoreError::Db`] for a database failure.
    pub async fn remove(&self, user_id: i64, host: &str, path: &str) -> Result<(), RepoStoreError> {
        let done = sqlx::query(DELETE)
            .bind(user_id)
            .bind(host)
            .bind(path)
            .execute(&self.pool)
            .await?;
        if done.rows_affected() == 0 {
            return Err(RepoStoreError::NotFound);
        }
        Ok(())
    }
}

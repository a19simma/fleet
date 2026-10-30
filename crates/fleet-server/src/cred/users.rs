//! Users, API tokens and the one-time setup code (ADR-0042).
//!
//! The server stores only the SHA-256 of an API token. Postgres computes it, so the plaintext
//! never needs a hashing crate here and never reaches a log or an error.

use std::fmt;
use std::sync::Arc;

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore;
use fleet_core::constant_time_eq;
use fleet_core::credential::Secret;
use sqlx::PgPool;
use tokio::sync::{Mutex, OnceCell};

/// The reserved name of the lazily created owner of legacy jobs.
pub const BOOTSTRAP_USERNAME: &str = "bootstrap";

/// The longest accepted username in bytes, matching the table check.
pub const MAX_USERNAME_LEN: usize = 64;

const TOKEN_PREFIX: &str = "flt_";
const RANDOM_BYTES: usize = 32;
const SETUP_LOCK: i64 = 0x4655_5345_5253;

const HAS_REAL_USERS: &str =
    "SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) <> 'bootstrap')";
const INSERT_USER: &str = "INSERT INTO users (username) VALUES ($1) RETURNING id";
const LOCK: &str = "SELECT pg_advisory_xact_lock($1)";
const BOOTSTRAP_ID: &str = "SELECT bootstrap_user_id()";
const INSERT_TOKEN: &str = "\
INSERT INTO api_tokens (user_id, hash, label) VALUES ($1, sha256($2::bytea), $3) RETURNING id";
const FIND_TOKEN: &str = "\
SELECT user_id FROM api_tokens WHERE hash = sha256($1::bytea) AND revoked_at IS NULL";
const REVOKE_TOKEN: &str = "\
UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL";

/// Why a user operation failed. Messages are fixed text.
#[derive(Debug)]
pub enum UserError {
    /// The username is empty, too long or has characters outside `[A-Za-z0-9._-]`.
    InvalidUsername,
    /// The username is `bootstrap`, in any letter case.
    ReservedUsername,
    /// Another user already has this username.
    Taken,
    /// The setup code does not match the one issued.
    BadSetupCode,
    /// A user already exists, so setup is closed for good.
    SetupClosed,
    /// No such token, or it belongs to another user.
    NotFound,
    /// The database failed.
    Db(sqlx::Error),
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidUsername => "invalid username",
            Self::ReservedUsername => "username is reserved",
            Self::Taken => "username is taken",
            Self::BadSetupCode => "invalid setup code",
            Self::SetupClosed => "setup is closed",
            Self::NotFound => "token not found",
            Self::Db(_) => "user store database error",
        })
    }
}

impl std::error::Error for UserError {}

impl From<sqlx::Error> for UserError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// Checks a username: 1 to 64 characters from `[A-Za-z0-9._-]`, and not `bootstrap`.
///
/// # Errors
///
/// Returns [`UserError::InvalidUsername`] or [`UserError::ReservedUsername`].
pub fn validate_username(name: &str) -> Result<(), UserError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_USERNAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        return Err(UserError::InvalidUsername);
    }
    if name.eq_ignore_ascii_case(BOOTSTRAP_USERNAME) {
        return Err(UserError::ReservedUsername);
    }
    Ok(())
}

fn random_hex() -> String {
    use fmt::Write as _;

    let mut bytes = [0_u8; RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(RANDOM_BYTES * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A freshly created API token. The plaintext is shown once and never stored.
pub struct NewApiToken {
    /// Row id, used to revoke.
    pub id: i64,
    /// The bearer value to give the user.
    pub token: Secret,
}

impl fmt::Debug for NewApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewApiToken")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Users, API tokens and the in-memory setup code over one pool.
#[derive(Clone)]
pub struct Users {
    pool: PgPool,
    setup: Arc<Mutex<Option<Secret>>>,
    bootstrap: Arc<OnceCell<i64>>,
}

impl fmt::Debug for Users {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Users(..)")
    }
}

impl Users {
    /// Builds the store over `pool`.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            setup: Arc::new(Mutex::new(None)),
            bootstrap: Arc::new(OnceCell::new()),
        }
    }

    /// True when any user other than the lazily created `bootstrap` user exists.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn has_real_users(&self) -> Result<bool, UserError> {
        Ok(sqlx::query_scalar(HAS_REAL_USERS)
            .fetch_one(&self.pool)
            .await?)
    }

    /// Issues a setup code held in memory, or `None` when a user already exists.
    ///
    /// Each call with no users replaces the previous code.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn issue_setup_code(&self) -> Result<Option<Secret>, UserError> {
        let mut slot = self.setup.lock().await;
        if self.has_real_users().await? {
            *slot = None;
            return Ok(None);
        }
        *slot = Some(Secret::new(random_hex()));
        Ok(slot
            .as_ref()
            .map(|code| Secret::new(String::from_utf8_lossy(code.expose()).into_owned())))
    }

    /// Checks `code` against the issued setup code without spending it.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::BadSetupCode`] when no code is issued or `code` differs.
    pub async fn check_setup(&self, code: &[u8]) -> Result<(), UserError> {
        let slot = self.setup.lock().await;
        let matches = slot
            .as_ref()
            .is_some_and(|issued| constant_time_eq(issued.expose(), code));
        drop(slot);
        if matches {
            Ok(())
        } else {
            Err(UserError::BadSetupCode)
        }
    }

    /// Creates the admin user when `code` matches the issued setup code.
    ///
    /// The code is spent on success. A wrong code leaves it in place. Once any user exists
    /// this always fails with [`UserError::SetupClosed`] and drops the code.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::BadSetupCode`], [`UserError::SetupClosed`], a username error or
    /// [`UserError::Db`].
    pub async fn redeem_setup(&self, code: &[u8], username: &str) -> Result<i64, UserError> {
        let mut slot = self.setup.lock().await;
        let matches = slot
            .as_ref()
            .is_some_and(|issued| constant_time_eq(issued.expose(), code));
        if !matches {
            return Err(UserError::BadSetupCode);
        }
        validate_username(username)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK).bind(SETUP_LOCK).execute(&mut *tx).await?;
        let exists: bool = sqlx::query_scalar(HAS_REAL_USERS)
            .fetch_one(&mut *tx)
            .await?;
        if exists {
            *slot = None;
            return Err(UserError::SetupClosed);
        }
        let id: i64 = sqlx::query_scalar(INSERT_USER)
            .bind(username)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => UserError::Taken,
                _ => UserError::Db(e),
            })?;
        tx.commit().await?;
        *slot = None;
        drop(slot);
        Ok(id)
    }

    /// The id of the `bootstrap` user that `FLEET_CLIENT_TOKEN` acts as.
    ///
    /// The row is created on first use and cached.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn bootstrap_user(&self) -> Result<i64, UserError> {
        self.bootstrap
            .get_or_try_init(|| async {
                sqlx::query_scalar(BOOTSTRAP_ID)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(UserError::Db)
            })
            .await
            .copied()
    }

    /// Creates an API token for `user_id`. Only its SHA-256 is stored.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn create_api_token(
        &self,
        user_id: i64,
        label: &str,
    ) -> Result<NewApiToken, UserError> {
        let token = Secret::new(format!("{TOKEN_PREFIX}{}", random_hex()));
        let id: i64 = sqlx::query_scalar(INSERT_TOKEN)
            .bind(user_id)
            .bind(token.expose())
            .bind(label)
            .fetch_one(&self.pool)
            .await?;
        Ok(NewApiToken { id, token })
    }

    /// Revokes the user's token. A revoked token no longer authenticates.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::NotFound`] when the id is unknown, revoked or owned by another user.
    pub async fn revoke_api_token(&self, user_id: i64, token_id: i64) -> Result<(), UserError> {
        let done = sqlx::query(REVOKE_TOKEN)
            .bind(token_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if done.rows_affected() == 0 {
            return Err(UserError::NotFound);
        }
        Ok(())
    }

    /// Resolves a bearer value to its user, or `None` for an unknown or revoked token.
    ///
    /// The lookup keys on the SHA-256 of the value, so its timing carries nothing about
    /// the plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn authenticate(&self, token: &[u8]) -> Result<Option<i64>, UserError> {
        Ok(sqlx::query_scalar(FIND_TOKEN)
            .bind(token)
            .fetch_optional(&self.pool)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_validated_and_bootstrap_is_reserved() {
        for ok in ["alice", "a.b_c-1", "Admin"] {
            assert!(validate_username(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "caf\u{e9}", &"x".repeat(65)] {
            assert!(
                matches!(validate_username(bad), Err(UserError::InvalidUsername)),
                "{bad}"
            );
        }
        for reserved in ["bootstrap", "Bootstrap", "BOOTSTRAP"] {
            assert!(
                matches!(
                    validate_username(reserved),
                    Err(UserError::ReservedUsername)
                ),
                "{reserved}"
            );
        }
    }

    #[test]
    fn new_token_debug_is_redacted() {
        let token = NewApiToken {
            id: 1,
            token: Secret::new("flt_secretvalue".into()),
        };
        assert!(!format!("{token:?}").contains("secretvalue"));
    }
}

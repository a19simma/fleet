//! Users, API tokens and the one-time setup code (ADR-0042).
//!
//! The server stores only the SHA-256 of an API token. Postgres computes it, so the plaintext
//! never needs a hashing crate here and never reaches a log or an error.

use std::fmt;
use std::sync::Arc;

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore;
use fleet_core::credential::Secret;
use fleet_core::{BOX_TOKEN_PREFIX, constant_time_eq};
use sqlx::PgPool;
use tokio::sync::{Mutex, OnceCell, OwnedMutexGuard};

/// The reserved name of the lazily created owner of legacy jobs.
pub const BOOTSTRAP_USERNAME: &str = "bootstrap";

/// The longest accepted username in bytes, matching the table check.
pub const MAX_USERNAME_LEN: usize = 64;

/// The most active per-Box tokens one user holds.
pub const MAX_ACTIVE_BOX_TOKENS: i64 = 20;

/// The default lifetime of a per-Box token in days.
pub const DEFAULT_BOX_TOKEN_DAYS: u32 = fleet_core::box_token::DEFAULT_DAYS;

/// The longest lifetime of a per-Box token in days.
pub const MAX_BOX_TOKEN_DAYS: u32 = fleet_core::box_token::MAX_DAYS;

/// The longest per-Box token label in characters.
pub const MAX_BOX_TOKEN_LABEL_CHARS: usize = fleet_core::box_token::MAX_LABEL_CHARS;

const TOKEN_PREFIX: &str = "flt_";
const RANDOM_BYTES: usize = 32;
const SETUP_LOCK: i64 = 0x4655_5345_5253;

const HAS_REAL_USERS: &str =
    "SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) <> 'bootstrap')";
const INSERT_ADMIN_USER: &str =
    "INSERT INTO users (username, is_admin) VALUES ($1, true) RETURNING id";
const LOCK_TARGET: &str = "SELECT username FROM users WHERE id = $1 FOR UPDATE";
const SET_ADMIN: &str = "UPDATE users SET is_admin = $2 WHERE id = $1";
const READ_ADMIN: &str = "SELECT is_admin FROM users WHERE id = $1";
const LOCK: &str = "SELECT pg_advisory_xact_lock($1)";
const BOOTSTRAP_ID: &str = "SELECT bootstrap_user_id()";
const INSERT_TOKEN: &str = "\
INSERT INTO api_tokens (user_id, hash, label) VALUES ($1, sha256($2::bytea), $3) RETURNING id";
const FIND_TOKEN: &str = "\
SELECT t.user_id, u.is_admin FROM api_tokens t JOIN users u ON u.id = t.user_id \
WHERE t.hash = sha256($1::bytea) AND t.revoked_at IS NULL";
const FIND_USER_CODE: &str = "\
SELECT user_id FROM setup_codes \
WHERE hash = sha256($1::bytea) AND used_at IS NULL AND expires_at > now()";
const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR UPDATE";
const REDEEM_USER_CODE: &str = "\
UPDATE setup_codes SET used_at = now() \
WHERE hash = sha256($1::bytea) AND used_at IS NULL AND expires_at > now() RETURNING user_id";
const PASSWORD_CLOSED: &str = "\
SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) <> 'bootstrap') \
OR EXISTS (SELECT 1 FROM bootstrap_password)";
const REVOKE_PASSWORD: &str = "\
INSERT INTO bootstrap_password (user_id, hash, revoked_at) VALUES ($1, '', now())";
const AUDIT_PASSWORD_REVOKED: &str = "\
INSERT INTO admin_audit (action, user_id, username, operator) \
VALUES ('bootstrap_password_revoked', $1, $2, 'server')";
const REVOKE_TOKEN: &str = "\
UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL";

const LOCK_BOX_TOKEN_OWNER: &str = "SELECT id FROM users WHERE id = $1 FOR UPDATE";
const EXPIRE_BOX_TOKENS: &str = "\
UPDATE box_tokens SET revoked_at = expires_at \
WHERE box_name = $1 AND revoked_at IS NULL AND expires_at <= now()";
const COUNT_BOX_TOKENS: &str = "\
SELECT count(*) FROM box_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()";
const INSERT_BOX_TOKEN: &str = "\
INSERT INTO box_tokens (user_id, box_name, hash, label, expires_at) \
VALUES ($1, $2, sha256($3::bytea), $4, now() + make_interval(days => $5)) \
RETURNING id, expires_at::text";
const AUDIT_BOX_TOKEN: &str = "\
INSERT INTO box_token_audit (token_id, user_id, box_name, action) VALUES ($1, $2, $3, $4)";
const FIND_BOX_TOKEN: &str = "\
SELECT id, user_id, box_name, last_used_at IS NULL OR last_used_at < now() - interval '1 minute' \
FROM box_tokens WHERE hash = sha256($1::bytea) AND revoked_at IS NULL AND expires_at > now()";
const TOUCH_BOX_TOKEN: &str = "\
UPDATE box_tokens SET last_used_at = now() \
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')";
const REVOKE_BOX_TOKEN: &str = "\
UPDATE box_tokens SET revoked_at = now() \
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING box_name";
const LIST_BOX_TOKENS: &str = "\
SELECT id, box_name, label, created_at::text, expires_at::text, last_used_at::text, revoked_at::text \
FROM box_tokens WHERE user_id = $1 ORDER BY id";

/// The user an API token belongs to and whether that user is an admin right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenOwner {
    /// The user's row id.
    pub user_id: i64,
    /// The `users.is_admin` flag at the time of the lookup.
    pub is_admin: bool,
}

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
    /// No user has this id.
    NoSuchUser,
    /// The reserved `bootstrap` user can never be admin.
    BootstrapNotAdmin,
    /// A per-Box token label is too long or holds control or hostile characters.
    InvalidLabel,
    /// A per-Box token lifetime is above [`MAX_BOX_TOKEN_DAYS`].
    InvalidTtl,
    /// An active per-Box token already exists for the Box name.
    BoxNameTaken,
    /// The user already holds [`MAX_ACTIVE_BOX_TOKENS`] active per-Box tokens.
    TooManyBoxTokens,
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
            Self::NoSuchUser => "no such user",
            Self::BootstrapNotAdmin => "the bootstrap user cannot be admin",
            Self::InvalidLabel => "invalid label",
            Self::InvalidTtl => "invalid lifetime",
            Self::BoxNameTaken => "box name is taken",
            Self::TooManyBoxTokens => "too many active box tokens",
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

pub(crate) fn random_hex() -> String {
    use fmt::Write as _;

    let mut bytes = [0_u8; RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(RANDOM_BYTES * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A validated per-Box token label: at most 64 characters, no control or hostile character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxTokenLabel(String);

impl BoxTokenLabel {
    /// Validates a label. An empty label is allowed.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::InvalidLabel`].
    pub fn new(raw: &str) -> Result<Self, UserError> {
        if fleet_core::box_token::label_is_valid(raw) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(UserError::InvalidLabel)
        }
    }

    /// The label text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated per-Box token lifetime in days, 1 to [`MAX_BOX_TOKEN_DAYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxTokenTtl(u32);

impl BoxTokenTtl {
    /// Validates a lifetime. Zero means [`DEFAULT_BOX_TOKEN_DAYS`].
    ///
    /// # Errors
    ///
    /// Returns [`UserError::InvalidTtl`] above [`MAX_BOX_TOKEN_DAYS`].
    pub const fn new(days: u32) -> Result<Self, UserError> {
        if days == 0 {
            Ok(Self(DEFAULT_BOX_TOKEN_DAYS))
        } else if fleet_core::box_token::days_are_valid(days) {
            Ok(Self(days))
        } else {
            Err(UserError::InvalidTtl)
        }
    }

    /// The lifetime in days.
    pub const fn days(self) -> u32 {
        self.0
    }
}

/// A freshly issued per-Box token. The plaintext is shown once and never stored.
pub struct NewBoxToken {
    /// Row id, used to revoke.
    pub id: i64,
    /// The bearer value to give the Box.
    pub token: Secret,
    /// The expiry as Postgres renders it.
    pub expires_at: String,
}

impl fmt::Debug for NewBoxToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewBoxToken")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// What a valid per-Box token resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxTokenOwner {
    /// The token row id.
    pub token_id: i64,
    /// The user the token was issued to.
    pub user_id: i64,
    /// The one Box name the token is bound to.
    pub box_name: String,
}

/// One row of a user's per-Box token list. It never holds the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxTokenRow {
    /// The token row id.
    pub id: i64,
    /// The Box name the token is bound to.
    pub box_name: String,
    /// The label given at issue.
    pub label: String,
    /// Creation time as Postgres renders it.
    pub created_at: String,
    /// Expiry as Postgres renders it.
    pub expires_at: String,
    /// The last use, throttled to once a minute.
    pub last_used_at: Option<String>,
    /// The revocation time, when revoked.
    pub revoked_at: Option<String>,
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

/// An admin user created in an open transaction, with the setup code still held.
pub struct SetupRedemption {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    slot: Option<OwnedMutexGuard<Option<Secret>>>,
    user_id: i64,
    username: String,
    revokes_password: bool,
}

impl SetupRedemption {
    /// The id of the user created in the transaction.
    pub const fn user_id(&self) -> i64 {
        self.user_id
    }

    /// The connection of the open transaction.
    pub fn conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    /// Commits the transaction and spends the setup code. A redemption by the bootstrap
    /// password first records the revocation and its audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] when a write or the commit fails; the code stays in place
    /// and the password stays unrevoked.
    pub async fn commit(self) -> Result<(), UserError> {
        let Self {
            mut tx,
            slot,
            user_id,
            username,
            revokes_password,
        } = self;
        if revokes_password {
            sqlx::query(REVOKE_PASSWORD)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(AUDIT_PASSWORD_REVOKED)
                .bind(user_id)
                .bind(&username)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        if let Some(mut slot) = slot {
            *slot = None;
        }
        Ok(())
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

    /// Creates the first admin user (flag set) when `code` matches the issued setup code.
    ///
    /// The code is spent on success. A wrong code leaves it in place. Once any user exists
    /// this always fails with [`UserError::SetupClosed`] and drops the code.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::BadSetupCode`], [`UserError::SetupClosed`],
    /// [`UserError::InvalidUsername`] or [`UserError::ReservedUsername`] for a refused username,
    /// [`UserError::Taken`] when the username exists, or [`UserError::Db`], which includes a
    /// failed commit.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "commit consumes the redemption; the lint cannot see the move"
    )]
    pub async fn redeem_setup(&self, code: &[u8], username: &str) -> Result<i64, UserError> {
        let redemption = self.begin_redeem_setup(code, username).await?;
        let id = redemption.user_id();
        redemption.commit().await?;
        Ok(id)
    }

    /// Creates the admin user inside an open transaction and holds the setup code.
    ///
    /// The caller stores the first passkey through [`SetupRedemption::conn`] and then calls
    /// [`SetupRedemption::commit`]. Dropping the redemption rolls back the user and leaves
    /// the code in place, so no admin exists without a passkey.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::BadSetupCode`], [`UserError::SetupClosed`],
    /// [`UserError::InvalidUsername`] or [`UserError::ReservedUsername`] for a refused username,
    /// [`UserError::Taken`] when the username exists, or [`UserError::Db`].
    pub async fn begin_redeem_setup(
        &self,
        code: &[u8],
        username: &str,
    ) -> Result<SetupRedemption, UserError> {
        let mut slot = Arc::clone(&self.setup).lock_owned().await;
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
        let id: i64 = sqlx::query_scalar(INSERT_ADMIN_USER)
            .bind(username)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => UserError::Taken,
                _ => UserError::Db(e),
            })?;
        Ok(SetupRedemption {
            tx,
            slot: Some(slot),
            user_id: id,
            username: username.to_owned(),
            revokes_password: false,
        })
    }

    /// True while the bootstrap password may still be used: no real user exists and no
    /// revocation row exists. A reset never clears a revocation row.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn bootstrap_password_armed(&self) -> Result<bool, UserError> {
        let closed: bool = sqlx::query_scalar(PASSWORD_CLOSED)
            .fetch_one(&self.pool)
            .await?;
        Ok(!closed)
    }

    /// Creates the admin user inside an open transaction for a caller that already verified
    /// the bootstrap password. The setup lock is taken first and the closed state is checked
    /// under it, so of two concurrent callers exactly one gets a redemption.
    ///
    /// The caller stores the first passkey through [`SetupRedemption::conn`] and then calls
    /// [`SetupRedemption::commit`], which revokes the password in the same transaction.
    /// Dropping the redemption rolls everything back and leaves the password unrevoked.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::SetupClosed`] once a user or a revocation exists,
    /// [`UserError::InvalidUsername`] or [`UserError::ReservedUsername`] for a refused username
    /// (the reserved `bootstrap` name included), [`UserError::Taken`] when the username exists,
    /// or [`UserError::Db`].
    pub async fn begin_redeem_password(
        &self,
        username: &str,
    ) -> Result<SetupRedemption, UserError> {
        validate_username(username)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK).bind(SETUP_LOCK).execute(&mut *tx).await?;
        let closed: bool = sqlx::query_scalar(PASSWORD_CLOSED)
            .fetch_one(&mut *tx)
            .await?;
        if closed {
            return Err(UserError::SetupClosed);
        }
        let id: i64 = sqlx::query_scalar(INSERT_ADMIN_USER)
            .bind(username)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => UserError::Taken,
                _ => UserError::Db(e),
            })?;
        Ok(SetupRedemption {
            tx,
            slot: None,
            user_id: id,
            username: username.to_owned(),
            revokes_password: true,
        })
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

    /// Sets or clears the admin flag of `user_id`.
    ///
    /// The target row is locked `FOR UPDATE` before the check, so a concurrent call waits and
    /// the `bootstrap` refusal never races a rename. Clearing the flag of `bootstrap` is a
    /// no-op that succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::NoSuchUser`], [`UserError::BootstrapNotAdmin`] when promoting
    /// the reserved user (refused before any write), or [`UserError::Db`].
    pub async fn set_admin(&self, user_id: i64, admin: bool) -> Result<(), UserError> {
        let mut tx = self.pool.begin().await?;
        let username: String = sqlx::query_scalar(LOCK_TARGET)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(UserError::NoSuchUser)?;
        if admin && username.eq_ignore_ascii_case(BOOTSTRAP_USERNAME) {
            return Err(UserError::BootstrapNotAdmin);
        }
        sqlx::query(SET_ADMIN)
            .bind(user_id)
            .bind(admin)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Reads the admin flag of `user_id` fresh from the database, with no cache.
    ///
    /// An unknown id reads as not admin.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn is_admin(&self, user_id: i64) -> Result<bool, UserError> {
        Ok(sqlx::query_scalar(READ_ADMIN)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(false))
    }

    /// Spends an admin-issued setup code and returns the user it was issued for.
    ///
    /// The code is stored as a SHA-256. It works once and only before it expires.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::BadSetupCode`] for an unknown, used or expired code and
    /// [`UserError::Db`] for a database failure.
    pub async fn redeem_user_setup(&self, code: &[u8]) -> Result<i64, UserError> {
        let mut tx = self.pool.begin().await?;
        let user_id = Self::redeem_user_setup_in(&mut tx, code).await?;
        tx.commit().await?;
        Ok(user_id)
    }

    /// Checks an admin-issued setup code without spending it and returns its user.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::BadSetupCode`] for an unknown, used or expired code and
    /// [`UserError::Db`] for a database failure.
    pub async fn check_user_setup(&self, code: &[u8]) -> Result<i64, UserError> {
        sqlx::query_scalar(FIND_USER_CODE)
            .bind(code)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(UserError::BadSetupCode)
    }

    /// Spends an admin-issued setup code inside the caller's transaction.
    ///
    /// The user row is locked with `FOR UPDATE` before the code is spent, so a concurrent
    /// passkey reset either finishes first and voids the code, or waits for the caller's
    /// commit. The caller stores the passkey in the same transaction before committing.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::BadSetupCode`] for an unknown, used or expired code and
    /// [`UserError::Db`] for a database failure.
    pub async fn redeem_user_setup_in(
        conn: &mut sqlx::PgConnection,
        code: &[u8],
    ) -> Result<i64, UserError> {
        let user_id: i64 = sqlx::query_scalar(FIND_USER_CODE)
            .bind(code)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(UserError::BadSetupCode)?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(UserError::BadSetupCode)?;
        sqlx::query_scalar(REDEEM_USER_CODE)
            .bind(code)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(UserError::BadSetupCode)
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

    /// Issues a per-Box token for `user_id` bound to `box_name`.
    ///
    /// The user row is locked `FOR UPDATE`, so two issues cannot both pass the cap. Expired
    /// tokens of the name are closed first, because the partial unique index cannot see time.
    /// The audit row is written in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::NoSuchUser`], [`UserError::BoxNameTaken`] when an active token holds
    /// the name, [`UserError::TooManyBoxTokens`] at the cap and [`UserError::Db`].
    pub async fn issue_box_token(
        &self,
        user_id: i64,
        box_name: &fleet_core::BoxName,
        label: &BoxTokenLabel,
        ttl: BoxTokenTtl,
    ) -> Result<NewBoxToken, UserError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_BOX_TOKEN_OWNER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(UserError::NoSuchUser)?;
        sqlx::query(EXPIRE_BOX_TOKENS)
            .bind(box_name.as_str())
            .execute(&mut *tx)
            .await?;
        let active: i64 = sqlx::query_scalar(COUNT_BOX_TOKENS)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if active >= MAX_ACTIVE_BOX_TOKENS {
            return Err(UserError::TooManyBoxTokens);
        }
        let token = Secret::new(format!("{BOX_TOKEN_PREFIX}{}", random_hex()));
        let (id, expires_at): (i64, String) = sqlx::query_as(INSERT_BOX_TOKEN)
            .bind(user_id)
            .bind(box_name.as_str())
            .bind(token.expose())
            .bind(label.as_str())
            .bind(i32::try_from(ttl.days()).unwrap_or(i32::MAX))
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => UserError::BoxNameTaken,
                _ => UserError::Db(e),
            })?;
        sqlx::query(AUDIT_BOX_TOKEN)
            .bind(id)
            .bind(user_id)
            .bind(box_name.as_str())
            .bind("issue")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(NewBoxToken {
            id,
            token,
            expires_at,
        })
    }

    /// Resolves a bearer value to its per-Box token, or `None` for an unknown, expired or
    /// revoked one. `last_used_at` moves at most once a minute.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn resolve_box_token(
        &self,
        token: &[u8],
    ) -> Result<Option<BoxTokenOwner>, UserError> {
        let row: Option<(i64, i64, String, bool)> = sqlx::query_as(FIND_BOX_TOKEN)
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        let Some((token_id, user_id, box_name, stale)) = row else {
            return Ok(None);
        };
        if stale {
            sqlx::query(TOUCH_BOX_TOKEN)
                .bind(token_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(Some(BoxTokenOwner {
            token_id,
            user_id,
            box_name,
        }))
    }

    /// Lists every per-Box token of `user_id`, revoked and expired ones included.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn list_box_tokens(&self, user_id: i64) -> Result<Vec<BoxTokenRow>, UserError> {
        type Row = (
            i64,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<Row> = sqlx::query_as(LIST_BOX_TOKENS)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, box_name, label, created_at, expires_at, last_used_at, revoked_at)| {
                    BoxTokenRow {
                        id,
                        box_name,
                        label,
                        created_at,
                        expires_at,
                        last_used_at,
                        revoked_at,
                    }
                },
            )
            .collect())
    }

    /// Revokes the user's per-Box token and audits it in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::NotFound`] when the id is unknown, already revoked or owned by
    /// another user, and [`UserError::Db`].
    pub async fn revoke_box_token(&self, user_id: i64, token_id: i64) -> Result<(), UserError> {
        let mut tx = self.pool.begin().await?;
        let name: String = sqlx::query_scalar(REVOKE_BOX_TOKEN)
            .bind(token_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(UserError::NotFound)?;
        sqlx::query(AUDIT_BOX_TOKEN)
            .bind(token_id)
            .bind(user_id)
            .bind(name)
            .bind("revoke")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Revokes the user's token. A revoked token no longer authenticates.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::NotFound`] when the id is unknown, revoked or owned by another user
    /// and [`UserError::Db`] for a database failure.
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
        Ok(self.resolve_token(token).await?.map(|owner| owner.user_id))
    }

    /// Resolves a bearer value to its user and that user's admin flag in one query, read live
    /// with no cache. `None` for an unknown or revoked token.
    ///
    /// # Errors
    ///
    /// Returns [`UserError::Db`] for a database failure.
    pub async fn resolve_token(&self, token: &[u8]) -> Result<Option<TokenOwner>, UserError> {
        let row: Option<(i64, bool)> = sqlx::query_as(FIND_TOKEN)
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(user_id, is_admin)| TokenOwner { user_id, is_admin }))
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

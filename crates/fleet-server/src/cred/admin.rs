//! The `fleet-server admin` subcommand: user create and passkey reset by direct database access.
//!
//! No web route does this (ADR-0042). Every action runs in one transaction that also writes
//! an `admin_audit` row. A setup code is stored as its SHA-256 and printed once by the caller.

use std::fmt;

use fleet_core::credential::Secret;
use sqlx::PgPool;

use super::users::{UserError, random_hex, validate_username};

/// How long a setup code stays valid after the admin command issues it.
pub const SETUP_CODE_TTL_HOURS: i32 = 24;

const FIND_USER: &str = "\
SELECT id, username FROM users WHERE lower(username) = lower($1) AND lower(username) <> 'bootstrap' FOR UPDATE";
const INSERT_USER: &str = "INSERT INTO users (username) VALUES ($1) RETURNING id";
const DELETE_PASSKEYS: &str = "DELETE FROM passkeys WHERE user_id = $1";
const DELETE_SESSIONS: &str = "DELETE FROM web_sessions WHERE user_id = $1";
const DELETE_OPEN_CODES: &str = "DELETE FROM setup_codes WHERE user_id = $1 AND used_at IS NULL";
const INSERT_CODE: &str = "\
INSERT INTO setup_codes (user_id, hash, expires_at) \
VALUES ($1, sha256($2::bytea), now() + make_interval(hours => $3))";
const INSERT_AUDIT: &str = "\
INSERT INTO admin_audit (action, user_id, username, passkeys_removed, sessions_revoked, operator) \
VALUES ($1, $2, $3, $4, $5, $6)";

/// A parsed `admin` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommand {
    /// Create a user and issue a setup code.
    CreateUser(String),
    /// Delete the user's passkeys and sessions and issue a fresh setup code.
    ResetPasskeys(String),
}

/// Why an admin command failed. Messages are fixed text and never carry a secret.
#[derive(Debug)]
pub enum AdminError {
    /// The arguments do not match a command.
    Usage,
    /// No user has that name, or it is the reserved `bootstrap` user.
    NoSuchUser,
    /// `FLEET_DATABASE_URL` is unset.
    MissingDatabaseUrl,
    /// Standard output could not be written, so the setup code was not delivered.
    Output,
    /// A user store error.
    User(UserError),
}

impl AdminError {
    /// The process exit code for this error.
    ///
    /// Usage 2, unknown user 3, username taken 4, invalid or reserved username 5, missing
    /// database URL 6, anything else 1.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage => 2,
            Self::NoSuchUser => 3,
            Self::User(UserError::Taken) => 4,
            Self::User(UserError::InvalidUsername | UserError::ReservedUsername) => 5,
            Self::MissingDatabaseUrl => 6,
            Self::Output | Self::User(_) => 1,
        }
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str(
                "usage: fleet-server admin create-user <username> | reset-passkeys <username>",
            ),
            Self::NoSuchUser => f.write_str("no such user"),
            Self::MissingDatabaseUrl => f.write_str("FLEET_DATABASE_URL is not set"),
            Self::Output => f.write_str("cannot write to standard output"),
            Self::User(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AdminError {}

impl From<UserError> for AdminError {
    fn from(e: UserError) -> Self {
        Self::User(e)
    }
}

impl From<sqlx::Error> for AdminError {
    fn from(e: sqlx::Error) -> Self {
        Self::User(UserError::Db(e))
    }
}

/// What a finished command hands back. The setup code is shown once and never stored in clear.
pub struct AdminOutcome {
    /// The affected user.
    pub user_id: i64,
    /// The user's name as stored.
    pub username: String,
    /// The one-time code that lets the user register a passkey.
    pub setup_code: Secret,
    /// How many passkeys the command deleted.
    pub passkeys_removed: u64,
    /// How many web sessions the command deleted.
    pub sessions_revoked: u64,
}

impl fmt::Debug for AdminOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminOutcome")
            .field("user_id", &self.user_id)
            .field("setup_code", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Parses the arguments after `admin`.
///
/// # Errors
///
/// Returns [`AdminError::Usage`] for an unknown command or a wrong argument count.
pub fn parse_args(args: &[String]) -> Result<AdminCommand, AdminError> {
    match args {
        [cmd, name] if cmd == "create-user" => Ok(AdminCommand::CreateUser(name.clone())),
        [cmd, name] if cmd == "reset-passkeys" => Ok(AdminCommand::ResetPasskeys(name.clone())),
        _ => Err(AdminError::Usage),
    }
}

/// Runs `cmd` in one transaction and records `operator` in the audit row.
///
/// # Errors
///
/// Returns [`AdminError::NoSuchUser`] when a reset names no user, a username error for a
/// create, or a database error. A failed command leaves no row behind.
pub async fn run(
    pool: &PgPool,
    cmd: &AdminCommand,
    operator: &str,
) -> Result<AdminOutcome, AdminError> {
    let mut tx = pool.begin().await?;
    let (action, user_id, username, passkeys, sessions) = match cmd {
        AdminCommand::CreateUser(name) => {
            validate_username(name)?;
            let id: i64 = sqlx::query_scalar(INSERT_USER)
                .bind(name)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| match &e {
                    sqlx::Error::Database(db) if db.is_unique_violation() => UserError::Taken,
                    _ => UserError::Db(e),
                })?;
            ("user_create", id, name.clone(), 0, 0)
        }
        AdminCommand::ResetPasskeys(name) => {
            let (id, stored): (i64, String) = sqlx::query_as(FIND_USER)
                .bind(name)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(AdminError::NoSuchUser)?;
            let passkeys = sqlx::query(DELETE_PASSKEYS)
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let sessions = sqlx::query(DELETE_SESSIONS)
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            sqlx::query(DELETE_OPEN_CODES)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            ("passkey_reset", id, stored, passkeys, sessions)
        }
    };
    let setup_code = Secret::new(random_hex());
    sqlx::query(INSERT_CODE)
        .bind(user_id)
        .bind(setup_code.expose())
        .bind(SETUP_CODE_TTL_HOURS)
        .execute(&mut *tx)
        .await?;
    sqlx::query(INSERT_AUDIT)
        .bind(action)
        .bind(user_id)
        .bind(&username)
        .bind(i32::try_from(passkeys).unwrap_or(i32::MAX))
        .bind(i32::try_from(sessions).unwrap_or(i32::MAX))
        .bind(operator)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(AdminOutcome {
        user_id,
        username,
        setup_code,
        passkeys_removed: passkeys,
        sessions_revoked: sessions,
    })
}

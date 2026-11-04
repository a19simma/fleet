//! Per-user capability grants behind `FleetCapabilityAdmin`.

use fleet_proto::v1::{
    GrantCapabilityRequest, ListCapabilitiesReply, ListCapabilitiesRequest, RevokeCapabilityReply,
    RevokeCapabilityRequest, UserCapability,
};
use tonic::Status;

use std::fmt;

use sqlx::PgPool;

const NOT_IMPLEMENTED: &str = "capabilities are not implemented";

/// The capability that lets a user attach tools to a profile. Store and handlers share this name.
pub const PROFILE_TOOLS: &str = "profile:tools";

/// Refusal text for a capability name outside the closed set.
pub const REASON_UNKNOWN_CAPABILITY: &str = "unknown capability";
/// Refusal text for a grant whose target user does not exist.
pub const REASON_NO_SUCH_USER: &str = "no such user";
/// Refusal text for a grant whose acting admin does not exist.
pub const REASON_NO_SUCH_ACTOR: &str = "no such acting user";
const REASON_DB: &str = "capability store database error";

const KNOWN: [&str; 1] = [PROFILE_TOOLS];

const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR SHARE";
const LOCK_GRANT: &str =
    "SELECT user_id FROM user_capabilities WHERE user_id = $1 AND capability = $2 FOR UPDATE";
const INSERT_GRANT: &str = "INSERT INTO user_capabilities (user_id, capability, granted_by) \
                            VALUES ($1, $2, $3) ON CONFLICT (user_id, capability) DO NOTHING";
const DELETE_GRANT: &str = "DELETE FROM user_capabilities WHERE user_id = $1 AND capability = $2";
const READ_GRANT: &str =
    "SELECT user_id FROM user_capabilities WHERE user_id = $1 AND capability = $2 FOR SHARE";

/// Why a capability store call failed. Messages are fixed text.
#[derive(Debug)]
pub enum CapabilityError {
    /// The capability name is outside the closed set.
    UnknownCapability,
    /// The target user does not exist.
    NoSuchUser,
    /// The acting admin does not exist.
    NoSuchActor,
    /// The database failed.
    Db(sqlx::Error),
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownCapability => REASON_UNKNOWN_CAPABILITY,
            Self::NoSuchUser => REASON_NO_SUCH_USER,
            Self::NoSuchActor => REASON_NO_SUCH_ACTOR,
            Self::Db(_) => REASON_DB,
        })
    }
}

impl std::error::Error for CapabilityError {}

impl From<sqlx::Error> for CapabilityError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

fn known(capability: &str) -> bool {
    KNOWN.contains(&capability)
}

/// The per-user capability store. The acting admin comes from the caller, never a request body.
#[derive(Clone, Debug)]
pub struct Capabilities {
    pool: PgPool,
}

impl Capabilities {
    /// Wraps a pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Grants `capability` to `target`, stamping `actor` as `granted_by`.
    ///
    /// Takes `FOR SHARE` on the actor and target `users` rows and `FOR UPDATE` on the grant row.
    /// Returns `true` when a grant was created, `false` when one already existed (its audit
    /// columns stay as first written).
    ///
    /// # Errors
    /// [`CapabilityError::UnknownCapability`], [`CapabilityError::NoSuchActor`],
    /// [`CapabilityError::NoSuchUser`] or [`CapabilityError::Db`].
    pub async fn grant(
        &self,
        actor: i64,
        target: i64,
        capability: &str,
    ) -> Result<bool, CapabilityError> {
        if !known(capability) {
            return Err(CapabilityError::UnknownCapability);
        }
        let mut tx = self.pool.begin().await?;
        let actor_row = sqlx::query(LOCK_USER)
            .bind(actor)
            .fetch_optional(&mut *tx)
            .await?;
        if actor_row.is_none() {
            return Err(CapabilityError::NoSuchActor);
        }
        let target_row = sqlx::query(LOCK_USER)
            .bind(target)
            .fetch_optional(&mut *tx)
            .await?;
        if target_row.is_none() {
            return Err(CapabilityError::NoSuchUser);
        }
        let held = sqlx::query(LOCK_GRANT)
            .bind(target)
            .bind(capability)
            .fetch_optional(&mut *tx)
            .await?;
        let created = if held.is_some() {
            false
        } else {
            sqlx::query(INSERT_GRANT)
                .bind(target)
                .bind(capability)
                .bind(actor)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                == 1
        };
        tx.commit().await?;
        Ok(created)
    }

    /// Revokes `capability` from `target` on behalf of `actor`.
    ///
    /// Takes `FOR SHARE` on the actor row and `FOR UPDATE` on the grant row. Returns `false` and writes nothing when no grant
    /// exists.
    ///
    /// # Errors
    /// [`CapabilityError::UnknownCapability`], [`CapabilityError::NoSuchActor`] or
    /// [`CapabilityError::Db`].
    pub async fn revoke(
        &self,
        actor: i64,
        target: i64,
        capability: &str,
    ) -> Result<bool, CapabilityError> {
        if !known(capability) {
            return Err(CapabilityError::UnknownCapability);
        }
        let mut tx = self.pool.begin().await?;
        let actor_row = sqlx::query(LOCK_USER)
            .bind(actor)
            .fetch_optional(&mut *tx)
            .await?;
        if actor_row.is_none() {
            return Err(CapabilityError::NoSuchActor);
        }
        let held = sqlx::query(LOCK_GRANT)
            .bind(target)
            .bind(capability)
            .fetch_optional(&mut *tx)
            .await?;
        if held.is_none() {
            return Ok(false);
        }
        let deleted = sqlx::query(DELETE_GRANT)
            .bind(target)
            .bind(capability)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted == 1)
    }

    /// Whether `user` holds `capability`. An unknown user or capability is `false`.
    ///
    /// Reads under `FOR SHARE`, so it waits for an open grant or revoke on the row.
    ///
    /// # Errors
    /// [`CapabilityError::Db`]; callers must treat it as a denial.
    pub async fn has(&self, user: i64, capability: &str) -> Result<bool, CapabilityError> {
        if !known(capability) {
            return Ok(false);
        }
        let mut tx = self.pool.begin().await?;
        let held = sqlx::query(READ_GRANT)
            .bind(user)
            .bind(capability)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(held.is_some())
    }
}

/// Grants a capability to a user.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn grant(_request: &GrantCapabilityRequest) -> Result<UserCapability, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Revokes a capability from a user.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn revoke(_request: &RevokeCapabilityRequest) -> Result<RevokeCapabilityReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Lists the capabilities a user holds.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn list(_request: &ListCapabilitiesRequest) -> Result<ListCapabilitiesReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

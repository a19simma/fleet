//! Per-user capability grants behind `FleetCapabilityAdmin`.

use fleet_proto::v1::{
    GrantCapabilityRequest, ListCapabilitiesReply, ListCapabilitiesRequest, RevokeCapabilityReply,
    RevokeCapabilityRequest, UserCapability,
};
use tonic::Status;

use std::fmt;

use sqlx::PgPool;

use crate::auth::ADMIN_REQUIRED;

/// The capability that lets a user attach tools to a profile. Store and handlers share this name.
pub const PROFILE_TOOLS: &str = "profile:tools";

pub use fleet_proto::ERR_CAPABILITY_NOT_GRANTED;
/// The capability that gates the `github_app` credential kind (ADR-0058).
pub const FORGE_GITHUB_APP: &str = "forge:github_app";
/// Refusal text for a capability name outside the closed set.
pub const REASON_UNKNOWN_CAPABILITY: &str = "unknown capability";
/// Refusal text for a call whose target user does not exist.
pub const REASON_NO_SUCH_USER: &str = "no such user";
/// Refusal text for a call whose acting admin does not exist.
pub const REASON_NO_SUCH_ACTOR: &str = "no such acting user";
/// Refusal text for a call whose acting user is not an admin.
pub const REASON_ADMIN_REQUIRED: &str = ADMIN_REQUIRED;
const REASON_DB: &str = "capability store database error";

const KNOWN: [&str; 2] = [PROFILE_TOOLS, FORGE_GITHUB_APP];

const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR SHARE";
const LOCK_ACTOR: &str = "SELECT is_admin FROM users WHERE id = $1 FOR SHARE";
const GRANT_ROW: &str = "SELECT user_id, capability, granted_by, \
                         (extract(epoch FROM granted_at) * 1000)::bigint \
                         FROM user_capabilities WHERE user_id = $1 AND capability = $2";
const LIST_ROWS: &str = "SELECT user_id, capability, granted_by, \
                         (extract(epoch FROM granted_at) * 1000)::bigint \
                         FROM user_capabilities WHERE user_id = $1 ORDER BY capability";
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
    /// The acting user is not an admin.
    NotAdmin,
    /// The database failed.
    Db(sqlx::Error),
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownCapability => REASON_UNKNOWN_CAPABILITY,
            Self::NoSuchUser => REASON_NO_SUCH_USER,
            Self::NoSuchActor => REASON_NO_SUCH_ACTOR,
            Self::NotAdmin => REASON_ADMIN_REQUIRED,
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

impl From<&CapabilityError> for Status {
    fn from(err: &CapabilityError) -> Self {
        match err {
            CapabilityError::UnknownCapability => Self::invalid_argument(REASON_UNKNOWN_CAPABILITY),
            CapabilityError::NoSuchUser => Self::not_found(REASON_NO_SUCH_USER),
            CapabilityError::NoSuchActor | CapabilityError::NotAdmin => {
                Self::permission_denied(ADMIN_REQUIRED)
            }
            CapabilityError::Db(_) => Self::internal(REASON_DB),
        }
    }
}

/// One stored grant row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The user holding the capability.
    pub user_id: i64,
    /// The capability name.
    pub capability: String,
    /// The admin who first granted it.
    pub granted_by: i64,
    /// When it was granted, in milliseconds since the Unix epoch.
    pub granted_at_ms: i64,
}

/// The outcome of [`Capabilities::grant_stored`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Granted {
    /// `true` when this call created the grant.
    pub created: bool,
    /// The stored row, with its first-written audit columns.
    pub grant: Grant,
}

impl Grant {
    fn into_proto(self) -> Result<UserCapability, Status> {
        let id = |v: i64| u64::try_from(v).map_err(|_| Status::internal(REASON_DB));
        Ok(UserCapability {
            user_id: id(self.user_id)?,
            capability: self.capability,
            granted_by: id(self.granted_by)?,
            granted_at_ms: id(self.granted_at_ms)?,
        })
    }
}

type GrantTuple = (i64, String, i64, i64);

fn grant_of((user_id, capability, granted_by, granted_at_ms): GrantTuple) -> Grant {
    Grant {
        user_id,
        capability,
        granted_by,
        granted_at_ms,
    }
}

async fn lock_admin(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: i64,
) -> Result<(), CapabilityError> {
    let admin: Option<bool> = sqlx::query_scalar(LOCK_ACTOR)
        .bind(actor)
        .fetch_optional(&mut **tx)
        .await?;
    match admin {
        None => Err(CapabilityError::NoSuchActor),
        Some(false) => Err(CapabilityError::NotAdmin),
        Some(true) => Ok(()),
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
    /// Returns `true` when a grant was created, `false` when one already existed. See
    /// [`Capabilities::grant_stored`].
    ///
    /// # Errors
    /// Those of [`Capabilities::grant_stored`].
    pub async fn grant(
        &self,
        actor: i64,
        target: i64,
        capability: &str,
    ) -> Result<bool, CapabilityError> {
        Ok(self.grant_stored(actor, target, capability).await?.created)
    }

    /// Grants `capability` to `target` as the admin `actor` and returns the stored row.
    ///
    /// `actor` is the authenticated caller's user id, never a request field. Reads `is_admin`
    /// under `FOR SHARE` on the actor `users` row, so a demotion in flight finishes first, and
    /// refuses a non-admin. Then takes `FOR SHARE` on the target row and `FOR UPDATE` on the
    /// grant row. An existing grant keeps its first-written audit columns.
    ///
    /// # Errors
    /// [`CapabilityError::UnknownCapability`], [`CapabilityError::NoSuchActor`],
    /// [`CapabilityError::NotAdmin`], [`CapabilityError::NoSuchUser`] or [`CapabilityError::Db`].
    pub async fn grant_stored(
        &self,
        actor: i64,
        target: i64,
        capability: &str,
    ) -> Result<Granted, CapabilityError> {
        if !known(capability) {
            return Err(CapabilityError::UnknownCapability);
        }
        let mut tx = self.pool.begin().await?;
        lock_admin(&mut tx, actor).await?;
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
        let row: GrantTuple = sqlx::query_as(GRANT_ROW)
            .bind(target)
            .bind(capability)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Granted {
            created,
            grant: grant_of(row),
        })
    }

    /// Lists the grants `target` holds, as the admin `actor`.
    ///
    /// Takes the same actor and target row locks as [`Capabilities::grant_stored`]. Rows of other
    /// users never appear.
    ///
    /// # Errors
    /// [`CapabilityError::NoSuchActor`], [`CapabilityError::NotAdmin`],
    /// [`CapabilityError::NoSuchUser`] or [`CapabilityError::Db`].
    pub async fn list(&self, actor: i64, target: i64) -> Result<Vec<Grant>, CapabilityError> {
        let mut tx = self.pool.begin().await?;
        lock_admin(&mut tx, actor).await?;
        let target_row = sqlx::query(LOCK_USER)
            .bind(target)
            .fetch_optional(&mut *tx)
            .await?;
        if target_row.is_none() {
            return Err(CapabilityError::NoSuchUser);
        }
        let rows: Vec<GrantTuple> = sqlx::query_as(LIST_ROWS)
            .bind(target)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(grant_of).collect())
    }

    /// Revokes `capability` from `target` on behalf of `actor`.
    ///
    /// Reads `is_admin` on the actor row under `FOR SHARE` and refuses a non-admin, takes
    /// `FOR SHARE` on the target row, then `FOR UPDATE` on the grant row. Returns `false` and
    /// writes nothing when the user holds no grant.
    ///
    /// # Errors
    /// [`CapabilityError::UnknownCapability`], [`CapabilityError::NoSuchActor`],
    /// [`CapabilityError::NotAdmin`], [`CapabilityError::NoSuchUser`] or [`CapabilityError::Db`].
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
        lock_admin(&mut tx, actor).await?;
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

fn target_of(user_id: u64) -> Result<i64, Status> {
    i64::try_from(user_id).map_err(|_| Status::invalid_argument(REASON_NO_SUCH_USER_RANGE))
}

const REASON_NO_SUCH_USER_RANGE: &str = "user id out of range";

/// Grants a capability to a user as the admin `actor` and echoes the stored row.
///
/// # Errors
/// `INVALID_ARGUMENT` for a user id over `i64::MAX` or an unknown capability, `NOT_FOUND` for an
/// unknown user, `PERMISSION_DENIED` when `actor` is not an admin, `INTERNAL` on a storage failure.
pub async fn grant(
    caps: &Capabilities,
    actor: i64,
    request: &GrantCapabilityRequest,
) -> Result<UserCapability, Status> {
    let target = target_of(request.user_id)?;
    caps.grant_stored(actor, target, &request.capability)
        .await
        .map_err(|err| Status::from(&err))?
        .grant
        .into_proto()
}

/// Revokes a capability from a user as the admin `actor`.
///
/// # Errors
/// `INVALID_ARGUMENT` for a user id over `i64::MAX` or an unknown capability, `NOT_FOUND` for an
/// unknown user, `PERMISSION_DENIED` when `actor` is not an admin, `INTERNAL` on a storage failure.
pub async fn revoke(
    caps: &Capabilities,
    actor: i64,
    request: &RevokeCapabilityRequest,
) -> Result<RevokeCapabilityReply, Status> {
    let target = target_of(request.user_id)?;
    let removed = caps
        .revoke(actor, target, &request.capability)
        .await
        .map_err(|err| Status::from(&err))?;
    Ok(RevokeCapabilityReply { removed })
}

/// Lists the capabilities one user holds, as the admin `actor`.
///
/// # Errors
/// `INVALID_ARGUMENT` for a user id over `i64::MAX`, `NOT_FOUND` for an unknown user,
/// `PERMISSION_DENIED` when `actor` is not an admin, `INTERNAL` on a storage failure.
pub async fn list(
    caps: &Capabilities,
    actor: i64,
    request: &ListCapabilitiesRequest,
) -> Result<ListCapabilitiesReply, Status> {
    let target = target_of(request.user_id)?;
    let grants = caps
        .list(actor, target)
        .await
        .map_err(|err| Status::from(&err))?;
    Ok(ListCapabilitiesReply {
        capabilities: grants
            .into_iter()
            .map(Grant::into_proto)
            .collect::<Result<_, _>>()?,
    })
}

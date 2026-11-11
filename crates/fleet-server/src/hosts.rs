//! The git host table and the `FleetHosts` add, list and remove handlers (ADR-0068).
//!
//! A User adds a host: the name is normalised, vetted against the public address rule, probed
//! for a Forgejo or Gitea version document with no credential, and inserted with its audit row in
//! one transaction. Every refusal carries one closed `FAILED_PRECONDITION` reason, and a private
//! or unresolvable host gets the same reason as a name outside the grammar, so the add path
//! cannot be used to scan a private network. Resolved addresses, upstream bodies and DNS errors go
//! to server logs only.
//!
//! Lock order: the credential store takes `git_hosts` `FOR SHARE` before it writes a credential
//! row, and deletes a credential row before it reads `git_hosts` `FOR SHARE`. [`HostStore::remove`]
//! takes the host row `FOR UPDATE` first and reads the credential and repository tables without a
//! row lock, so it queues behind a put and never waits on a credential row: no cycle exists.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use fleet_core::host::{Host, HostKind, HostName};
use fleet_forge::{
    ForgeApi, ForgeError, GiteaForge, Http, HttpError, HttpRequest, HttpResponse, REPO_CHECK_BUDGET,
};
use fleet_proto::v1::{
    AddHostRequest, ApproveHostPrivateRequest, HostInfo, HostRequestInfo, ListHostRequestsReply,
    ListHostsReply, RemoveHostReply, RemoveHostRequest, RevokeHostPrivateRequest,
};
use fleet_proto::{MAX_HOST_APPROVED_IPS, Reason};
use sqlx::{PgPool, Row};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tonic::Status;

use crate::cred::https::{FetchError, ForgeGet, ForgeReply, ForgeTransport, TlsError};
use crate::cred::pinned::{
    Dial, PinnedHttps, Resolve, SystemResolver, TcpDial, is_dns_host, is_private_range, vet_all,
};
use crate::cred::repo_limit::{CheckLimiter, MAX_CONCURRENT_REPO_CHECKS};

const VERSION_ACCEPT: &str = "application/json";

/// Locks one user row `FOR NO KEY UPDATE`.
///
/// Lock order of the host store: user row, then the table-wide advisory lock ([`LOCK_TOTAL`]),
/// then host rows. [`HostStore::add`] and [`HostStore::record_request`] take the user row first.
/// [`HostStore::approve`] takes [`LOCK_TOTAL`] first and then writes rows that reference a user
/// (`added_by`, `approved_by`, the audit row), and each such write takes `FOR KEY SHARE` on that
/// user row through the foreign key. `FOR UPDATE` conflicts with `FOR KEY SHARE`, so an add
/// holding the user row and waiting for the advisory lock deadlocked with an approve holding the
/// advisory lock and waiting for that user row. `FOR NO KEY UPDATE` still serialises one User's
/// adds and does not conflict with `FOR KEY SHARE`, so approve never waits on a user row.
const LOCK_USER: &str = "SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE";

const LOCK_TOTAL: &str = "SELECT pg_advisory_xact_lock(6850, 1)";

const LOCK_HOST: &str = "SELECT kind FROM git_hosts WHERE host = $1 FOR UPDATE";

macro_rules! columns {
    () => {
        "host, kind, allow_private, \
ARRAY(SELECT host(a) FROM unnest(approved_ips) AS a)::text[] AS approved_ips, \
added_by, approved_by, \
(EXTRACT(EPOCH FROM approved_at) * 1000)::bigint AS approved_ms, \
(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms"
    };
}

const SELECT_ONE: &str = concat!("SELECT ", columns!(), " FROM git_hosts WHERE host = $1");

const SELECT_ALL: &str = concat!("SELECT ", columns!(), " FROM git_hosts ORDER BY host");

const COUNT_BY_USER: &str = "SELECT count(*) FROM git_hosts WHERE added_by = $1";

const COUNT_ALL: &str = "SELECT count(*) FROM git_hosts";

const INSERT: &str = "INSERT INTO git_hosts (host, kind, added_by) VALUES ($1, $2, $3)";

const DELETE: &str = "DELETE FROM git_hosts WHERE host = $1";

const HAS_CREDENTIALS: &str = "SELECT EXISTS (SELECT 1 FROM credentials WHERE host = $1)";

const HAS_REPOSITORIES: &str = "SELECT EXISTS (SELECT 1 FROM user_repos WHERE host = $1)";

const INSERT_AUDIT: &str =
    "INSERT INTO host_audit (user_id, host, action, outcome) VALUES ($1, $2, $3, $4)";

const INSERT_AUDIT_ADDRESSES: &str = "INSERT INTO host_audit (user_id, host, action, outcome, addresses) \
VALUES ($1, $2, $3, $4, $5::text[]::inet[])";

const COUNT_PENDING_BY_USER: &str =
    "SELECT count(*) FROM git_host_requests WHERE user_id = $1 AND status = 'pending'";

const COUNT_PENDING_ALL: &str = "SELECT count(*) FROM git_host_requests WHERE status = 'pending'";

const HAS_PENDING: &str = "SELECT EXISTS (SELECT 1 FROM git_host_requests \
WHERE user_id = $1 AND host = $2 AND status = 'pending')";

const UPSERT_REQUEST: &str = "INSERT INTO git_host_requests (host, user_id, resolved) \
VALUES ($1, $2, $3::text[]::inet[]) \
ON CONFLICT (user_id, host) WHERE status = 'pending' DO UPDATE SET resolved = EXCLUDED.resolved";

const SELECT_PENDING: &str = "SELECT host, user_id, \
ARRAY(SELECT host(a) FROM unnest(resolved) AS a)::text[] AS resolved, \
(EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms \
FROM git_host_requests WHERE status = 'pending' ORDER BY id";

const CAN_APPROVE: &str = "SELECT EXISTS (SELECT 1 FROM git_hosts WHERE host = $1 AND kind = 'forgejo') \
OR EXISTS (SELECT 1 FROM git_host_requests WHERE host = $1 AND status = 'pending')";

const FIRST_REQUESTER: &str = "SELECT user_id FROM git_host_requests \
WHERE host = $1 AND status = 'pending' ORDER BY id LIMIT 1";

const GRANT: &str = "UPDATE git_hosts SET allow_private = true, approved_ips = $2::text[]::inet[], \
approved_by = $3, approved_at = now() WHERE host = $1";

const CLOSE_REQUESTS: &str =
    "UPDATE git_host_requests SET status = 'approved' WHERE host = $1 AND status = 'pending'";

const UNGRANT: &str = "UPDATE git_hosts SET allow_private = false, approved_ips = '{}', \
approved_by = NULL, approved_at = NULL WHERE host = $1";

const STALE_REPOS: &str = "UPDATE user_repos SET verified_at = to_timestamp(0) WHERE host = $1";

/// The private addresses of `resolved` an admin may approve, or `None`.
///
/// The set must hold at least one RFC 1918 or unique-local address and every address must pass
/// [`vet_all`] with the private ones approved. Loopback, link-local, metadata, CGNAT, multicast,
/// NAT64, 6to4 and every other range the address rule refuses fail the whole set. An empty set,
/// a set over [`crate::cred::pinned::MAX_ADDRESSES`] and a set with no private address have nothing to approve.
#[must_use]
pub fn private_grant(resolved: &[IpAddr]) -> Option<Vec<IpAddr>> {
    let private = canonical_set(
        resolved
            .iter()
            .copied()
            .filter(|ip| is_private_range(*ip))
            .collect(),
    );
    if private.is_empty() || vet_all(resolved, true, &private).is_err() {
        return None;
    }
    Some(private)
}

fn canonical_set(mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    for ip in &mut addrs {
        *ip = ip.to_canonical();
    }
    addrs.sort();
    addrs.dedup();
    addrs
}

fn texts(addrs: &[IpAddr]) -> Vec<String> {
    addrs.iter().map(ToString::to_string).collect()
}

/// One pending request for a private host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRow {
    /// The requested host.
    pub host: String,
    /// The User who tried to add it.
    pub user_id: i64,
    /// The addresses the host resolved to at the request.
    pub resolved: Vec<String>,
    /// When the request was made, in milliseconds since the Unix epoch.
    pub created_at_ms: i64,
}

/// The result of [`HostStore::approve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveOutcome {
    /// The grant was stored.
    Approved(HostRow),
    /// The table holds no forgejo row and no pending request for the host.
    Unknown,
    /// The host needed a new row and the table holds [`fleet_proto::MAX_HOSTS_TOTAL`] hosts.
    TableFull,
}

/// The result of [`HostStore::revoke`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The grant was cleared and the host's repositories were marked stale.
    Revoked(HostRow),
    /// The host held no grant. Nothing changed.
    NoGrant(HostRow),
    /// The table holds no forgejo row for the host.
    Unknown,
}

/// One row of `git_hosts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRow {
    /// The normalised host name.
    pub host: String,
    /// The stored kind, `github` or `forgejo`.
    pub kind: String,
    /// Whether an admin approved private addresses for the host.
    pub allow_private: bool,
    /// The private addresses an admin approved.
    pub approved_ips: Vec<String>,
    /// The User who added the host, `None` for a seeded row.
    pub added_by: Option<i64>,
    /// The admin who approved private addresses.
    pub approved_by: Option<i64>,
    /// When private addresses were approved, in milliseconds since the Unix epoch.
    pub approved_at_ms: Option<i64>,
    /// When the row was created, in milliseconds since the Unix epoch.
    pub created_at_ms: i64,
}

impl HostRow {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            host: row.try_get("host")?,
            kind: row.try_get("kind")?,
            allow_private: row.try_get("allow_private")?,
            approved_ips: row.try_get("approved_ips")?,
            added_by: row.try_get("added_by")?,
            approved_by: row.try_get("approved_by")?,
            approved_at_ms: row.try_get("approved_ms")?,
            created_at_ms: row.try_get("created_ms")?,
        })
    }

    fn into_info(self, reveal_addresses: bool) -> HostInfo {
        let unsigned = |value: i64| u64::try_from(value).unwrap_or_default();
        HostInfo {
            host: self.host,
            kind: self.kind,
            allow_private: self.allow_private,
            approved_ips: if reveal_addresses {
                self.approved_ips
            } else {
                Vec::new()
            },
            added_by: self.added_by.map_or(0, unsigned),
            approved_by: self.approved_by.map(unsigned),
            approved_at_ms: self.approved_at_ms.map(unsigned),
            created_at_ms: unsigned(self.created_at_ms),
        }
    }
}

/// The result of [`HostStore::add`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOutcome {
    /// A new row was inserted.
    Added(HostRow),
    /// The host was already in the table. Nothing was inserted.
    Exists(HostRow),
    /// The User holds [`fleet_proto::MAX_HOSTS_PER_USER`] hosts.
    UserFull,
    /// The table holds [`fleet_proto::MAX_HOSTS_TOTAL`] hosts.
    TableFull,
}

/// The result of [`HostStore::remove`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// The row was deleted.
    Removed,
    /// The table holds no such host.
    Unknown,
    /// The host has credentials, repositories, or is the built-in GitHub row.
    InUse,
}

/// Why a store operation failed. The text is fixed.
#[derive(Debug)]
pub enum HostStoreError {
    /// The acting user no longer exists.
    UserGone,
    /// The database failed.
    Db(sqlx::Error),
}

impl fmt::Display for HostStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UserGone => "user not found",
            Self::Db(_) => "host store database error",
        })
    }
}

impl std::error::Error for HostStoreError {}

impl From<sqlx::Error> for HostStoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Db(err)
    }
}

/// The `git_hosts` table and its audit rows.
#[derive(Clone)]
pub struct HostStore {
    pool: PgPool,
    max_per_user: usize,
    max_total: usize,
}

impl fmt::Debug for HostStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostStore(..)")
    }
}

impl HostStore {
    /// A store over `pool` with the caps [`fleet_proto::MAX_HOSTS_PER_USER`] and
    /// [`fleet_proto::MAX_HOSTS_TOTAL`].
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            max_per_user: fleet_proto::MAX_HOSTS_PER_USER,
            max_total: fleet_proto::MAX_HOSTS_TOTAL,
        }
    }

    /// Replaces the caps. Tests shrink them.
    #[must_use]
    pub fn with_caps(mut self, per_user: usize, total: usize) -> Self {
        self.max_per_user = per_user;
        self.max_total = total;
        self
    }

    /// The row for `host`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure.
    pub async fn find(&self, host: &HostName) -> Result<Option<HostRow>, HostStoreError> {
        let row = sqlx::query(SELECT_ONE)
            .bind(host.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(HostRow::from_row).transpose()?)
    }

    /// Every row, ordered by host.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure.
    pub async fn list(&self) -> Result<Vec<HostRow>, HostStoreError> {
        let rows = sqlx::query(SELECT_ALL).fetch_all(&self.pool).await?;
        Ok(rows
            .iter()
            .map(HostRow::from_row)
            .collect::<Result<_, _>>()?)
    }

    /// Writes one audit row outside any other write. Used for refusals decided before the store
    /// is reached.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure.
    pub async fn audit(
        &self,
        user_id: i64,
        host: &HostName,
        action: &str,
        outcome: &str,
    ) -> Result<(), HostStoreError> {
        sqlx::query(INSERT_AUDIT)
            .bind(user_id)
            .bind(host.as_str())
            .bind(action)
            .bind(outcome)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Writes one audit row that names `addresses`.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure.
    pub async fn audit_addresses(
        &self,
        user_id: i64,
        host: &HostName,
        action: &str,
        outcome: &str,
        addresses: &[IpAddr],
    ) -> Result<(), HostStoreError> {
        sqlx::query(INSERT_AUDIT_ADDRESSES)
            .bind(user_id)
            .bind(host.as_str())
            .bind(action)
            .bind(outcome)
            .bind(texts(addresses))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Records a pending request of `user_id` for `host` with the addresses it resolved to.
    ///
    /// One pending row exists per User and host: a repeat refreshes the addresses. A new row is
    /// skipped, with no error, when the User already holds the per-user cap of pending rows or
    /// the table holds the total cap. Returns whether a row now exists.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::UserGone`] when the user row is missing and
    /// [`HostStoreError::Db`] for a database failure.
    pub async fn record_request(
        &self,
        user_id: i64,
        host: &HostName,
        resolved: &[IpAddr],
    ) -> Result<bool, HostStoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(HostStoreError::UserGone)?;
        sqlx::query(LOCK_TOTAL).execute(&mut *tx).await?;
        let held: bool = sqlx::query_scalar(HAS_PENDING)
            .bind(user_id)
            .bind(host.as_str())
            .fetch_one(&mut *tx)
            .await?;
        let room = held
            || (!over(
                &mut tx,
                COUNT_PENDING_BY_USER,
                Some(user_id),
                self.max_per_user,
            )
            .await?
                && !over(&mut tx, COUNT_PENDING_ALL, None, self.max_total).await?);
        if room {
            sqlx::query(UPSERT_REQUEST)
                .bind(host.as_str())
                .bind(user_id)
                .bind(texts(resolved))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(room)
    }

    /// Every pending request, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure.
    pub async fn pending_requests(&self) -> Result<Vec<RequestRow>, HostStoreError> {
        let rows = sqlx::query(SELECT_PENDING).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| {
                Ok(RequestRow {
                    host: row.try_get("host")?,
                    user_id: row.try_get("user_id")?,
                    resolved: row.try_get("resolved")?,
                    created_at_ms: row.try_get("created_ms")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(Into::into)
    }

    /// Whether an approval of `host` has anything to act on: a forgejo row or a pending request.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure.
    pub async fn can_approve(&self, host: &HostName) -> Result<bool, HostStoreError> {
        Ok(sqlx::query_scalar(CAN_APPROVE)
            .bind(host.as_str())
            .fetch_one(&self.pool)
            .await?)
    }

    /// Stores the approval of `private` for `host` by the admin `admin_id`.
    ///
    /// One transaction takes the table-wide advisory lock the add path takes, then the host row
    /// `FOR UPDATE`, which is the lock a credential put takes `FOR SHARE` before it writes, so the
    /// order `git_hosts` before `credentials` holds. A host with no row gets one, of kind
    /// `forgejo`, owned by the first pending requester. The grant, the closing of every pending
    /// request for the host and the audit row naming `private` commit together.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure. Nothing is written on an error.
    pub async fn approve(
        &self,
        admin_id: i64,
        host: &HostName,
        private: &[IpAddr],
    ) -> Result<ApproveOutcome, HostStoreError> {
        let name = host.as_str();
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_TOTAL).execute(&mut *tx).await?;
        let existing = sqlx::query(LOCK_HOST)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = existing {
            let kind: String = row.try_get("kind")?;
            if HostKind::from_stored(&kind) != Some(HostKind::Forgejo) {
                return Ok(ApproveOutcome::Unknown);
            }
        } else {
            let requester: Option<i64> = sqlx::query_scalar(FIRST_REQUESTER)
                .bind(name)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(requester) = requester else {
                return Ok(ApproveOutcome::Unknown);
            };
            if over(&mut tx, COUNT_ALL, None, self.max_total).await? {
                return Ok(ApproveOutcome::TableFull);
            }
            sqlx::query(INSERT)
                .bind(name)
                .bind(HostKind::Forgejo.as_str())
                .bind(requester)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(GRANT)
            .bind(name)
            .bind(texts(private))
            .bind(admin_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(CLOSE_REQUESTS)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        sqlx::query(INSERT_AUDIT_ADDRESSES)
            .bind(admin_id)
            .bind(name)
            .bind("approve_private")
            .bind("approved")
            .bind(texts(private))
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(SELECT_ONE)
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
        let row = HostRow::from_row(&row)?;
        tx.commit().await?;
        Ok(ApproveOutcome::Approved(row))
    }

    /// Clears the grant of `host` for the admin `admin_id`.
    ///
    /// The host row is taken `FOR UPDATE` first. A granted host loses `allow_private` and
    /// `approved_ips`, every repository row on the host is marked stale by moving `verified_at` to
    /// the Unix epoch, and the audit row names the addresses that were approved. A host with no
    /// grant changes nothing and writes a `refused` audit row.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure. Nothing is written on an error.
    pub async fn revoke(
        &self,
        admin_id: i64,
        host: &HostName,
    ) -> Result<RevokeOutcome, HostStoreError> {
        let name = host.as_str();
        let mut tx = self.pool.begin().await?;
        let Some(locked) = sqlx::query(LOCK_HOST)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Ok(RevokeOutcome::Unknown);
        };
        let kind: String = locked.try_get("kind")?;
        if HostKind::from_stored(&kind) != Some(HostKind::Forgejo) {
            return Ok(RevokeOutcome::Unknown);
        }
        let row = sqlx::query(SELECT_ONE)
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
        let before = HostRow::from_row(&row)?;
        let audit = |outcome: &'static str, addresses: Vec<String>| {
            sqlx::query(INSERT_AUDIT_ADDRESSES)
                .bind(admin_id)
                .bind(name)
                .bind("revoke_private")
                .bind(outcome)
                .bind(addresses)
        };
        if !before.allow_private {
            audit("refused", Vec::new()).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(RevokeOutcome::NoGrant(before));
        }
        sqlx::query(UNGRANT).bind(name).execute(&mut *tx).await?;
        sqlx::query(STALE_REPOS)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        audit("revoked", before.approved_ips.clone())
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(SELECT_ONE)
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
        let after = HostRow::from_row(&row)?;
        tx.commit().await?;
        Ok(RevokeOutcome::Revoked(after))
    }

    /// Inserts `host` for `user_id` with its audit row in one transaction.
    ///
    /// The transaction takes `FOR NO KEY UPDATE` on the user row, which serialises that User's adds, and
    /// a transaction-scoped advisory lock that serialises every add, before it counts rows for
    /// either cap. A host already in the table is returned as [`AddOutcome::Exists`] and a cap
    /// refusal as [`AddOutcome::UserFull`] or [`AddOutcome::TableFull`]. Each outcome writes one
    /// audit row and commits it.
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::UserGone`] when the user row is missing and
    /// [`HostStoreError::Db`] for a database failure. Nothing is written on an error.
    pub async fn add(&self, user_id: i64, host: &Host) -> Result<AddOutcome, HostStoreError> {
        let name = host.name().as_str();
        let mut tx = self.pool.begin().await?;
        sqlx::query(LOCK_USER)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(HostStoreError::UserGone)?;
        sqlx::query(LOCK_TOTAL).execute(&mut *tx).await?;
        let existing = sqlx::query(SELECT_ONE)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
        let audit = |outcome: &'static str| {
            sqlx::query(INSERT_AUDIT)
                .bind(user_id)
                .bind(name)
                .bind("add")
                .bind(outcome)
        };
        let outcome = if let Some(row) = existing {
            audit("exists").execute(&mut *tx).await?;
            AddOutcome::Exists(HostRow::from_row(&row)?)
        } else if over(&mut tx, COUNT_BY_USER, Some(user_id), self.max_per_user).await? {
            audit("refused").execute(&mut *tx).await?;
            AddOutcome::UserFull
        } else if over(&mut tx, COUNT_ALL, None, self.max_total).await? {
            audit("refused").execute(&mut *tx).await?;
            AddOutcome::TableFull
        } else {
            sqlx::query(INSERT)
                .bind(name)
                .bind(host.kind().as_str())
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            audit("added").execute(&mut *tx).await?;
            let row = sqlx::query(SELECT_ONE)
                .bind(name)
                .fetch_one(&mut *tx)
                .await?;
            AddOutcome::Added(HostRow::from_row(&row)?)
        };
        tx.commit().await?;
        Ok(outcome)
    }

    /// Deletes `host` for the admin `admin_id` with its audit row in one transaction.
    ///
    /// The host row is taken `FOR UPDATE` first, the lock a credential put takes `FOR SHARE`
    /// before it writes. A put in flight therefore commits before the credential check runs, and
    /// a credential deleted in flight cannot block this call because the credential and
    /// repository reads take no row lock. A host with any credential row, tombstones included, or
    /// any repository row, and the built-in `github` row, is [`RemoveOutcome::InUse`].
    ///
    /// # Errors
    ///
    /// Returns [`HostStoreError::Db`] for a database failure. Nothing is deleted on an error.
    pub async fn remove(
        &self,
        admin_id: i64,
        host: &HostName,
    ) -> Result<RemoveOutcome, HostStoreError> {
        let name = host.as_str();
        let mut tx = self.pool.begin().await?;
        let audit = |outcome: &'static str| {
            sqlx::query(INSERT_AUDIT)
                .bind(admin_id)
                .bind(name)
                .bind("remove")
                .bind(outcome)
        };
        let Some(row) = sqlx::query(LOCK_HOST)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?
        else {
            audit("refused").execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(RemoveOutcome::Unknown);
        };
        let kind: String = row.try_get("kind")?;
        let builtin = HostKind::from_stored(&kind) != Some(HostKind::Forgejo);
        let credentials: bool = sqlx::query_scalar(HAS_CREDENTIALS)
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
        let repositories: bool = sqlx::query_scalar(HAS_REPOSITORIES)
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
        if builtin || credentials || repositories {
            audit("refused").execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(RemoveOutcome::InUse);
        }
        sqlx::query(DELETE).bind(name).execute(&mut *tx).await?;
        audit("removed").execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(RemoveOutcome::Removed)
    }
}

/// Parses the named address list. The raw count is checked against
/// [`MAX_HOST_APPROVED_IPS`] before duplicates are dropped, as the CLI does.
fn parse_named(named: &[String]) -> Option<Vec<IpAddr>> {
    if named.len() > MAX_HOST_APPROVED_IPS {
        return None;
    }
    let parsed: Result<Vec<IpAddr>, _> = named.iter().map(|text| text.parse::<IpAddr>()).collect();
    parsed.ok().map(canonical_set)
}

async fn over(
    tx: &mut sqlx::PgConnection,
    statement: &'static str,
    user_id: Option<i64>,
    cap: usize,
) -> Result<bool, sqlx::Error> {
    let query = sqlx::query_scalar::<_, i64>(statement);
    let held = match user_id {
        Some(id) => query.bind(id),
        None => query,
    }
    .fetch_one(tx)
    .await?;
    Ok(usize::try_from(held).map_or(true, |held| held >= cap))
}

/// Why a host add was refused. Each variant maps to one closed `FAILED_PRECONDITION` reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRefusal {
    /// The name is outside the grammar, resolves to a non-public address, or does not resolve.
    NotAllowedHost,
    /// The host does not answer as a Forgejo or Gitea server.
    NotForge,
    /// The host could not be reached or its reply was unusable.
    Unavailable,
    /// The probe ran out of its time budget.
    Timeout,
}

impl HostRefusal {
    /// The closed reason.
    #[must_use]
    pub const fn reason(self) -> Reason {
        match self {
            Self::NotAllowedHost => Reason::RepoNotAllowedHost,
            Self::NotForge => Reason::HostNotForge,
            Self::Unavailable => Reason::RepoUpstreamUnavailable,
            Self::Timeout => Reason::RepoTimeout,
        }
    }

    fn status(self) -> Status {
        let (code, message) = self.reason().status_parts();
        Status::new(code, message)
    }
}

const fn refusal_of(error: ForgeError) -> HostRefusal {
    match error {
        ForgeError::Rejected => HostRefusal::NotAllowedHost,
        ForgeError::WrongKind
        | ForgeError::Redirected
        | ForgeError::TooLarge
        | ForgeError::Malformed => HostRefusal::NotForge,
        ForgeError::Timeout => HostRefusal::Timeout,
        ForgeError::Unavailable
        | ForgeError::NotFound
        | ForgeError::NonFastForward
        | ForgeError::Unauthorized
        | ForgeError::HostMismatch => HostRefusal::Unavailable,
    }
}

/// Vets a host and asks it what kind of forge it is. Tests replace it with a fake.
#[tonic::async_trait]
pub trait HostProbe: Send + Sync {
    /// Resolves and vets `host`, then identifies it with no credential.
    ///
    /// # Errors
    ///
    /// Returns the closed [`HostRefusal`].
    async fn probe(&self, host: &HostName) -> Result<HostKind, HostRefusal>;

    /// Every address `host` resolves to now, or none when the lookup fails.
    async fn resolve(&self, host: &HostName) -> Vec<IpAddr>;

    /// Like [`HostProbe::probe`], but a private address passes when `approved` holds it.
    ///
    /// # Errors
    ///
    /// Returns the closed [`HostRefusal`].
    async fn probe_approved(
        &self,
        host: &HostName,
        approved: &[IpAddr],
    ) -> Result<HostKind, HostRefusal>;
}

/// The [`Http`] seam over a [`ForgeTransport`]: public addresses only, no credential, no redirect.
pub struct PinnedHttp<T> {
    transport: T,
    approved: Vec<IpAddr>,
}

impl<T> fmt::Debug for PinnedHttp<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedHttp(..)")
    }
}

impl<T: ForgeTransport> PinnedHttp<T> {
    /// An adapter that sends through `transport` and admits public addresses only.
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            approved: Vec::new(),
        }
    }

    /// An adapter that also admits the private addresses in `approved`, and no other.
    pub const fn approved(transport: T, approved: Vec<IpAddr>) -> Self {
        Self {
            transport,
            approved,
        }
    }
}

impl<T: ForgeTransport> Http for PinnedHttp<T> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        if request.header("authorization").is_some() {
            return Err(HttpError::HostRefused);
        }
        let accept = request.header("accept").unwrap_or(VERSION_ACCEPT);
        let reply = self
            .transport
            .get(&ForgeGet {
                host: request.host.as_str(),
                path: &request.path,
                allow_private: !self.approved.is_empty(),
                approved_ips: &self.approved,
                authorization: None,
                accept,
            })
            .await
            .map_err(|error| match error {
                FetchError::Blocked => HttpError::HostRefused,
                FetchError::Unavailable => HttpError::Reset,
                FetchError::TooLarge => HttpError::BodyTooLarge,
            })?;
        Ok(HttpResponse {
            status: reply.status.as_u16(),
            headers: reply
                .location
                .map(|value| ("Location".to_owned(), value))
                .into_iter()
                .collect(),
            body: reply.body,
        })
    }
}

struct Borrowed<'a, T>(&'a T);

#[tonic::async_trait]
impl<T: ForgeTransport> ForgeTransport for Borrowed<'_, T> {
    async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
        self.0.get(request).await
    }
}

/// The production [`HostProbe`]: [`is_dns_host`], one lookup vetted with [`vet_all`], then
/// `GiteaForge::identify` over the pinned connector.
///
/// [`HostProbe::probe`] admits public addresses only. [`HostProbe::probe_approved`] admits the
/// private addresses an admin approved and no other, through the same [`vet_all`] and the same
/// connector.
pub struct PinnedProbe<R, T> {
    resolver: R,
    transport: T,
}

impl<R, T> fmt::Debug for PinnedProbe<R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedProbe(..)")
    }
}

impl<R: Resolve, T: ForgeTransport> PinnedProbe<R, T> {
    /// A probe that vets through `resolver` and identifies through `transport`.
    pub const fn new(resolver: R, transport: T) -> Self {
        Self {
            resolver,
            transport,
        }
    }

    async fn vetted_identify(
        &self,
        host: &HostName,
        approved: &[IpAddr],
    ) -> Result<HostKind, HostRefusal> {
        if !is_dns_host(host.as_str()) {
            return Err(HostRefusal::NotAllowedHost);
        }
        let addrs = self
            .resolver
            .resolve(host.as_str())
            .await
            .map_err(|error| {
                tracing::warn!(host = %host, %error, "host lookup failed");
                HostRefusal::NotAllowedHost
            })?;
        vet_all(&addrs, !approved.is_empty(), approved).map_err(|error| {
            tracing::warn!(host = %host, %error, "host address refused");
            HostRefusal::NotAllowedHost
        })?;
        let http = PinnedHttp::approved(Borrowed(&self.transport), approved.to_vec());
        GiteaForge::new(http).identify(host).await.map_err(|error| {
            tracing::warn!(host = %host, %error, "host identify failed");
            refusal_of(error)
        })
    }
}

impl PinnedProbe<SystemResolver, PinnedHttps<SystemResolver, TcpDial>> {
    /// The production probe: system DNS, plain TCP and the bundled web roots.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] when the TLS stack cannot be set up.
    pub fn system() -> Result<Self, TlsError> {
        Ok(Self::new(SystemResolver, PinnedHttps::system()?))
    }
}

#[tonic::async_trait]
impl<R: Resolve, T: ForgeTransport> HostProbe for PinnedProbe<R, T> {
    async fn probe(&self, host: &HostName) -> Result<HostKind, HostRefusal> {
        self.vetted_identify(host, &[]).await
    }

    async fn resolve(&self, host: &HostName) -> Vec<IpAddr> {
        if !is_dns_host(host.as_str()) {
            return Vec::new();
        }
        self.resolver
            .resolve(host.as_str())
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(host = %host, %error, "host lookup failed");
                Vec::new()
            })
    }

    async fn probe_approved(
        &self,
        host: &HostName,
        approved: &[IpAddr],
    ) -> Result<HostKind, HostRefusal> {
        self.vetted_identify(host, approved).await
    }
}

/// Builds a probe over an injected resolver and dialer, for tests that drive the real vet path.
///
/// # Errors
///
/// Returns [`TlsError`] when the TLS stack cannot be set up.
pub fn pinned_probe<R, D>(resolver: R, dialer: D) -> Result<impl HostProbe, TlsError>
where
    R: Resolve + Clone + 'static,
    D: Dial + 'static,
{
    let tls = crate::cred::https::tls_config()?;
    Ok(PinnedProbe::new(
        resolver.clone(),
        PinnedHttps::new(resolver, dialer, tls),
    ))
}

/// The `FleetHosts` add, list and remove logic over a store, a probe and the check bounds.
#[derive(Clone)]
pub struct HostService {
    store: HostStore,
    probe: Arc<dyn HostProbe>,
    limiter: Arc<CheckLimiter>,
    permits: Arc<Semaphore>,
    budget: Duration,
}

impl fmt::Debug for HostService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostService(..)")
    }
}

fn store_status(error: &HostStoreError) -> Status {
    match error {
        HostStoreError::UserGone => Status::permission_denied(fleet_proto::ERR_NEEDS_USER_TOKEN),
        HostStoreError::Db(_) => {
            tracing::error!(%error, "host storage failed");
            Status::unavailable("storage unavailable")
        }
    }
}

impl HostService {
    /// A service over `store` that probes through `probe`, with the production check bounds.
    pub fn new(store: HostStore, probe: Arc<dyn HostProbe>) -> Self {
        Self {
            store,
            probe,
            limiter: Arc::new(CheckLimiter::system()),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REPO_CHECKS)),
            budget: REPO_CHECK_BUDGET,
        }
    }

    /// The production service over `pool`.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] when the TLS stack cannot be set up.
    pub fn system(pool: PgPool) -> Result<Self, TlsError> {
        Ok(Self::new(
            HostStore::new(pool),
            Arc::new(PinnedProbe::system()?),
        ))
    }

    /// Replaces the per-User check limiter. Pass the limiter of `RepoService` to share one
    /// window across repository checks and host adds. Tests inject a clock.
    #[must_use]
    pub fn with_limiter(mut self, limiter: Arc<CheckLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    /// Replaces the global cap on concurrent checks. Tests shrink it.
    #[must_use]
    pub fn with_concurrency(mut self, permits: usize) -> Self {
        self.permits = Arc::new(Semaphore::new(permits));
        self
    }

    /// Replaces the probe time budget. Tests shrink it.
    #[must_use]
    pub const fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// Adds a host for `user_id`.
    ///
    /// # Errors
    ///
    /// `FAILED_PRECONDITION` with one closed reason: `NOT_ALLOWED_HOST` for a name outside the
    /// grammar, `github.com`, a name that does not resolve and a name with any non-public
    /// address, `HOST_NOT_FORGE` for a host that does not answer as Forgejo or Gitea, and the
    /// upstream and timeout reasons for an unreachable or slow host. `RESOURCE_EXHAUSTED` past
    /// the per-User check rate, the concurrency cap, the per-User host cap or the table cap.
    /// `UNAVAILABLE` when storage fails. A refused add inserts no row.
    pub async fn add(&self, user_id: i64, request: &AddHostRequest) -> Result<HostInfo, Status> {
        let host = Host::user_added(&request.host).map_err(|error| {
            tracing::debug!(%error, "host add refused at normalise");
            HostRefusal::NotAllowedHost.status()
        })?;
        if !self.limiter.admit(user_id) {
            return Err(Status::resource_exhausted(
                fleet_proto::ERR_REPO_RATE_LIMITED,
            ));
        }
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| Status::resource_exhausted(fleet_proto::ERR_REPO_BUSY))?;
        if let Some(row) = self
            .store
            .find(host.name())
            .await
            .map_err(|error| store_status(&error))?
        {
            self.store
                .audit(user_id, host.name(), "add", "exists")
                .await
                .map_err(|error| store_status(&error))?;
            return Ok(row.into_info(false));
        }
        let verdict = timeout(self.budget, self.probe.probe(host.name()))
            .await
            .unwrap_or(Err(HostRefusal::Timeout));
        let refusal = match verdict {
            Ok(HostKind::Forgejo) => None,
            Ok(HostKind::Github) => Some(HostRefusal::NotForge),
            Err(refusal) => Some(refusal),
        };
        if let Some(refusal) = refusal {
            if let Err(error) = self
                .store
                .audit(user_id, host.name(), "add", "refused")
                .await
            {
                tracing::error!(%error, "host audit row failed");
            }
            if refusal == HostRefusal::NotAllowedHost {
                self.record_request(user_id, host.name()).await;
            }
            return Err(refusal.status());
        }
        match self
            .store
            .add(user_id, &host)
            .await
            .map_err(|error| store_status(&error))?
        {
            AddOutcome::Added(row) | AddOutcome::Exists(row) => Ok(row.into_info(false)),
            AddOutcome::UserFull | AddOutcome::TableFull => {
                Err(Status::resource_exhausted(fleet_proto::ERR_HOST_LIMIT))
            }
        }
    }

    async fn record_request(&self, user_id: i64, host: &HostName) {
        let resolved = timeout(self.budget, self.probe.resolve(host))
            .await
            .unwrap_or_default();
        if private_grant(&resolved).is_none() {
            return;
        }
        if let Err(error) = self.store.record_request(user_id, host, &resolved).await {
            tracing::error!(%error, "host request row failed");
        }
    }

    /// Approves the private addresses of a host for the admin `admin_id`.
    ///
    /// The host must have a forgejo row or a pending request. The host is resolved afresh, the
    /// named addresses must equal that set, and the set must pass [`private_grant`]. The host is
    /// then identified through the approved addresses only, and the grant, the request and the
    /// audit row commit together. A refusal after the resolve writes a `refused` audit row.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for a name outside the grammar, `github.com`, and a host with no row and no
    /// pending request. `FAILED_PRECONDITION` with `HOST_ADDRESS_MISMATCH` when the named set is
    /// not the fresh resolve, `NOT_ALLOWED_HOST` when the set has no approvable private address or
    /// holds a forbidden range, and the probe reasons when the host is not a forge.
    /// `RESOURCE_EXHAUSTED` at the concurrency cap or the table cap. `UNAVAILABLE` when storage
    /// fails.
    pub async fn approve(
        &self,
        admin_id: i64,
        request: &ApproveHostPrivateRequest,
    ) -> Result<HostInfo, Status> {
        let not_found = || Status::not_found(fleet_proto::ERR_HOST_NOT_FOUND);
        let host = HostName::normalise(&request.host).map_err(|_| not_found())?;
        if !self
            .store
            .can_approve(&host)
            .await
            .map_err(|error| store_status(&error))?
        {
            return Err(not_found());
        }
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| Status::resource_exhausted(fleet_proto::ERR_REPO_BUSY))?;
        let resolved = canonical_set(
            timeout(self.budget, self.probe.resolve(&host))
                .await
                .unwrap_or_default(),
        );
        let (audited_host, audited) = (&host, &resolved);
        let refuse = |reason: Reason| async move {
            if let Err(error) = self
                .store
                .audit_addresses(
                    admin_id,
                    audited_host,
                    "approve_private",
                    "refused",
                    audited,
                )
                .await
            {
                tracing::error!(%error, "host audit row failed");
            }
            let (code, message) = reason.status_parts();
            Status::new(code, message)
        };
        let named = parse_named(&request.approved_ips);
        if resolved.is_empty() || named.as_ref() != Some(&resolved) {
            return Err(refuse(Reason::HostAddressMismatch).await);
        }
        let Some(private) = private_grant(&resolved) else {
            return Err(refuse(Reason::RepoNotAllowedHost).await);
        };
        let verdict = timeout(self.budget, self.probe.probe_approved(&host, &private))
            .await
            .unwrap_or(Err(HostRefusal::Timeout));
        match verdict {
            Ok(HostKind::Forgejo) => {}
            Ok(HostKind::Github) => return Err(refuse(HostRefusal::NotForge.reason()).await),
            Err(refusal) => return Err(refuse(refusal.reason()).await),
        }
        match self
            .store
            .approve(admin_id, &host, &private)
            .await
            .map_err(|error| store_status(&error))?
        {
            ApproveOutcome::Approved(row) => Ok(row.into_info(true)),
            ApproveOutcome::Unknown => Err(not_found()),
            ApproveOutcome::TableFull => {
                Err(Status::resource_exhausted(fleet_proto::ERR_HOST_LIMIT))
            }
        }
    }

    /// Clears the private grant of a host for the admin `admin_id` and marks the repositories on
    /// the host stale.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for a name the table does not hold as a forgejo row, `UNAVAILABLE` when storage
    /// fails. A host with no grant is returned unchanged.
    pub async fn revoke(
        &self,
        admin_id: i64,
        request: &RevokeHostPrivateRequest,
    ) -> Result<HostInfo, Status> {
        let not_found = || Status::not_found(fleet_proto::ERR_HOST_NOT_FOUND);
        let host = HostName::normalise(&request.host).map_err(|_| not_found())?;
        match self
            .store
            .revoke(admin_id, &host)
            .await
            .map_err(|error| store_status(&error))?
        {
            RevokeOutcome::Revoked(row) | RevokeOutcome::NoGrant(row) => Ok(row.into_info(true)),
            RevokeOutcome::Unknown => Err(not_found()),
        }
    }

    /// Lists the pending requests for private hosts, oldest first.
    ///
    /// # Errors
    ///
    /// `UNAVAILABLE` when storage fails.
    pub async fn list_requests(&self) -> Result<ListHostRequestsReply, Status> {
        let unsigned = |value: i64| u64::try_from(value).unwrap_or_default();
        let requests = self
            .store
            .pending_requests()
            .await
            .map_err(|error| store_status(&error))?
            .into_iter()
            .map(|row| HostRequestInfo {
                host: row.host,
                requested_by: unsigned(row.user_id),
                resolved_ips: row.resolved,
                requested_at_ms: unsigned(row.created_at_ms),
            })
            .collect();
        Ok(ListHostRequestsReply { requests })
    }

    /// Lists every host. Approved private addresses go to an admin only.
    ///
    /// # Errors
    ///
    /// `UNAVAILABLE` when storage fails.
    pub async fn list(&self, is_admin: bool) -> Result<ListHostsReply, Status> {
        let hosts = self
            .store
            .list()
            .await
            .map_err(|error| store_status(&error))?
            .into_iter()
            .map(|row| row.into_info(is_admin))
            .collect();
        Ok(ListHostsReply { hosts })
    }

    /// Removes a host for the admin `admin_id`. The service layer has already checked the admin
    /// flag.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for a name the table does not hold, `FAILED_PRECONDITION` with
    /// `HOST_IN_USE` for a host with credentials or repositories and for the built-in GitHub row,
    /// `UNAVAILABLE` when storage fails.
    pub async fn remove(
        &self,
        admin_id: i64,
        request: &RemoveHostRequest,
    ) -> Result<RemoveHostReply, Status> {
        let not_found = || Status::not_found(fleet_proto::ERR_HOST_NOT_FOUND);
        let host = HostName::normalise(&request.host).map_err(|_| not_found())?;
        match self
            .store
            .remove(admin_id, &host)
            .await
            .map_err(|error| store_status(&error))?
        {
            RemoveOutcome::Removed => Ok(RemoveHostReply {}),
            RemoveOutcome::Unknown => Err(not_found()),
            RemoveOutcome::InUse => {
                let (code, message) = Reason::HostInUse.status_parts();
                Err(Status::new(code, message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;
    use std::sync::Mutex;

    use fleet_proto::MAX_HOSTS_PER_USER;
    use hyper::StatusCode;

    use super::*;
    use crate::cred::https::ForgeReply;

    struct Recorded {
        host: String,
        path: String,
        allow_private: bool,
        approved: usize,
        authorised: bool,
        accept: String,
    }

    struct FakeTransport {
        reply: Result<ForgeReply, FetchError>,
        seen: Mutex<Vec<Recorded>>,
    }

    #[derive(Clone)]
    struct Shared(Arc<FakeTransport>);

    #[tonic::async_trait]
    impl ForgeTransport for Shared {
        async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
            let this = &self.0;
            this.seen.lock().unwrap().push(Recorded {
                host: request.host.to_owned(),
                path: request.path.to_owned(),
                allow_private: request.allow_private,
                approved: request.approved_ips.len(),
                authorised: request.authorization.is_some(),
                accept: request.accept.to_owned(),
            });
            this.reply.clone()
        }
    }

    fn reply(status: u16, body: &str) -> ForgeReply {
        ForgeReply {
            status: StatusCode::from_u16(status).unwrap(),
            body: body.as_bytes().to_vec(),
            location: None,
        }
    }

    fn transport(reply: Result<ForgeReply, FetchError>) -> Shared {
        Shared(Arc::new(FakeTransport {
            reply,
            seen: Mutex::new(Vec::new()),
        }))
    }

    #[derive(Clone)]
    struct Resolver(io::ErrorKind, Vec<IpAddr>);

    #[tonic::async_trait]
    impl Resolve for Resolver {
        async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            if self.1.is_empty() {
                Err(io::Error::from(self.0))
            } else {
                Ok(self.1.clone())
            }
        }
    }

    fn public() -> Resolver {
        Resolver(
            io::ErrorKind::NotFound,
            vec!["93.184.216.34".parse().unwrap()],
        )
    }

    fn name() -> HostName {
        HostName::normalise("git.example.com").unwrap()
    }

    #[tokio::test]
    async fn identify_sends_a_blind_public_only_version_probe() {
        let fake = transport(Ok(reply(200, r#"{"version":"17.0.1"}"#)));
        let probe = PinnedProbe::new(public(), fake.clone());
        assert_eq!(probe.probe(&name()).await, Ok(HostKind::Forgejo));
        let seen = fake.0.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].host, "git.example.com");
        assert_eq!(seen[0].path, "/api/v1/version");
        assert!(!seen[0].allow_private);
        assert_eq!(seen[0].approved, 0);
        assert!(!seen[0].authorised);
        assert_eq!(seen[0].accept, "application/json");
    }

    #[tokio::test]
    async fn a_private_or_unresolvable_host_is_refused_before_any_request() {
        let private: Vec<IpAddr> = vec!["192.168.3.1".parse().unwrap()];
        let mixed: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ];
        let cases = [
            Resolver(io::ErrorKind::NotFound, private),
            Resolver(io::ErrorKind::NotFound, mixed),
            Resolver(io::ErrorKind::NotFound, Vec::new()),
        ];
        for resolver in cases {
            let fake = transport(Ok(reply(200, r#"{"version":"1"}"#)));
            let probe = PinnedProbe::new(resolver, fake.clone());
            assert_eq!(probe.probe(&name()).await, Err(HostRefusal::NotAllowedHost));
            assert!(fake.0.seen.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn every_forge_error_maps_to_one_refusal() {
        use ForgeError as E;
        let table = [
            (E::Rejected, HostRefusal::NotAllowedHost),
            (E::WrongKind, HostRefusal::NotForge),
            (E::Redirected, HostRefusal::NotForge),
            (E::TooLarge, HostRefusal::NotForge),
            (E::Malformed, HostRefusal::NotForge),
            (E::Timeout, HostRefusal::Timeout),
            (E::Unavailable, HostRefusal::Unavailable),
            (E::NotFound, HostRefusal::Unavailable),
            (E::NonFastForward, HostRefusal::Unavailable),
            (E::Unauthorized, HostRefusal::Unavailable),
            (E::HostMismatch, HostRefusal::Unavailable),
        ];
        for (error, refusal) in table {
            assert_eq!(refusal_of(error), refusal, "{error:?}");
        }
    }

    #[tokio::test]
    async fn transport_failures_map_to_closed_refusals() {
        let cases = [
            (Err(FetchError::Blocked), HostRefusal::NotAllowedHost),
            (Err(FetchError::Unavailable), HostRefusal::Unavailable),
            (Err(FetchError::TooLarge), HostRefusal::NotForge),
            (Ok(reply(301, "")), HostRefusal::NotForge),
            (Ok(reply(200, "<html>")), HostRefusal::NotForge),
            (Ok(reply(404, "")), HostRefusal::NotForge),
            (Ok(reply(503, "")), HostRefusal::Unavailable),
        ];
        for (answer, expected) in cases {
            let probe = PinnedProbe::new(public(), transport(answer));
            assert_eq!(probe.probe(&name()).await, Err(expected));
        }
    }

    #[tokio::test]
    async fn pinned_http_refuses_a_request_that_carries_a_credential() {
        let fake = transport(Ok(reply(200, "{}")));
        let http = PinnedHttp::new(fake.clone());
        let request = HttpRequest {
            method: fleet_forge::Method::Get,
            host: name(),
            path: "/api/v1/version".to_owned(),
            headers: vec![("authorization".to_owned(), "token x".to_owned())],
            body: Vec::new(),
        };
        assert_eq!(
            http.send(request).await.unwrap_err(),
            HttpError::HostRefused
        );
        assert!(fake.0.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn the_caps_are_the_wire_constants() {
        assert_eq!(MAX_HOSTS_PER_USER, 20);
    }
}

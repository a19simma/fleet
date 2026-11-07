//! The per-job credential book: holds, refreshes, leases and revokes the credentials of the jobs
//! on this box. See the parent module for the wire client and the failure reasons.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::credential::Secret;
use zeroize::Zeroizing;

use super::{
    CredentialClient, CredentialFailure, ERR_RATE_LIMITED, JobCredentials, RATE_RETRIES,
    RATE_RETRY_DELAY, REFRESH_RETRY_MS, REFRESH_SKEW_MS, REFRESH_SKEW_SLACK_MS, REFRESH_WINDOW_MS,
    Rejected,
};
use crate::revoke::{REVOKE_FAILED, Revoker};

/// The time source of the refresh decision, in milliseconds since the Unix epoch. A test
/// injects its own.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current time.
    fn now_ms(&self) -> u64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

#[derive(Debug)]
struct Held {
    credentials: Arc<JobCredentials>,
    attempt: u32,
    box_name: String,
    retry_at_ms: u64,
    skewed: bool,
    fetched_at_ms: u64,
    refused: Option<CredentialFailure>,
    generation: Arc<Generation>,
    turn: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Default)]
struct Generation {
    users: AtomicUsize,
    idle: tokio::sync::Notify,
}

impl Generation {
    async fn drained(&self, limit: Duration) {
        let wait = async {
            loop {
                let notified = self.idle.notified();
                if self.users.load(Ordering::SeqCst) == 0 {
                    return;
                }
                notified.await;
            }
        };
        let _ = tokio::time::timeout(limit, wait).await;
    }
}

struct Snapshot {
    credentials: Arc<JobCredentials>,
    attempt: u32,
    box_name: String,
    retry_at_ms: u64,
    skewed: bool,
    fetched_at_ms: u64,
    refused: Option<CredentialFailure>,
}

/// Fetches and holds the credentials of the jobs that run on this box.
#[derive(Debug)]
pub struct CredentialBook {
    client: CredentialClient,
    held: Mutex<HashMap<String, Held>>,
    clock: Arc<dyn Clock>,
    revoker: Option<Arc<Revoker>>,
    drain_limit: Duration,
    rate_retries: u32,
    rate_delay: Duration,
}

/// The longest a replaced token waits for the children that hold it before it is revoked.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(15 * 60);

/// A token resolved for one child, with the [`TokenLease`] that keeps it from being revoked.
///
/// Keep it until the child exits. Its `Debug` output never shows the token.
pub struct LeasedToken {
    token: String,
    lease: Option<TokenLease>,
}

impl LeasedToken {
    /// `token`, held by the `lease` the book gave for the job. The book leases any job it
    /// holds, a PAT job included, so `lease` is `None` when the runner has no book or the book holds nothing for the job.
    #[must_use]
    pub const fn new(token: String, lease: Option<TokenLease>) -> Self {
        Self { token, lease }
    }

    /// The token value, empty when the job holds no GitHub credential.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Whether a [`TokenLease`] backs the token.
    #[must_use]
    pub const fn is_leased(&self) -> bool {
        self.lease.is_some()
    }
}

impl fmt::Debug for LeasedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeasedToken")
            .field("leased", &self.lease.is_some())
            .finish_non_exhaustive()
    }
}

/// The future a [`TokenSource`] returns.
pub type LeaseFuture<'a> =
    Pin<Box<dyn Future<Output = Result<LeasedToken, CredentialFailure>> + Send + 'a>>;

/// Resolves the GitHub token of one job at the moment a child starts.
///
/// A holder of a copy of the token breaks after the first refresh: the book revokes the token
/// a refresh replaced. Every child that carries the token resolves it here instead, once per
/// start, and keeps the returned [`LeasedToken`] until it exits.
pub trait TokenSource: Send + Sync + fmt::Debug {
    /// Refreshes the token when it is due, then returns the current one with its lease.
    ///
    /// # Errors
    ///
    /// Returns the [`CredentialFailure`] of [`CredentialBook::refresh_if_due`]: `MintCap`,
    /// `InstallationRefused`, `RepoRefused`, `LeaseMismatch`, `NoGithub`, `NoAgent`,
    /// `NotConfigured`, `Malformed`, `AppIdentityMissing`, `AppIdentityInvalid`, or
    /// `Unavailable` or `Expired` once the held token is no longer usable. The caller fails the
    /// step and never falls back to another token.
    fn lease(&self) -> LeaseFuture<'_>;
}

/// A hold on the credentials a child was started with.
///
/// The book only revokes an installation token, so a lease on a PAT job holds nothing back.
/// While a lease is alive the book does not revoke the token a refresh replaced, up to
/// [`DRAIN_LIMIT`]: the child keeps the old value in its environment and would fail mid-run
/// on a revoked token. Dropping the lease lets the revoke go ahead once every lease of that
/// token has dropped.
#[derive(Debug)]
pub struct TokenLease {
    generation: Arc<Generation>,
}

impl Drop for TokenLease {
    fn drop(&mut self) {
        if self.generation.users.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.generation.idle.notify_waiters();
        }
    }
}

impl CredentialBook {
    /// An empty book that fetches through `client`.
    #[must_use]
    pub fn new(client: CredentialClient) -> Self {
        Self {
            client,
            held: Mutex::new(HashMap::new()),
            clock: Arc::new(SystemClock),
            revoker: None,
            drain_limit: DRAIN_LIMIT,
            rate_retries: RATE_RETRIES,
            rate_delay: RATE_RETRY_DELAY,
        }
    }

    /// Replaces the longest wait of a replaced token for the children that hold it,
    /// [`DRAIN_LIMIT`] by default. A seam for tests.
    #[must_use]
    pub const fn with_drain_limit(mut self, limit: Duration) -> Self {
        self.drain_limit = limit;
        self
    }

    /// The credentials held for `job_id` and a [`TokenLease`] on the same token, taken in one
    /// step so no refresh can swap between the read and the lease. `None` when the book holds
    /// nothing for the job.
    ///
    /// Keep the lease until the child exits. The job end revokes the held token without waiting
    /// for any lease.
    #[must_use]
    pub fn lease_held(&self, job_id: &str) -> Option<(Arc<JobCredentials>, TokenLease)> {
        let guard = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let lease = guard.get(job_id).map(|entry| {
            entry.generation.users.fetch_add(1, Ordering::SeqCst);
            (
                Arc::clone(&entry.credentials),
                TokenLease {
                    generation: Arc::clone(&entry.generation),
                },
            )
        });
        drop(guard);
        lease
    }

    /// Attaches the client that revokes installation tokens. Without one nothing is revoked.
    #[must_use]
    pub fn with_revoker(mut self, revoker: Arc<Revoker>) -> Self {
        self.revoker = Some(revoker);
        self
    }

    /// Replaces how a first fetch waits out the per-minute mint limit: `retries` more asks,
    /// `delay` apart. [`RATE_RETRIES`] and [`RATE_RETRY_DELAY`] by default.
    #[must_use]
    pub const fn with_rate_retry(mut self, retries: u32, delay: Duration) -> Self {
        self.rate_retries = retries;
        self.rate_delay = delay;
        self
    }

    /// Replaces the clock the refresh decision reads, [`SystemClock`] by default.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Fetches the credentials of a claimed job and holds them under its id.
    ///
    /// Call it once the lease is held and before the agent starts. A fetch first ends any
    /// entry held for the same id and revokes its installation token, so a second fetch
    /// replaces the first and a failed one leaves nothing readable.
    ///
    /// # Errors
    ///
    /// Returns the failure whose [`CredentialFailure::reason`] the job reports. Nothing is
    /// held for `job_id` after an error. The server's answer maps to
    /// [`CredentialFailure::LeaseMismatch`] (any `PERMISSION_DENIED`),
    /// [`CredentialFailure::NoGithub`], [`CredentialFailure::NoAgent`],
    /// [`CredentialFailure::Expired`], [`CredentialFailure::NotConfigured`],
    /// [`CredentialFailure::MintCap`], [`CredentialFailure::RateLimited`],
    /// [`CredentialFailure::InstallationRefused`] and
    /// [`CredentialFailure::RepoRefused`]. A `RateLimited` answer is waited out
    /// [`RATE_RETRIES`] times, [`RATE_RETRY_DELAY`] apart, before it is returned. Any other
    /// status, a timeout or a transport error is [`CredentialFailure::Unavailable`]. A reply that
    /// breaks a rule is
    /// [`CredentialFailure::Malformed`], [`CredentialFailure::AppIdentityMissing`] or
    /// [`CredentialFailure::AppIdentityInvalid`]; the well-formed installation token in such a
    /// reply is revoked, because the server already minted and committed it. A reply that holds no
    /// GitHub credential or no agent credential is [`CredentialFailure::NoGithub`] or
    /// [`CredentialFailure::NoAgent`], the same as the server's own answer.
    pub async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<Arc<JobCredentials>, CredentialFailure> {
        self.end(job_id);
        let credentials = Arc::new(self.fetch_waiting(job_id, attempt, box_name).await?);
        let fetched_at_ms = self.clock.now_ms();
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                job_id.to_owned(),
                Held {
                    credentials: Arc::clone(&credentials),
                    attempt,
                    box_name: box_name.to_owned(),
                    retry_at_ms: 0,
                    refused: None,
                    skewed: false,
                    fetched_at_ms,
                    generation: Arc::new(Generation::default()),
                    turn: Arc::new(tokio::sync::Mutex::new(())),
                },
            );
        Ok(credentials)
    }

    /// Asks the server for a new installation token when fewer than [`REFRESH_WINDOW_MS`] of
    /// the held one remain, and swaps it in. Returns the new credentials when it swapped and
    /// `None` when nothing was due, the job holds no installation token, the retry wait has
    /// not passed, or a transient failure left the last good token in place.
    ///
    /// Call it before every use of the token. Calls for one job serialize, so two steps that
    /// find the token due make one request. Nothing is due while the retry wait has not passed:
    /// after a failure the next request waits [`REFRESH_RETRY_MS`].
    ///
    /// A fresh token that already looks expired, or inside the window, means the box clock runs
    /// ahead of the server's. The book takes it, marks the entry skewed and refreshes it again
    /// only after [`REFRESH_SKEW_MS`]. A skewed token counts as usable until
    /// [`REFRESH_SKEW_MS`] plus [`REFRESH_SKEW_SLACK_MS`] have passed since it was fetched.
    ///
    /// The old value is not forgotten by the book: the caller keeps it in the job redactor.
    /// With a [`Revoker`] attached, a swap revokes the replaced token on its own task, after
    /// every [`TokenLease`] on it has dropped or [`DRAIN_LIMIT`] has passed.
    ///
    /// This is [`CredentialBook::refresh_if_due_with`] with no hook.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialFailure::MintCap`] when the server's per-Job mint cap is reached,
    /// [`CredentialFailure::InstallationRefused`] or
    /// [`CredentialFailure::RepoRefused`] when the allowlists now refuse the installation or
    /// the repository, and any other server refusal as the variant [`CredentialBook::fetch`]
    /// maps it to ([`CredentialFailure::LeaseMismatch`] for a lost lease or a capability that
    /// is gone, [`CredentialFailure::NoGithub`], [`CredentialFailure::NoAgent`],
    /// [`CredentialFailure::NotConfigured`]). A reply with a bad identity returns
    /// [`CredentialFailure::AppIdentityMissing`] or
    /// [`CredentialFailure::AppIdentityInvalid`], and the well-formed installation token in that reply is
    /// revoked, as is the token of a [`CredentialFailure::Malformed`] reply and the fresh token
    /// of a reply whose swap `refreshed` refuses. None of these keeps the old token or falls back
    /// to a PAT; the caller fails the step. A transient failure,
    /// [`CredentialFailure::Unavailable`], the server's
    /// [`CredentialFailure::Expired`] or the per-User [`CredentialFailure::RateLimited`], returns
    /// `Ok(None)` while the held token is usable and keeps it. Once it is not usable, an
    /// entry that is not skewed returns
    /// [`CredentialFailure::Unavailable`] and a skewed entry returns
    /// [`CredentialFailure::Expired`], whichever transient failure it was. A skewed entry has
    /// no expiry the box clock can judge, so it counts as usable until [`REFRESH_SKEW_MS`]
    /// plus [`REFRESH_SKEW_SLACK_MS`] have passed since it was fetched. A recorded retry wait more
    /// than [`REFRESH_SKEW_MS`] ahead of the clock (the stale-wait guard, `wait_is_stale`) is
    /// ignored and the refresh goes ahead, so a clock that moved back cannot hold it off for
    /// longer than that. An allowlist refusal ([`CredentialFailure::InstallationRefused`] or
    /// [`CredentialFailure::RepoRefused`]) is sticky: the entry records it, and every later
    /// call returns it with no fetch and no retry wait, so the held token is not reused for the
    /// rest of the job. [`CredentialFailure::Malformed`] is returned when the reply holds no
    /// installation token or no expiry, or breaks any other reply rule.
    ///
    /// Returns `Ok(None)` when no refresh was due, and also when a `fetch` for the same job id
    /// replaced the entry while the refresh ran: the fresh token is then revoked and stored
    /// nowhere.
    pub async fn refresh_if_due(
        &self,
        job_id: &str,
    ) -> Result<Option<Arc<JobCredentials>>, CredentialFailure> {
        self.refresh_if_due_with(job_id, |_| {}).await
    }

    /// [`CredentialBook::refresh_if_due`] with a hook that sees the new credentials before the
    /// book makes them readable.
    ///
    /// `before_swap` runs once per successful refresh, under the job's refresh lock, after the
    /// reply is validated and before [`CredentialBook::get`] can return the new token. The
    /// caller uses it to add the new value to the job redactor, so no step reads a token that
    /// is not yet masked. It runs even when the job ended during the call. When the job ended
    /// the book revokes the token it just got, because nothing will hold it.
    ///
    /// # Errors
    ///
    /// The same variants as [`CredentialBook::refresh_if_due`], with the same skewed-entry rule
    /// and stale-wait guard: `MintCap`, `InstallationRefused`, `RepoRefused`, `LeaseMismatch`,
    /// `NoGithub`, `NoAgent`, `NotConfigured`, `Malformed`, `AppIdentityMissing`,
    /// `AppIdentityInvalid`, and `Unavailable` or `Expired` once the held token is not usable.
    pub async fn refresh_if_due_with(
        &self,
        job_id: &str,
        before_swap: impl FnOnce(&JobCredentials),
    ) -> Result<Option<Arc<JobCredentials>>, CredentialFailure> {
        let Some(turn) = self.turn(job_id) else {
            return Ok(None);
        };
        let _turn = turn.lock().await;
        let now = self.clock.now_ms();
        let Some(Snapshot {
            credentials: current,
            attempt,
            box_name,
            retry_at_ms,
            skewed,
            fetched_at_ms,
            refused,
        }) = self.snapshot(job_id)
        else {
            return Ok(None);
        };
        if let Some(refused) = refused {
            return Err(refused);
        }
        let Some(expiry) = current.app_expires_at_ms() else {
            return Ok(None);
        };
        if expiry.saturating_sub(now) >= REFRESH_WINDOW_MS {
            return Ok(None);
        }
        let usable = if skewed {
            now < fetched_at_ms
                .saturating_add(REFRESH_SKEW_MS)
                .saturating_add(REFRESH_SKEW_SLACK_MS)
        } else {
            now < expiry
        };
        let lapsed = if skewed {
            CredentialFailure::Expired
        } else {
            CredentialFailure::Unavailable
        };
        let wait_is_stale = retry_at_ms.saturating_sub(now) > REFRESH_SKEW_MS;
        if now < retry_at_ms && !wait_is_stale {
            return if usable { Ok(None) } else { Err(lapsed) };
        }
        let renewed = match self.fetch_checked(job_id, attempt, &box_name).await {
            Ok(fresh) => self.renewed(&current, &fresh),
            Err(failure) => Err(failure),
        };
        match renewed {
            Ok(next) => {
                let skew = next
                    .app_expires_at_ms()
                    .is_some_and(|at| at.saturating_sub(now) < REFRESH_WINDOW_MS);
                let next = Arc::new(next);
                before_swap(&next);
                let retry_at_ms = if skew { now + REFRESH_SKEW_MS } else { 0 };
                let replaced = self.store(job_id, &turn, Arc::clone(&next), retry_at_ms, skew, now);
                if let Some(generation) = &replaced {
                    self.revoke_replaced(&current, &next, generation);
                } else {
                    self.revoke_app_token(&next, None);
                }
                Ok(replaced.map(|_| next))
            }
            Err(failure) => {
                if matches!(
                    failure,
                    CredentialFailure::InstallationRefused | CredentialFailure::RepoRefused
                ) {
                    self.refuse(job_id, failure);
                } else {
                    self.back_off(job_id, now + REFRESH_RETRY_MS);
                }
                let transient = matches!(
                    failure,
                    CredentialFailure::Unavailable
                        | CredentialFailure::Expired
                        | CredentialFailure::RateLimited
                );
                if usable && transient {
                    tracing::warn!(
                        reason = failure.reason(),
                        "token refresh failed, keeping the held token"
                    );
                    Ok(None)
                } else if transient {
                    Err(lapsed)
                } else {
                    Err(failure)
                }
            }
        }
    }

    async fn fetch_waiting(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<JobCredentials, CredentialFailure> {
        let mut retries = self.rate_retries;
        loop {
            match self.fetch_checked(job_id, attempt, box_name).await {
                Err(CredentialFailure::RateLimited) if retries > 0 => {
                    retries -= 1;
                    tracing::warn!(
                        reason = ERR_RATE_LIMITED,
                        "first credential fetch rate limited, retrying"
                    );
                    tokio::time::sleep(self.rate_delay).await;
                }
                other => return other,
            }
        }
    }

    async fn fetch_checked(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<JobCredentials, CredentialFailure> {
        match self.client.fetch(job_id, attempt, box_name).await {
            Ok(credentials) => Ok(credentials),
            Err(Rejected { failure, tokens }) => {
                for token in tokens {
                    self.revoke_value(token, None);
                }
                Err(failure)
            }
        }
    }

    fn renewed(
        &self,
        current: &JobCredentials,
        fresh: &JobCredentials,
    ) -> Result<JobCredentials, CredentialFailure> {
        current
            .refreshed(fresh)
            .inspect_err(|_| self.revoke_app_token(fresh, None))
    }

    fn turn(&self, job_id: &str) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(job_id)
            .map(|entry| Arc::clone(&entry.turn))
    }

    fn snapshot(&self, job_id: &str) -> Option<Snapshot> {
        let guard = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let snap = guard.get(job_id).map(|entry| Snapshot {
            credentials: Arc::clone(&entry.credentials),
            attempt: entry.attempt,
            box_name: entry.box_name.clone(),
            retry_at_ms: entry.retry_at_ms,
            skewed: entry.skewed,
            fetched_at_ms: entry.fetched_at_ms,
            refused: entry.refused,
        });
        drop(guard);
        snap
    }

    fn revoke_replaced(
        &self,
        old: &JobCredentials,
        new: &JobCredentials,
        generation: &Arc<Generation>,
    ) {
        if old.app_token().map(Secret::expose) != new.app_token().map(Secret::expose) {
            self.revoke_app_token(old, Some(Arc::clone(generation)));
        }
    }

    fn revoke_app_token(&self, credentials: &JobCredentials, drain: Option<Arc<Generation>>) {
        let Some(token) = credentials.app_token() else {
            return;
        };
        let Ok(token) = std::str::from_utf8(token.expose()).map(|t| Zeroizing::new(t.to_owned()))
        else {
            return;
        };
        self.revoke_value(token, drain);
    }

    fn revoke_value(&self, token: Zeroizing<String>, drain: Option<Arc<Generation>>) {
        let Some(revoker) = &self.revoker else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(reason = REVOKE_FAILED, "no runtime to revoke the token");
            return;
        };
        let revoker = Arc::clone(revoker);
        let limit = self.drain_limit;
        drop(runtime.spawn(async move {
            if let Some(generation) = drain {
                generation.drained(limit).await;
            }
            if revoker.revoke(&token).await.is_err() {
                tracing::warn!(reason = REVOKE_FAILED, "token revoke failed");
            }
        }));
    }

    fn store(
        &self,
        job_id: &str,
        turn: &Arc<tokio::sync::Mutex<()>>,
        next: Arc<JobCredentials>,
        retry_at_ms: u64,
        skewed: bool,
        fetched_at_ms: u64,
    ) -> Option<Arc<Generation>> {
        let mut guard = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let replaced = guard
            .get_mut(job_id)
            .filter(|entry| Arc::ptr_eq(&entry.turn, turn))
            .map(|entry| {
                entry.credentials = next;
                entry.retry_at_ms = retry_at_ms;
                entry.skewed = skewed;
                entry.fetched_at_ms = fetched_at_ms;
                std::mem::take(&mut entry.generation)
            });
        drop(guard);
        replaced
    }

    fn refuse(&self, job_id: &str, failure: CredentialFailure) {
        if let Some(entry) = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(job_id)
        {
            entry.refused = Some(failure);
        }
    }

    fn back_off(&self, job_id: &str, retry_at_ms: u64) {
        if let Some(entry) = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(job_id)
        {
            entry.retry_at_ms = retry_at_ms;
        }
    }

    /// The credentials held for `job_id`.
    #[must_use]
    pub fn get(&self, job_id: &str) -> Option<Arc<JobCredentials>> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(job_id)
            .map(|entry| Arc::clone(&entry.credentials))
    }

    /// Drops the credentials of `job_id`. The buffers zero when the last borrower lets go.
    /// Dropping an id that is not held does nothing. Does not revoke an installation token; see
    /// [`CredentialBook::end`].
    pub fn forget(&self, job_id: &str) {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }

    /// Drops the credentials of `job_id` and revokes the installation token it held, on its own
    /// task and best effort (ADR-0058, SEC-010). A PAT job, an unknown id and a second call
    /// revoke nothing.
    pub fn end(&self, job_id: &str) {
        let removed = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
        if let Some(entry) = removed {
            self.revoke_app_token(&entry.credentials, None);
        }
    }

    /// The job end hook: pass it to [`crate::runner::JobEnd::on_end`]. It runs
    /// [`CredentialBook::end`], so it revokes the held installation token.
    pub fn end_hook(self: &Arc<Self>) -> impl Fn(&str) + Send + Sync + 'static {
        let book = Arc::clone(self);
        move |job_id| book.end(job_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialBook, RATE_RETRIES, RATE_RETRY_DELAY};
    use crate::cred::{Credential, CredentialClient, JobCredentials};
    use crate::revoke::Revoker;
    use fleet_core::credential::{CredentialKind, Secret};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn a_new_book_waits_out_the_rate_limit_longer_than_its_window() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let book = CredentialBook::new(CredentialClient::new(channel, "tok").unwrap());
        assert_eq!(book.rate_retries, RATE_RETRIES);
        assert_eq!(book.rate_delay, RATE_RETRY_DELAY);
        let waited = book.rate_delay * book.rate_retries;
        assert!(waited > Duration::from_secs(60), "{waited:?}");
        assert!(waited <= Duration::from_secs(120), "{waited:?}");
    }

    #[tokio::test]
    async fn a_refresh_whose_swap_fails_revokes_the_token_it_got() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0_u8; 512];
                let _ = stream.read(&mut buf).await;
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let client = CredentialClient::new(channel, "tok").unwrap();
        let book = CredentialBook::new(client).with_revoker(Arc::new(
            Revoker::plain(addr).with_timeout(Duration::from_millis(300)),
        ));
        let held = JobCredentials {
            items: Vec::new(),
            identity: None,
        };
        let fresh = JobCredentials {
            items: vec![Credential {
                kind: CredentialKind::GithubApp,
                value: Arc::new(Secret::new("ghs_Fresh0123456789".to_owned())),
                expires_at_ms: None,
            }],
            identity: None,
        };
        assert!(book.renewed(&held, &fresh).is_err());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while hits.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "no revoke arrived");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

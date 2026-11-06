//! Job credentials: the `GetJobCredentials` client and the per-job holder.
//!
//! A [`CredentialBook`] asks the server for the credentials of one claimed job, holds them in
//! memory under the job id and drops them when the job ends. Nothing here writes a value to
//! disk, to a log or to an error. A value lives in a [`Secret`], which zeroes its buffer on
//! drop and prints as `[REDACTED]`.
//!
//! The call is authorised by the job lease (ADR-0033), so the caller fetches only after the
//! claim is held and before the agent starts. The server's fixed refusals map to one
//! [`CredentialFailure`] each, and each failure has a fixed reason the job report carries.
//! There is no fallback to a box credential on any failure.
//!
//! A GitHub App job holds an installation token under wire kind `github_installation_token`
//! and the bot [`BotIdentity`] the server sent with it (ADR-0058). The token takes the place of
//! the PAT as the git and `gh` token. fleetd validates the identity again with
//! [`BotIdentity::new`] and fails the job before any clone when the identity is missing or
//! outside the grammar.
//!
//! An installation token lasts one hour. [`CredentialBook::refresh_if_due`] calls
//! `GetJobCredentials` again when fewer than [`REFRESH_WINDOW_MS`] of the held token remain,
//! on the injected [`Clock`], and swaps in the new token. A refresh that fails with a transient
//! reason keeps the last good token until it expires. The server's mint cap is terminal: it
//! fails the step with [`ERR_MINT_CAP`] and there is no PAT fallback (ADR-0058, SEC-004).
//!
//! With a [`Revoker`] attached the book revokes the token a refresh replaced, and the held
//! token when the job ends (ADR-0058, SEC-010). Each revoke runs on its own task, is best effort
//! and never fails the job; a failure logs [`REVOKE_FAILED`] and nothing else. A PAT job revokes
//! nothing.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_core::credential::{
    BotIdentity, CredentialKind, CredentialShape, MAX_CREDENTIAL_LEN, MIN_CREDENTIAL_LEN, Secret,
};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{GetJobCredentialsReply, GetJobCredentialsRequest};
use fleet_proto::{
    GITHUB_INSTALLATION_TOKEN_KIND, MAX_CREDENTIAL_VALUE_BYTES, MAX_CREDENTIALS_PER_USER,
    PRECONDITION_APP_MINT_CAP, PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB,
    PRECONDITION_NOT_CONFIGURED,
};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};
use zeroize::Zeroizing;

use crate::Error;
use crate::poller::{CALL_BACKSTOP, TOKEN_ENV};
use crate::revoke::{REVOKE_FAILED, Revoker};

/// Largest `GetJobCredentials` reply the client decodes, in bytes: the most credentials one
/// user holds, each at the longest value plus 64 bytes of framing and field overhead.
pub const MAX_REPLY_BYTES: usize = MAX_CREDENTIALS_PER_USER * (MAX_CREDENTIAL_VALUE_BYTES + 64);

const _: () = assert!(MAX_REPLY_BYTES >= MAX_CREDENTIALS_PER_USER * MAX_CREDENTIAL_VALUE_BYTES);
const _: () = assert!(MAX_REPLY_BYTES < 1024 * 1024);

/// Job failure reason: the server says the lease does not match.
pub const ERR_LEASE: &str = "credentials refused: lease does not match";

/// Job failure reason: the owner stored no GitHub credential.
pub const ERR_NO_GITHUB: &str = "no github credential";

/// Job failure reason: the owner stored no credential for the job's agent.
pub const ERR_NO_AGENT: &str = "no agent credential";

/// Job failure reason: a credential the job needs has expired.
pub const ERR_EXPIRED: &str = "credential expired";

/// Job failure reason: the server runs without a credential store.
pub const ERR_NOT_CONFIGURED: &str = "credentials are not configured";

/// Job failure reason: the call failed or timed out.
pub const ERR_UNAVAILABLE: &str = "credentials could not be fetched";

/// Job failure reason: the reply carries a GitHub App installation token and no git identity.
pub const ERR_APP_IDENTITY_MISSING: &str = "github app credential has no git identity";

/// Job failure reason: the git identity of a GitHub App credential is outside the grammar.
pub const ERR_APP_IDENTITY_INVALID: &str = "github app git identity is invalid";

/// Prefix of every GitHub App installation token.
const APP_TOKEN_PREFIX: &str = "ghs_";

/// Job failure reason: the Job reached its mint cap or its User reached the per-minute mint
/// limit (ADR-0058, SEC-003, SEC-004, SEC-011).
pub const ERR_MINT_CAP: &str = "github app token limit reached";

/// Refresh the installation token when fewer than this many milliseconds remain: 10 minutes
/// (ADR-0058, Lifetime and refresh). Exactly this much left is not yet due.
pub const REFRESH_WINDOW_MS: u64 = 10 * 60 * 1000;

/// The wait after a failed refresh.
///
/// It also applies after a refresh that returned a token still inside the window. It keeps a
/// failing server from being asked once per step and the Job's mint cap from being spent on
/// retries.
pub const REFRESH_RETRY_MS: u64 = 30 * 1000;

/// Job failure reason: the reply broke a rule the server keeps.
pub const ERR_MALFORMED: &str = "credentials reply was invalid";

/// Why a job could not get its credentials. Each variant has one fixed reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailure {
    /// `PERMISSION_DENIED`: wrong box, wrong attempt, lost lease or unknown job.
    LeaseMismatch,
    /// `FAILED_PRECONDITION` `no github credential`.
    NoGithub,
    /// `FAILED_PRECONDITION` `no agent credential`.
    NoAgent,
    /// `FAILED_PRECONDITION` `credential expired`.
    Expired,
    /// `FAILED_PRECONDITION` `credentials are not configured`.
    NotConfigured,
    /// `FAILED_PRECONDITION` `github app token limit reached`: the Job reached its mint cap
    /// or its User reached the per-minute mint limit (SEC-003, SEC-004, SEC-011). Terminal,
    /// never retried.
    MintCap,
    /// Any other status, a timeout or a transport error.
    Unavailable,
    /// The reply carries wire kind `github_installation_token` and no git identity.
    AppIdentityMissing,
    /// The git identity that came with an installation token is outside the grammar of
    /// ADR-0058 (SEC-006, SEC-012).
    AppIdentityInvalid,
    /// The reply held an unknown kind or shape, a bad value, a duplicate kind, or lacked the
    /// GitHub or agent credential. It is also this variant when an installation token does not
    /// start with `ghs_` followed by alphanumerics or underscores, when the reply holds two
    /// forge credentials, when a credential has the wire kind `github_app`, or when a git
    /// identity rides on a credential that is not an installation token.
    Malformed,
}

impl CredentialFailure {
    /// The fixed text the failed job reports. It never holds a credential value.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::LeaseMismatch => ERR_LEASE,
            Self::NoGithub => ERR_NO_GITHUB,
            Self::NoAgent => ERR_NO_AGENT,
            Self::Expired => ERR_EXPIRED,
            Self::NotConfigured => ERR_NOT_CONFIGURED,
            Self::MintCap => ERR_MINT_CAP,
            Self::Unavailable => ERR_UNAVAILABLE,
            Self::AppIdentityMissing => ERR_APP_IDENTITY_MISSING,
            Self::AppIdentityInvalid => ERR_APP_IDENTITY_INVALID,
            Self::Malformed => ERR_MALFORMED,
        }
    }

    fn from_status(status: &Status) -> Self {
        match (status.code(), status.message()) {
            (Code::PermissionDenied, _) => Self::LeaseMismatch,
            (Code::FailedPrecondition, PRECONDITION_NO_GITHUB) => Self::NoGithub,
            (Code::FailedPrecondition, PRECONDITION_NO_AGENT) => Self::NoAgent,
            (Code::FailedPrecondition, PRECONDITION_EXPIRED) => Self::Expired,
            (Code::FailedPrecondition, PRECONDITION_NOT_CONFIGURED) => Self::NotConfigured,
            (Code::FailedPrecondition, PRECONDITION_APP_MINT_CAP) => Self::MintCap,
            _ => Self::Unavailable,
        }
    }
}

impl fmt::Display for CredentialFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for CredentialFailure {}

/// One credential of a job: its kind, its secret value and the expiry the server sent.
#[derive(Debug, Clone)]
pub struct Credential {
    kind: CredentialKind,
    value: Arc<Secret>,
    expires_at_ms: Option<u64>,
}

impl Credential {
    /// What the credential authenticates against.
    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// The secret value. Hand it to a child or a client, never to a log or a file.
    #[must_use]
    pub fn value(&self) -> &Secret {
        &self.value
    }

    /// The expiry the server sent, in milliseconds since the Unix epoch. Only an installation
    /// token carries one. [`CredentialBook::refresh_if_due`] reads it.
    #[must_use]
    pub const fn expires_at_ms(&self) -> Option<u64> {
        self.expires_at_ms
    }
}

/// The credentials of one job, one per kind.
#[derive(Debug)]
pub struct JobCredentials {
    items: Vec<Credential>,
    identity: Option<BotIdentity>,
}

impl JobCredentials {
    fn from_reply(reply: GetJobCredentialsReply) -> Result<Self, CredentialFailure> {
        let mut seen = HashSet::new();
        let mut items = Vec::with_capacity(reply.credentials.len());
        let mut identity = None;
        for wire in reply.credentials {
            let mut value = Zeroizing::new(wire.value);
            let is_app = wire.kind == GITHUB_INSTALLATION_TOKEN_KIND;
            let kind = if is_app {
                CredentialKind::GithubApp
            } else {
                CredentialKind::from_wire_name(&wire.kind).ok_or(CredentialFailure::Malformed)?
            };
            if wire.shape != CredentialShape::StaticSecret.wire_name()
                || !(MIN_CREDENTIAL_LEN..=MAX_CREDENTIAL_LEN).contains(&value.len())
                || !seen.insert(wire.kind)
                || (is_app && !is_app_token(&value))
                || (!is_app && wire.git_identity.is_some())
                || (kind == CredentialKind::GithubApp && !is_app)
            {
                return Err(CredentialFailure::Malformed);
            }
            if is_app {
                identity = Some(
                    wire.git_identity
                        .ok_or(CredentialFailure::AppIdentityMissing)?,
                );
            }
            items.push(Credential {
                kind,
                value: Arc::new(Secret::new(std::mem::take(&mut *value))),
                expires_at_ms: wire.expires_at_ms,
            });
        }
        if items.iter().filter(|c| c.kind.is_forge()).count() > 1 {
            return Err(CredentialFailure::Malformed);
        }
        let identity = identity
            .map(|wire| {
                BotIdentity::new(&wire.name, &wire.email)
                    .map_err(|_| CredentialFailure::AppIdentityInvalid)
            })
            .transpose()?;
        if !items.iter().any(|c| c.kind.is_forge()) {
            return Err(CredentialFailure::NoGithub);
        }
        if items.iter().all(|c| c.kind.is_forge()) {
            return Err(CredentialFailure::NoAgent);
        }
        Ok(Self { items, identity })
    }

    /// The credential of `kind`, if the job has one.
    #[must_use]
    pub fn get(&self, kind: CredentialKind) -> Option<&Secret> {
        self.items
            .iter()
            .find(|c| c.kind == kind)
            .map(Credential::value)
    }

    /// The GitHub token: the PAT, or the installation token of a GitHub App job. Every
    /// successful fetch holds exactly one.
    #[must_use]
    pub fn github(&self) -> Option<&Secret> {
        self.items
            .iter()
            .find(|c| c.kind.is_forge())
            .map(Credential::value)
    }

    /// The bot identity a GitHub App job commits under. `None` for a PAT job, which keeps the
    /// fixed job identity.
    #[must_use]
    pub const fn git_identity(&self) -> Option<&BotIdentity> {
        self.identity.as_ref()
    }

    /// The expiry of the installation token, in milliseconds since the Unix epoch. `None` for a
    /// PAT job or a token the server sent with no expiry.
    #[must_use]
    pub fn app_expires_at_ms(&self) -> Option<u64> {
        self.items
            .iter()
            .find(|c| c.kind == CredentialKind::GithubApp)
            .and_then(Credential::expires_at_ms)
    }

    fn refreshed(&self, fresh: &Self) -> Result<Self, CredentialFailure> {
        let is_app = |c: &&Credential| c.kind == CredentialKind::GithubApp;
        let (Some(_), Some(token)) = (
            self.items.iter().find(is_app),
            fresh.items.iter().find(is_app),
        ) else {
            return Err(CredentialFailure::Malformed);
        };
        if token.expires_at_ms.is_none() {
            return Err(CredentialFailure::Malformed);
        }
        let items = self
            .items
            .iter()
            .map(|c| if is_app(&c) { token.clone() } else { c.clone() })
            .collect();
        Ok(Self {
            items,
            identity: fresh.identity.clone(),
        })
    }

    fn app_token(&self) -> Option<&Secret> {
        self.items
            .iter()
            .find(|c| c.kind == CredentialKind::GithubApp)
            .map(Credential::value)
    }

    /// The credentials, in reply order.
    pub fn iter(&self) -> std::slice::Iter<'_, Credential> {
        self.items.iter()
    }

    /// A redactor over every value held, to merge into the job's output scrubbing.
    ///
    /// The values that are valid UTF-8 are registered. Values the server accepted are plain
    /// text, so none is skipped in practice.
    ///
    /// The [`Redactor`] keeps its own plain `String` copies, which are not zeroed when it
    /// drops. The copies live as long as the redactor, so drop it when the job ends.
    #[must_use]
    pub fn redactor(&self) -> Redactor {
        Redactor::new(self.items.iter().filter_map(|c| {
            std::str::from_utf8(c.value.expose())
                .ok()
                .map(str::to_owned)
        }))
    }
}

impl<'a> IntoIterator for &'a JobCredentials {
    type Item = &'a Credential;
    type IntoIter = std::slice::Iter<'a, Credential>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

fn is_app_token(value: &str) -> bool {
    value
        .strip_prefix(APP_TOKEN_PREFIX)
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

fn bearer_header(token: &str) -> Result<MetadataValue<tonic::metadata::Ascii>, Error> {
    let text = Zeroizing::new(format!("Bearer {token}"));
    let mut header: MetadataValue<_> = text.as_str().parse().map_err(|_| Error::InvalidValue {
        name: TOKEN_ENV,
        value: String::from("<redacted>"),
    })?;
    header.set_sensitive(true);
    Ok(header)
}

#[derive(Clone)]
struct Attach(MetadataValue<tonic::metadata::Ascii>);

impl Interceptor for Attach {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("authorization", self.0.clone());
        Ok(request)
    }
}

type Client = FleetWorkerClient<InterceptedService<Channel, Attach>>;

/// The `GetJobCredentials` caller, with the bearer token attached.
///
/// Each call builds its own client over a clone of the channel, so concurrent calls never
/// queue behind one another and the backstop covers the whole call.
pub struct CredentialClient {
    channel: Channel,
    attach: Attach,
    backstop: Duration,
}

impl fmt::Debug for CredentialClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialClient").finish_non_exhaustive()
    }
}

impl CredentialClient {
    /// A client over `channel`. The caller sets the request timeout on the channel.
    ///
    /// # Errors
    ///
    /// Fails when the token is not a valid header value. The error never contains it.
    pub fn new(channel: Channel, token: &str) -> Result<Self, Error> {
        Ok(Self {
            channel,
            attach: Attach(bearer_header(token)?),
            backstop: CALL_BACKSTOP,
        })
    }

    /// Replaces the longest time one call may take, [`CALL_BACKSTOP`] by default.
    #[must_use]
    pub const fn with_backstop(mut self, backstop: Duration) -> Self {
        self.backstop = backstop;
        self
    }

    fn client(&self) -> Client {
        FleetWorkerClient::with_interceptor(self.channel.clone(), self.attach.clone())
            .max_decoding_message_size(MAX_REPLY_BYTES)
    }

    async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<JobCredentials, CredentialFailure> {
        let request = GetJobCredentialsRequest {
            job_id: job_id.to_owned(),
            attempt,
            r#box: box_name.to_owned(),
        };
        let mut client = self.client();
        let call = tokio::time::timeout(self.backstop, client.get_job_credentials(request)).await;
        let reply = call
            .map_err(|_| CredentialFailure::Unavailable)?
            .map_err(|status| CredentialFailure::from_status(&status))?
            .into_inner();
        JobCredentials::from_reply(reply)
    }
}

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
    turn: Arc<tokio::sync::Mutex<()>>,
}

struct Snapshot {
    credentials: Arc<JobCredentials>,
    attempt: u32,
    box_name: String,
    retry_at_ms: u64,
}

/// Fetches and holds the credentials of the jobs that run on this box.
#[derive(Debug)]
pub struct CredentialBook {
    client: CredentialClient,
    held: Mutex<HashMap<String, Held>>,
    clock: Arc<dyn Clock>,
    revoker: Option<Arc<Revoker>>,
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
        }
    }

    /// Attaches the client that revokes installation tokens. Without one nothing is revoked.
    #[must_use]
    pub fn with_revoker(mut self, revoker: Arc<Revoker>) -> Self {
        self.revoker = Some(revoker);
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
    /// Call it once the lease is held and before the agent starts. A fetch first drops any
    /// entry held for the same id, so a second fetch replaces the first and a failed one
    /// leaves nothing readable.
    ///
    /// # Errors
    ///
    /// Returns the failure whose [`CredentialFailure::reason`] the job reports. Nothing is
    /// held for `job_id` after an error.
    pub async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<Arc<JobCredentials>, CredentialFailure> {
        self.forget(job_id);
        let credentials = Arc::new(self.client.fetch(job_id, attempt, box_name).await?);
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
    /// after a failure, or a token still inside the window, the next request waits
    /// [`REFRESH_RETRY_MS`]. The old value is not forgotten by the book: the caller keeps it in
    /// the job redactor. With a [`Revoker`] attached, a swap revokes the replaced token on its
    /// own task.
    ///
    /// This is [`CredentialBook::refresh_if_due_with`] with no hook.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialFailure::MintCap`] when the server's per-Job mint cap or per-User
    /// mint rate limit is reached, and any other server refusal (lease lost, capability gone)
    /// as its own variant. A reply with a bad identity returns
    /// [`CredentialFailure::AppIdentityMissing`] or
    /// [`CredentialFailure::AppIdentityInvalid`]. None of these keeps the old token or falls
    /// back to a PAT; the caller fails the step. [`CredentialFailure::Unavailable`] and
    /// [`CredentialFailure::Expired`] are returned only once the held token has expired,
    /// because before that the last good token stays in use. [`CredentialFailure::Malformed`]
    /// is returned when the reply holds no installation token, no expiry, or one already in
    /// the past.
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
    /// The same as [`CredentialBook::refresh_if_due`].
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
        }) = self.snapshot(job_id)
        else {
            return Ok(None);
        };
        let Some(expiry) = current.app_expires_at_ms() else {
            return Ok(None);
        };
        if expiry.saturating_sub(now) >= REFRESH_WINDOW_MS {
            return Ok(None);
        }
        let usable = now < expiry;
        if now < retry_at_ms {
            return if usable {
                Ok(None)
            } else {
                Err(CredentialFailure::Unavailable)
            };
        }
        let renewed = match self.client.fetch(job_id, attempt, &box_name).await {
            Ok(fresh) => {
                current
                    .refreshed(&fresh)
                    .and_then(|next| match next.app_expires_at_ms() {
                        Some(at) if at > now => Ok(next),
                        _ => Err(CredentialFailure::Malformed),
                    })
            }
            Err(failure) => Err(failure),
        };
        match renewed {
            Ok(next) => {
                let still_due = next
                    .app_expires_at_ms()
                    .is_some_and(|at| at.saturating_sub(now) < REFRESH_WINDOW_MS);
                let next = Arc::new(next);
                before_swap(&next);
                let swapped = self.store(
                    job_id,
                    Arc::clone(&next),
                    if still_due { now + REFRESH_RETRY_MS } else { 0 },
                );
                if swapped {
                    self.revoke_replaced(&current, &next);
                } else {
                    self.revoke_app_token(&next);
                }
                Ok(swapped.then_some(next))
            }
            Err(failure) => {
                self.back_off(job_id, now + REFRESH_RETRY_MS);
                let transient = matches!(
                    failure,
                    CredentialFailure::Unavailable | CredentialFailure::Expired
                );
                if usable && transient {
                    tracing::warn!(
                        reason = failure.reason(),
                        "token refresh failed, keeping the held token"
                    );
                    Ok(None)
                } else {
                    Err(failure)
                }
            }
        }
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
        });
        drop(guard);
        snap
    }

    fn revoke_replaced(&self, old: &JobCredentials, new: &JobCredentials) {
        if old.app_token().map(Secret::expose) != new.app_token().map(Secret::expose) {
            self.revoke_app_token(old);
        }
    }

    fn revoke_app_token(&self, credentials: &JobCredentials) {
        let Some(revoker) = &self.revoker else {
            return;
        };
        let Some(token) = credentials.app_token() else {
            return;
        };
        let Ok(token) = std::str::from_utf8(token.expose()).map(|t| Zeroizing::new(t.to_owned()))
        else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(reason = REVOKE_FAILED, "no runtime to revoke the token");
            return;
        };
        let revoker = Arc::clone(revoker);
        drop(runtime.spawn(async move {
            if revoker.revoke(&token).await.is_err() {
                tracing::warn!(reason = REVOKE_FAILED, "token revoke failed");
            }
        }));
    }

    fn store(&self, job_id: &str, next: Arc<JobCredentials>, retry_at_ms: u64) -> bool {
        let mut guard = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let found = guard.get_mut(job_id).map(|entry| {
            entry.credentials = next;
            entry.retry_at_ms = retry_at_ms;
        });
        drop(guard);
        found.is_some()
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
    /// Dropping an id that is not held does nothing.
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
            self.revoke_app_token(&entry.credentials);
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
    use super::bearer_header;

    #[test]
    fn the_authorization_header_is_sensitive() {
        let header = bearer_header("tok-abc").map_err(|_| ());
        assert!(header.is_ok_and(|header| header.is_sensitive()));
    }
}

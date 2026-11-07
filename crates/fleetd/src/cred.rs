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
//! reason keeps the last good token until it expires. The per-User mint rate limit is transient
//! too: a first fetch waits it out and a refresh keeps the held token. The server's per-Job
//! mint cap and its installation and repository refusals are terminal: they fail the step with
//! [`ERR_MINT_CAP`], [`ERR_APP_INSTALLATION`] or [`ERR_APP_REPO`] and there is no PAT fallback
//! (ADR-0058, SEC-004, SEC-001, SEC-002).
//!
//! A fresh token that already looks expired, or inside the window, means the box clock runs
//! ahead of the server's. The book keeps it and refreshes again only after
//! [`REFRESH_SKEW_MS`], so a skewed clock does not spend the mint cap. The token stays usable until
//! [`REFRESH_SKEW_MS`] plus [`REFRESH_SKEW_SLACK_MS`] after the fetch, and a failed refresh past
//! that fails the step with the expired reason.
//!
//! With a [`Revoker`] attached the book revokes the token a refresh replaced, and the held
//! token when the job ends (ADR-0058, SEC-010). It also revokes an installation token that sat
//! in a reply it rejected, and the token of a refresh whose entry a later fetch replaced.
//!
//! A [`TokenLease`] holds a replaced token live until the child that started with it exits, up
//! to [`DRAIN_LIMIT`].
//!
//! Each revoke runs on its own task, is best effort and never fails the job; a failure logs
//! [`REVOKE_FAILED`] and nothing else. A PAT job revokes nothing.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_core::credential::{
    BotIdentity, CredentialKind, CredentialShape, GITHUB_INSTALLATION_TOKEN_PREFIX,
    MAX_CREDENTIAL_LEN, MIN_CREDENTIAL_LEN, Secret,
};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{GetJobCredentialsReply, GetJobCredentialsRequest};
use fleet_proto::{
    GITHUB_INSTALLATION_TOKEN_KIND, MAX_CREDENTIAL_VALUE_BYTES, MAX_CREDENTIALS_PER_USER,
    PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_MINT_CAP, PRECONDITION_APP_MINT_RATE,
    PRECONDITION_APP_REPO, PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB,
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

/// Job failure reason: the GitHub App installation is off the server's allowlist or fails the
/// owner binding (ADR-0058, SEC-001, SEC-014).
pub const ERR_APP_INSTALLATION: &str = "github app installation is not allowed";

/// Job failure reason: the Job repository is off the server's allowlist for the GitHub App
/// (ADR-0058, SEC-002, SEC-009).
pub const ERR_APP_REPO: &str = "repository is not allowed for the github app";

/// Job failure reason: the Job reached its mint cap (ADR-0058, SEC-004, SEC-011).
pub const ERR_MINT_CAP: &str = "github app token limit reached";

/// Job failure reason: the User kept hitting the per-minute mint limit through every wait of
/// the first fetch (ADR-0058, SEC-003).
pub const ERR_RATE_LIMITED: &str = "github app token rate limited";

/// How many times a first fetch asks again after the per-minute mint limit, so the fetch
/// makes at most this many plus one calls.
pub const RATE_RETRIES: u32 = 7;

/// The wait between asks of a first fetch that hit the per-minute mint limit. With
/// [`RATE_RETRIES`] the fetch waits 70 seconds in all, longer than the one-minute window the
/// limit counts over.
pub const RATE_RETRY_DELAY: Duration = Duration::from_secs(10);

/// Refresh the installation token when fewer than this many milliseconds remain: 10 minutes
/// (ADR-0058, Lifetime and refresh). Exactly this much left is not yet due.
pub const REFRESH_WINDOW_MS: u64 = 10 * 60 * 1000;

/// The wait after a failed refresh.
///
/// It keeps a failing server from being asked once per step and the Job's mint cap from being
/// spent on retries. A refresh that returned a token the box clock cannot judge waits
/// [`REFRESH_SKEW_MS`] instead.
pub const REFRESH_RETRY_MS: u64 = 30 * 1000;

/// The wait between refreshes of a token whose lifetime the box clock cannot judge.
///
/// A freshly minted installation token lasts one hour. When a fresh token already looks
/// expired, or inside [`REFRESH_WINDOW_MS`], by the box clock, the box clock runs ahead of the
/// server's. The book then keeps the token, never fails a step on the expiry while the token
/// is younger than [`REFRESH_SKEW_MS`] plus [`REFRESH_SKEW_SLACK_MS`], and refreshes
/// every [`REFRESH_SKEW_MS`] by elapsed time alone, so a skewed clock spends one mint per
/// interval and not one per step. A box clock that runs behind the server's cannot be
/// detected: the token then expires on the server before the box thinks it is due, and the
/// step that uses it fails at GitHub.
pub const REFRESH_SKEW_MS: u64 = 45 * 60 * 1000;

/// The grace past [`REFRESH_SKEW_MS`] a skewed token stays usable: 5 minutes.
///
/// A fresh installation token lasts one hour, so a skewed token whose refresh keeps failing
/// is dropped 50 minutes after it was fetched, before the server expires it.
pub const REFRESH_SKEW_SLACK_MS: u64 = 5 * 60 * 1000;

/// Job failure reason: the reply broke a rule the server keeps.
pub const ERR_MALFORMED: &str = "credentials reply was invalid";

/// Why a job could not get its credentials. Each variant has one fixed reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailure {
    /// Any `PERMISSION_DENIED`: wrong box, wrong attempt, lost lease, unknown job, or a User
    /// who lacks the capability a stored kind needs. fleetd does not tell them apart.
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
    /// (SEC-004, SEC-011). Terminal, never retried.
    MintCap,
    /// `FAILED_PRECONDITION` `github app token rate limited`: the User reached the per-minute
    /// mint limit (SEC-003). Transient: a first fetch retries after [`RATE_RETRY_DELAY`] up to
    /// [`RATE_RETRIES`] times, and a refresh keeps the held token and waits
    /// [`REFRESH_RETRY_MS`].
    RateLimited,
    /// `FAILED_PRECONDITION` `github app installation is not allowed`: the installation is off
    /// the allowlist or fails the owner binding (SEC-001, SEC-014). Terminal, never retried.
    InstallationRefused,
    /// `FAILED_PRECONDITION` `repository is not allowed for the github app`: the Job
    /// repository is off the allowlist (SEC-002, SEC-009). Terminal, never retried.
    RepoRefused,
    /// Any other status, a timeout or a transport error.
    Unavailable,
    /// The reply carries wire kind `github_installation_token` and no git identity.
    AppIdentityMissing,
    /// The git identity that came with an installation token is outside the grammar of
    /// ADR-0058 (SEC-006, SEC-012).
    AppIdentityInvalid,
    /// The reply held an unknown kind or shape, a value outside the length bounds, a duplicate
    /// kind, or an installation token with no expiry. A refresh reply with no installation
    /// token or no expiry is this variant too. It is also this variant when an installation
    /// token does not start with `ghs_` followed by alphanumerics or underscores, when the
    /// reply holds two forge credentials, when a credential has the wire kind `github_app`, or
    /// when a git identity rides on a credential that is not an installation token.
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
            Self::RateLimited => ERR_RATE_LIMITED,
            Self::InstallationRefused => ERR_APP_INSTALLATION,
            Self::RepoRefused => ERR_APP_REPO,
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
            (Code::FailedPrecondition, PRECONDITION_APP_MINT_RATE) => Self::RateLimited,
            (Code::FailedPrecondition, PRECONDITION_APP_INSTALLATION) => Self::InstallationRefused,
            (Code::FailedPrecondition, PRECONDITION_APP_REPO) => Self::RepoRefused,
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

    /// The expiry the server sent, in milliseconds since the Unix epoch. The server sends one
    /// for an installation token and none for a stored secret, and fleetd keeps what the reply
    /// carries. [`CredentialBook::refresh_if_due`] reads the expiry of the installation token.
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
                || (is_app && wire.expires_at_ms.is_none())
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

    fn has_app_token(&self) -> bool {
        self.app_token().is_some()
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
        let redactor = Redactor::new(self.items.iter().filter_map(|c| {
            std::str::from_utf8(c.value.expose())
                .ok()
                .map(str::to_owned)
        }));
        if self.has_app_token() {
            redactor.with_installation_tokens()
        } else {
            redactor
        }
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
        .strip_prefix(GITHUB_INSTALLATION_TOKEN_PREFIX)
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
    /// Returns [`Error::InvalidValue`] when the token is not a valid header value. The error
    /// never contains it.
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
    ) -> Result<JobCredentials, Rejected> {
        let request = GetJobCredentialsRequest {
            job_id: job_id.to_owned(),
            attempt,
            r#box: box_name.to_owned(),
        };
        let mut client = self.client();
        let call = tokio::time::timeout(self.backstop, client.get_job_credentials(request)).await;
        let reply = call
            .map_err(|_| Rejected::from(CredentialFailure::Unavailable))?
            .map_err(|status| Rejected::from(CredentialFailure::from_status(&status)))?
            .into_inner();
        let tokens = app_tokens(&reply);
        JobCredentials::from_reply(reply).map_err(|failure| Rejected { failure, tokens })
    }
}

struct Rejected {
    failure: CredentialFailure,
    tokens: Vec<Zeroizing<String>>,
}

impl From<CredentialFailure> for Rejected {
    fn from(failure: CredentialFailure) -> Self {
        Self {
            failure,
            tokens: Vec::new(),
        }
    }
}

/// The installation tokens of a rejected reply that are worth revoking: those of the GitHub
/// installation kind that pass [`is_app_token`] and fit [`MAX_CREDENTIAL_LEN`], at most
/// [`MAX_CREDENTIALS_PER_USER`] of them. A value outside those bounds is not a token GitHub
/// minted, so it is never sent to the revoke call.
fn app_tokens(reply: &GetJobCredentialsReply) -> Vec<Zeroizing<String>> {
    reply
        .credentials
        .iter()
        .filter(|wire| wire.kind == GITHUB_INSTALLATION_TOKEN_KIND)
        .filter(|wire| wire.value.len() <= MAX_CREDENTIAL_LEN && is_app_token(&wire.value))
        .take(MAX_CREDENTIALS_PER_USER)
        .map(|wire| Zeroizing::new(wire.value.clone()))
        .collect()
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
    use super::{
        Arc, Credential, CredentialBook, CredentialClient, CredentialKind,
        GITHUB_INSTALLATION_TOKEN_KIND, GetJobCredentialsReply, JobCredentials, MAX_CREDENTIAL_LEN,
        MAX_CREDENTIALS_PER_USER, Secret, app_tokens, bearer_header,
    };
    use crate::revoke::Revoker;
    use fleet_proto::v1::JobCredential;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn a_new_book_waits_out_the_rate_limit_longer_than_its_window() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let book = CredentialBook::new(CredentialClient::new(channel, "tok").unwrap());
        assert_eq!(book.rate_retries, super::RATE_RETRIES);
        assert_eq!(book.rate_delay, super::RATE_RETRY_DELAY);
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

    fn app_wire(value: &str) -> JobCredential {
        JobCredential {
            kind: GITHUB_INSTALLATION_TOKEN_KIND.into(),
            shape: "static_secret".into(),
            value: value.into(),
            expires_at_ms: None,
            git_identity: None,
        }
    }

    fn held(reply: &GetJobCredentialsReply) -> Vec<String> {
        app_tokens(reply)
            .iter()
            .map(|token| token.as_str().to_owned())
            .collect()
    }

    #[test]
    fn only_a_well_formed_installation_token_is_collected_for_revocation() {
        let good = "ghs_Good0123456789".to_owned();
        let at_cap = format!("ghs_{}", "a".repeat(MAX_CREDENTIAL_LEN - 4));
        let reply = GetJobCredentialsReply {
            credentials: vec![
                app_wire(&good),
                app_wire("ghs_bad token"),
                app_wire("not-a-token"),
                app_wire(&format!("ghs_{}", "a".repeat(MAX_CREDENTIAL_LEN - 3))),
                app_wire(&at_cap),
                JobCredential {
                    kind: "github_pat".into(),
                    ..app_wire("ghs_Other0123456789")
                },
            ],
        };
        assert_eq!(held(&reply), vec![good, at_cap]);
    }

    #[test]
    fn the_collected_tokens_are_capped_at_the_per_user_limit() {
        let reply = GetJobCredentialsReply {
            credentials: (0..MAX_CREDENTIALS_PER_USER + 5)
                .map(|n| app_wire(&format!("ghs_Tok{n:010}")))
                .collect(),
        };
        assert_eq!(held(&reply).len(), MAX_CREDENTIALS_PER_USER);
    }

    #[test]
    fn the_authorization_header_is_sensitive() {
        let header = bearer_header("tok-abc").map_err(|_| ());
        assert!(header.is_ok_and(|header| header.is_sensitive()));
    }
}

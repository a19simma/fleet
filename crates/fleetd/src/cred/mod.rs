//! Job credentials: the `GetJobCredentials` client and the per-job holder.
//!
//! A [`CredentialBook`] asks the server for the credentials of one claimed job, holds them in
//! memory under the job id and drops them when the job ends. Nothing here writes a value to
//! disk, to a log or to an error. A value lives in a [`Secret`], which zeroes its buffer on
//! drop and prints as `[REDACTED]`.
//!
//! Zeroing is partial. The bearer token header value and the `prost` decode buffers of a reply
//! are plain allocations that are not zeroed when dropped, and the [`Redactor`] keeps plain
//! copies. A process that can read fleetd memory can still recover a value.
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
//! The server also sends the Job repository host (`hosts`): its name, kind, `allow_private`,
//! `approved_ips` and that host's credential (ADR-0068). The holder keys that policy and token by
//! the normalised host. [`JobCredentials::token_for`] returns the token for the one host asked
//! about and nothing for any other string, so a name taken from a Job field or a git prompt never
//! selects another host's token. A Forgejo host carries its `forgejo_pat` only in the host entry;
//! the `github.com` entry repeats the forge credential of `credentials` and must equal it. An
//! entry whose `host` is empty is the file-repo form: it carries no host policy, is never a host,
//! and [`JobCredentials::token_for`] never returns it. It is refused beside a named host.
//! [`JobCredentials::check_job_host`] refuses a reply whose entries name a host other than the Job
//! repository host.
//!
//! Each revoke runs on its own task, is best effort and never fails the job; a failure logs
//! [`REVOKE_FAILED`] and nothing else. A PAT job revokes nothing.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use fleet_core::credential::{
    BotIdentity, CredentialKind, CredentialShape, GITHUB_HOST, GITHUB_INSTALLATION_TOKEN_PREFIX,
    MAX_CREDENTIAL_LEN, MIN_CREDENTIAL_LEN, Secret, validate,
};
use fleet_core::host::{HostKind, HostName};
use fleet_core::{Redactor, constant_time_eq};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    GetJobCredentialsReply, GetJobCredentialsRequest, JobCredential, JobHostCredential,
};
use fleet_proto::{
    GITHUB_INSTALLATION_TOKEN_KIND, MAX_CREDENTIAL_VALUE_BYTES, MAX_CREDENTIALS_PER_USER,
    MAX_HOST_APPROVED_IPS, Reason, classify,
};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};
use zeroize::Zeroizing;

use crate::Error;
use crate::netguard::is_approvable_address;
use crate::poller::{CALL_BACKSTOP, TOKEN_ENV};

mod book;

pub use book::{
    Clock, CredentialBook, DRAIN_LIMIT, LeaseFuture, LeasedToken, SystemClock, TokenLease,
    TokenSource,
};

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
    /// token does not start with [`GITHUB_INSTALLATION_TOKEN_PREFIX`] followed by alphanumerics
    /// or underscores, when the
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

    /// Maps a failed call. Any `PERMISSION_DENIED` is [`Self::LeaseMismatch`] whatever its
    /// message, so `classify` is not consulted for it. Every other pair goes through `classify`,
    /// and a pair it does not list is [`Self::Unavailable`].
    fn from_status(status: &Status) -> Self {
        if status.code() == Code::PermissionDenied {
            return Self::LeaseMismatch;
        }
        match classify(status.code(), status.message()) {
            Some(Reason::NoGithub) => Self::NoGithub,
            Some(Reason::NoAgent) => Self::NoAgent,
            Some(Reason::Expired) => Self::Expired,
            Some(Reason::NotConfigured) => Self::NotConfigured,
            Some(Reason::AppMintCap) => Self::MintCap,
            Some(Reason::AppMintRate) => Self::RateLimited,
            Some(Reason::AppInstallation) => Self::InstallationRefused,
            Some(Reason::AppRepo) => Self::RepoRefused,
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

/// The policy and credential the server sent for one host of a job.
#[derive(Debug, Clone)]
pub struct HostEntry {
    host: Option<HostName>,
    kind: HostKind,
    allow_private: bool,
    approved_ips: Vec<IpAddr>,
    credential: Option<Credential>,
}

impl HostEntry {
    /// The normalised host. `None` for the file-repo form, which carries no host policy.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.host.as_ref().map(HostName::as_str)
    }

    /// The kind of the host.
    #[must_use]
    pub const fn kind(&self) -> HostKind {
        self.kind
    }

    /// True when an admin approved the host for private addresses.
    #[must_use]
    pub const fn allow_private(&self) -> bool {
        self.allow_private
    }

    /// The private addresses the admin approved. Empty unless [`HostEntry::allow_private`].
    #[must_use]
    pub fn approved_ips(&self) -> &[IpAddr] {
        &self.approved_ips
    }
}

/// The credentials of one job, one per kind, and the policy and token of each host.
#[derive(Debug)]
pub struct JobCredentials {
    items: Vec<Credential>,
    identity: Option<BotIdentity>,
    hosts: Vec<HostEntry>,
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
        let forge = items.iter().find(|c| c.kind.is_forge());
        let hosts = reply
            .hosts
            .into_iter()
            .map(|wire| host_entry(wire, forge))
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen_hosts = HashSet::new();
        let forgejo = hosts.iter().filter(|h| h.credential.is_some()).count();
        if !hosts.iter().all(|h| seen_hosts.insert(h.host.clone()))
            || forgejo > 1
            || (hosts.len() > 1 && hosts.iter().any(|h| h.host.is_none()))
            || (forgejo == 1 && forge.is_some())
        {
            return Err(CredentialFailure::Malformed);
        }
        let identity = identity
            .map(|wire| {
                BotIdentity::new(&wire.name, &wire.email)
                    .map_err(|_| CredentialFailure::AppIdentityInvalid)
            })
            .transpose()?;
        if forgejo == 0 && forge.is_none() {
            return Err(CredentialFailure::NoGithub);
        }
        if items.iter().all(|c| c.kind.is_forge()) {
            return Err(CredentialFailure::NoAgent);
        }
        Ok(Self {
            items,
            identity,
            hosts,
        })
    }

    /// The policy entries the server sent, in reply order.
    #[must_use]
    pub fn hosts(&self) -> &[HostEntry] {
        &self.hosts
    }

    /// The entry for `host`, matched on its normalised form. `None` for an empty string, a
    /// string outside the host grammar (userinfo, port, scheme, whitespace, an IP literal), and
    /// a host the reply did not name. The file-repo entry is never returned.
    #[must_use]
    pub fn host(&self, host: &str) -> Option<&HostEntry> {
        let name = HostName::normalise(host).ok()?;
        self.hosts
            .iter()
            .find(|entry| entry.host.as_ref() == Some(&name))
    }

    /// The token stored for `host` and no other: the forge credential for `github.com`, the
    /// `forgejo_pat` for a Forgejo host. `None` for any host the reply did not name.
    #[must_use]
    pub fn token_for(&self, host: &str) -> Option<&Secret> {
        let entry = self.host(host)?;
        match entry.kind {
            HostKind::Github => self.github(),
            HostKind::Forgejo => entry.credential.as_ref().map(Credential::value),
        }
    }

    /// [`JobCredentials::token_for`] as text. `None` when the token is not UTF-8.
    #[must_use]
    pub fn token_str_for(&self, host: &str) -> Option<&str> {
        self.token_for(host)
            .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
    }

    /// Checks that the reply names the Job repository host and no other host.
    ///
    /// `repo_host` is `None` for a file repository, whose reply holds one entry with an empty
    /// host. A repository host that is outside the host grammar, a reply with no entry, an entry
    /// for another host and an empty-host entry beside a real repository host all fail.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialFailure::Malformed`] when the entries do not match `repo_host`.
    pub fn check_job_host(&self, repo_host: Option<&str>) -> Result<(), CredentialFailure> {
        let want = repo_host
            .map(HostName::normalise)
            .transpose()
            .map_err(|_| CredentialFailure::Malformed)?;
        if self.hosts.is_empty() || self.hosts.iter().any(|entry| entry.host != want) {
            return Err(CredentialFailure::Malformed);
        }
        Ok(())
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

    /// [`JobCredentials::github`] as text. `None` when the job holds no GitHub token or the
    /// token is not UTF-8.
    #[must_use]
    pub fn github_str(&self) -> Option<&str> {
        self.github()
            .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
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

    /// Swaps in the app token of `fresh`. A reply that changes a host or its kind, turns
    /// `allow_private` on or adds an approved address is refused; one that clears or shrinks
    /// either is applied, which is how a revoked approval reaches a running job. Addresses
    /// compare as sent, so an IPv4-mapped form of a held address counts as new.
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
        let same_hosts = self.hosts.len() == fresh.hosts.len()
            && self.hosts.iter().zip(&fresh.hosts).all(|(held, new)| {
                held.host == new.host
                    && held.kind == new.kind
                    && (held.allow_private || !new.allow_private)
                    && new
                        .approved_ips
                        .iter()
                        .all(|ip| held.approved_ips.contains(ip))
            });
        if !same_hosts {
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
            hosts: fresh.hosts.clone(),
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
        let held = self
            .items
            .iter()
            .chain(self.hosts.iter().filter_map(|h| h.credential.as_ref()));
        let redactor = Redactor::new(held.filter_map(|c| {
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

fn host_entry(
    wire: JobHostCredential,
    forge: Option<&Credential>,
) -> Result<HostEntry, CredentialFailure> {
    let malformed = CredentialFailure::Malformed;
    let kind = HostKind::from_stored(&wire.host_kind).ok_or(malformed)?;
    let host = if wire.host.is_empty() {
        None
    } else {
        let name = HostName::normalise(&wire.host).map_err(|_| malformed)?;
        if name.as_str() != wire.host {
            return Err(malformed);
        }
        Some(name)
    };
    let is_github = host.as_ref().is_none_or(|h| h.as_str() == GITHUB_HOST);
    if is_github != (kind == HostKind::Github) {
        return Err(malformed);
    }
    if !wire.allow_private && !wire.approved_ips.is_empty() {
        return Err(malformed);
    }
    if wire.approved_ips.len() > MAX_HOST_APPROVED_IPS || (host.is_none() && wire.allow_private) {
        return Err(malformed);
    }
    let approved_ips = wire
        .approved_ips
        .iter()
        .map(|text| IpAddr::from_str(text).map_err(|_| malformed))
        .collect::<Result<Vec<_>, _>>()?;
    if approved_ips.iter().any(|ip| !is_approvable_address(*ip)) {
        return Err(malformed);
    }
    let sent = wire.credential.ok_or(malformed)?;
    let credential = match kind {
        HostKind::Github => {
            let forge = forge.ok_or(malformed)?;
            if sent.kind != forge_wire_kind(forge.kind)
                || !constant_time_eq(sent.value.as_bytes(), forge.value.expose())
            {
                return Err(malformed);
            }
            None
        }
        HostKind::Forgejo => Some(forgejo_credential(sent)?),
    };
    Ok(HostEntry {
        host,
        kind,
        allow_private: wire.allow_private,
        approved_ips,
        credential,
    })
}

fn forgejo_credential(wire: JobCredential) -> Result<Credential, CredentialFailure> {
    let value = Zeroizing::new(wire.value);
    if wire.kind != CredentialKind::ForgejoPat.wire_name()
        || wire.shape != CredentialShape::StaticSecret.wire_name()
        || wire.expires_at_ms.is_some()
        || wire.git_identity.is_some()
        || validate(
            CredentialKind::ForgejoPat,
            CredentialShape::StaticSecret,
            &value,
        )
        .is_err()
    {
        return Err(CredentialFailure::Malformed);
    }
    Ok(Credential {
        kind: CredentialKind::ForgejoPat,
        value: Arc::new(Secret::new(value.to_string())),
        expires_at_ms: None,
    })
}

fn forge_wire_kind(kind: CredentialKind) -> &'static str {
    if kind == CredentialKind::GithubApp {
        GITHUB_INSTALLATION_TOKEN_KIND
    } else {
        kind.wire_name()
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

#[cfg(test)]
mod tests {
    use super::CredentialFailure;
    use super::{
        GITHUB_INSTALLATION_TOKEN_KIND, GetJobCredentialsReply, MAX_CREDENTIAL_LEN,
        MAX_CREDENTIALS_PER_USER, app_tokens, bearer_header,
    };
    use fleet_proto::v1::JobCredential;
    use fleet_proto::{
        ERR_CAPABILITY_NOT_GRANTED, ERR_LEASE_MISMATCH, ERR_NEEDS_USER_TOKEN,
        PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_MINT, PRECONDITION_APP_MINT_CAP,
        PRECONDITION_APP_MINT_RATE, PRECONDITION_APP_REPO, PRECONDITION_CREDENTIAL_TOMBSTONED,
        PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB,
        PRECONDITION_NO_VERIFY_REPO, PRECONDITION_NOT_CONFIGURED,
    };
    use tonic::{Code, Status};

    fn ip(text: &str) -> std::net::IpAddr {
        text.parse().expect("test address")
    }

    fn with_hosts(allow_private: bool, ips: &[&str]) -> super::JobCredentials {
        super::JobCredentials {
            items: vec![super::Credential {
                kind: super::CredentialKind::GithubApp,
                value: std::sync::Arc::new(super::Secret::new("ghs_Fresh0123456789".to_owned())),
                expires_at_ms: Some(1),
            }],
            identity: None,
            hosts: vec![super::HostEntry {
                host: Some(super::HostName::normalise("git.example.org").expect("test host")),
                kind: super::HostKind::Forgejo,
                allow_private,
                approved_ips: ips.iter().map(|t| ip(t)).collect(),
                credential: None,
            }],
        }
    }

    fn private_addr(last: u8) -> String {
        format!("{}.{}.{}.{last}", 10, 0, 0)
    }

    #[test]
    fn a_refresh_that_turns_allow_private_on_is_refused() {
        let held = with_hosts(false, &[]);
        let fresh = with_hosts(true, &[]);
        assert_eq!(
            held.refreshed(&fresh).err(),
            Some(CredentialFailure::Malformed)
        );
    }

    #[test]
    fn a_refresh_that_adds_an_approved_address_is_refused() {
        let (a, b) = (private_addr(1), private_addr(2));
        let held = with_hosts(true, &[&a]);
        let wider = [
            vec![a.clone(), b.clone()],
            vec![b],
            vec![a.clone(), "fd00::1".to_owned()],
            vec![format!("::ffff:{a}")],
        ];
        for ips in wider {
            let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
            let fresh = with_hosts(true, &refs);
            assert_eq!(
                held.refreshed(&fresh).err(),
                Some(CredentialFailure::Malformed),
                "{ips:?}"
            );
        }
        let empty = with_hosts(true, &[]);
        let fresh = with_hosts(true, &[&a]);
        assert!(empty.refreshed(&fresh).is_err());
    }

    #[test]
    fn a_refresh_that_clears_or_shrinks_the_policy_is_applied() {
        let (a, b) = (private_addr(1), private_addr(2));
        let held = with_hosts(true, &[&a, &b]);
        let shrunk = with_hosts(true, &[&b]);
        let applied = held.refreshed(&shrunk).expect("subset");
        assert_eq!(applied.hosts[0].approved_ips, vec![ip(&b)]);
        assert!(applied.hosts[0].allow_private);
        let cleared = with_hosts(false, &[]);
        let applied = held.refreshed(&cleared).expect("narrowed");
        assert!(!applied.hosts[0].allow_private);
        assert_eq!(applied.hosts[0].approved_ips.len(), 0);
    }

    #[test]
    fn a_refresh_with_an_equal_policy_is_applied_in_any_order() {
        let (a, b) = (private_addr(1), private_addr(2));
        let held = with_hosts(true, &[&a, &b]);
        for ips in [vec![&a, &b], vec![&b, &a], vec![&a, &b, &a]] {
            let refs: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();
            let fresh = with_hosts(true, &refs);
            assert!(held.refreshed(&fresh).is_ok(), "{ips:?}");
        }
        let none = with_hosts(false, &[]);
        assert!(none.refreshed(&with_hosts(false, &[])).is_ok());
    }

    #[test]
    fn from_status_maps_each_code_and_message_pair() {
        use CredentialFailure as F;
        let fp = Code::FailedPrecondition;
        let cases = [
            (Code::PermissionDenied, ERR_LEASE_MISMATCH, F::LeaseMismatch),
            (Code::PermissionDenied, "anything", F::LeaseMismatch),
            (
                Code::PermissionDenied,
                ERR_CAPABILITY_NOT_GRANTED,
                F::LeaseMismatch,
            ),
            (
                Code::PermissionDenied,
                ERR_NEEDS_USER_TOKEN,
                F::LeaseMismatch,
            ),
            (fp, PRECONDITION_NO_GITHUB, F::NoGithub),
            (fp, PRECONDITION_NO_AGENT, F::NoAgent),
            (fp, PRECONDITION_EXPIRED, F::Expired),
            (fp, PRECONDITION_NOT_CONFIGURED, F::NotConfigured),
            (fp, PRECONDITION_APP_MINT_CAP, F::MintCap),
            (fp, PRECONDITION_APP_MINT_RATE, F::RateLimited),
            (fp, PRECONDITION_APP_INSTALLATION, F::InstallationRefused),
            (fp, PRECONDITION_APP_REPO, F::RepoRefused),
            (fp, PRECONDITION_APP_MINT, F::Unavailable),
            (fp, PRECONDITION_NO_VERIFY_REPO, F::Unavailable),
            (fp, PRECONDITION_CREDENTIAL_TOMBSTONED, F::Unavailable),
            (fp, ERR_LEASE_MISMATCH, F::Unavailable),
            (fp, "", F::Unavailable),
            (Code::Unavailable, PRECONDITION_NO_GITHUB, F::Unavailable),
            (Code::NotFound, PRECONDITION_APP_REPO, F::Unavailable),
            (Code::Internal, PRECONDITION_APP_MINT_CAP, F::Unavailable),
            (Code::InvalidArgument, PRECONDITION_EXPIRED, F::Unavailable),
            (Code::Unknown, "x", F::Unavailable),
        ];
        for (code, message, want) in cases {
            let got = F::from_status(&Status::new(code, message));
            assert_eq!(got, want, "{code:?} {message}");
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
            hosts: Vec::new(),
        };
        assert_eq!(held(&reply), vec![good, at_cap]);
    }

    #[test]
    fn the_collected_tokens_are_capped_at_the_per_user_limit() {
        let reply = GetJobCredentialsReply {
            credentials: (0..MAX_CREDENTIALS_PER_USER + 5)
                .map(|n| app_wire(&format!("ghs_Tok{n:010}")))
                .collect(),
            hosts: Vec::new(),
        };
        assert_eq!(held(&reply).len(), MAX_CREDENTIALS_PER_USER);
    }

    #[test]
    fn the_authorization_header_is_sensitive() {
        let header = bearer_header("tok-abc").map_err(|_| ());
        assert!(header.is_ok_and(|header| header.is_sensitive()));
    }
}

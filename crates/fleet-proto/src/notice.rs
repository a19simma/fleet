//! Fixed outcome notices of the credential commands, shared by the web page and the CLI.
//!
//! A notice carries a stable code and a fixed text. No notice ever holds user input, a server
//! message or a secret, so both surfaces can print one verbatim.

use fleet_core::credential::CredentialError;
use tonic::{Code, Status};

use crate::{Reason, classify};

/// One outcome of a credential operation, as shown to a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialNotice {
    /// A credential was stored.
    Saved,
    /// A credential was deleted.
    Deleted,
    /// GitHub accepted a stored credential.
    Verified,
    /// GitHub refused a stored credential.
    InvalidToken,
    /// A GitHub value was not a fine-grained token.
    GithubClassic,
    /// GitHub refused a value on save.
    GithubRefused,
    /// The value or kind was refused.
    Invalid,
    /// A backing service is down.
    Unavailable,
    /// No such credential for this user.
    NotFound,
    /// The kind has no verifier.
    NoVerifier,
    /// A GitHub App check needs a Job to name a repository.
    NoJob,
    /// The kind needs a capability the user lacks.
    CapabilityRequired,
    /// The server runs without a credential store.
    NotConfigured,
    /// The caller authenticated with the shared token, which has no user.
    UserTokenRequired,
    /// The credential was deleted and kept as a tombstone, so it cannot be replaced.
    Tombstoned,
    /// The GitHub App installation is not allowed by the operator.
    InstallationRefused,
    /// The repository of the Job is not allowed for the GitHub App.
    RepoRefused,
    /// The User reached the per-minute GitHub App mint limit. Retry later.
    RateLimited,
    /// The repository host is not on the operator list or has no verifier.
    RepoHostRefused,
    /// The User has no credential for the repository host.
    RepoNoCredential,
    /// The forge reports no such repository, or the credential cannot see it.
    RepoNotFound,
    /// The repository host could not be reached.
    RepoUpstreamUnavailable,
    /// The repository check timed out.
    RepoTimeout,
    /// The repository reference is outside the grammar of its forge.
    RepoInvalid,
    /// The user has no such repository registered.
    RepoMissing,
    /// A check rate, a concurrency cap or the per-User row cap refused the call.
    RepoLimit,
    /// A host was added.
    HostAdded,
    /// A host was removed.
    HostRemoved,
    /// An admin approved a host for its private addresses.
    HostApproved,
    /// An admin revoked the private approval of a host.
    HostRevoked,
    /// The host is not allowed, or it resolves to a private address.
    HostRefused,
    /// The host does not answer as Forgejo or Gitea.
    HostNotForge,
    /// The host is not in the table.
    HostUnknown,
    /// The host still has credentials or repositories.
    HostInUse,
    /// The host has no pending private request.
    HostNoRequest,
    /// The named addresses differ from the resolved set.
    HostAddressMismatch,
    /// Private approval does not apply to the host.
    HostNotApplicable,
    /// The job owner has no credential for the job host.
    HostNoCredential,
    /// The host name is outside the grammar.
    HostInvalid,
    /// The host is not in the table.
    HostMissing,
    /// A host cap or the check limiter refused the call.
    HostLimit,
    /// Any other failure.
    Failed,
}

impl CredentialNotice {
    /// Every notice.
    pub const ALL: &'static [Self] = &[
        Self::Saved,
        Self::Deleted,
        Self::Verified,
        Self::InvalidToken,
        Self::GithubClassic,
        Self::GithubRefused,
        Self::Invalid,
        Self::Unavailable,
        Self::NotFound,
        Self::NoVerifier,
        Self::NoJob,
        Self::CapabilityRequired,
        Self::NotConfigured,
        Self::UserTokenRequired,
        Self::Tombstoned,
        Self::InstallationRefused,
        Self::RepoRefused,
        Self::RateLimited,
        Self::RepoHostRefused,
        Self::RepoNoCredential,
        Self::RepoNotFound,
        Self::RepoUpstreamUnavailable,
        Self::RepoTimeout,
        Self::RepoInvalid,
        Self::RepoMissing,
        Self::RepoLimit,
        Self::HostAdded,
        Self::HostRemoved,
        Self::HostApproved,
        Self::HostRevoked,
        Self::HostRefused,
        Self::HostNotForge,
        Self::HostUnknown,
        Self::HostInUse,
        Self::HostNoRequest,
        Self::HostAddressMismatch,
        Self::HostNotApplicable,
        Self::HostNoCredential,
        Self::HostInvalid,
        Self::HostMissing,
        Self::HostLimit,
        Self::Failed,
    ];

    /// The stable code, used in the web redirect query string.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Saved => "saved",
            Self::Deleted => "deleted",
            Self::Verified => "verified",
            Self::InvalidToken => "invalid_token",
            Self::GithubClassic => "github_classic",
            Self::GithubRefused => "github_refused",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
            Self::NotFound => "not_found",
            Self::NoVerifier => "no_verifier",
            Self::NoJob => "no_job",
            Self::CapabilityRequired => "capability_required",
            Self::NotConfigured => "not_configured",
            Self::UserTokenRequired => "user_token_required",
            Self::Tombstoned => "tombstoned",
            Self::InstallationRefused => "installation_refused",
            Self::RepoRefused => "repo_refused",
            Self::RateLimited => "rate_limited",
            Self::RepoHostRefused => "repo_host_refused",
            Self::RepoNoCredential => "repo_no_credential",
            Self::RepoNotFound => "repo_not_found",
            Self::RepoUpstreamUnavailable => "repo_upstream_unavailable",
            Self::RepoTimeout => "repo_timeout",
            Self::RepoInvalid => "repo_invalid",
            Self::RepoMissing => "repo_missing",
            Self::RepoLimit => "repo_limit",
            Self::HostAdded => "host_added",
            Self::HostRemoved => "host_removed",
            Self::HostApproved => "host_approved",
            Self::HostRevoked => "host_revoked",
            Self::HostRefused => "host_refused",
            Self::HostNotForge => "host_not_forge",
            Self::HostUnknown => "host_unknown",
            Self::HostInUse => "host_in_use",
            Self::HostNoRequest => "host_no_request",
            Self::HostAddressMismatch => "host_address_mismatch",
            Self::HostNotApplicable => "host_not_applicable",
            Self::HostNoCredential => "host_no_credential",
            Self::HostInvalid => "host_invalid",
            Self::HostMissing => "host_missing",
            Self::HostLimit => "host_limit",
            Self::Failed => "failed",
        }
    }

    /// The notice for a code, or `None` for an unknown one.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|n| n.code() == code)
    }

    /// The fixed human text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Saved => "Saved.",
            Self::Deleted => "Deleted.",
            Self::Verified => "GitHub accepted the stored credential.",
            Self::InvalidToken => "GitHub refused the stored credential.",
            Self::GithubClassic => {
                "A GitHub credential must be a fine-grained token starting with github_pat_."
            }
            Self::GithubRefused => "GitHub refused the token.",
            Self::Invalid => "The credential was refused. Check the kind and the value.",
            Self::Unavailable => "A backing service is unavailable. Try again later.",
            Self::NotFound => "No such credential.",
            Self::NoVerifier => "This kind cannot be verified.",
            Self::NoJob => {
                "Submit a Job first. A GitHub App check mints a token for the repository of your latest Job."
            }
            Self::CapabilityRequired => {
                "This credential kind needs the forge:github_app capability. Ask an admin to grant it."
            }
            Self::NotConfigured => "Credentials are not configured on this server.",
            Self::UserTokenRequired => {
                "Credentials need a per-user API token, not the shared client token."
            }
            Self::Tombstoned => {
                "This credential was deleted and cannot be replaced. Ask an admin for help."
            }
            Self::InstallationRefused => {
                "The GitHub App installation is not allowed on this server. Ask the operator."
            }
            Self::RepoRefused => {
                "The repository is not allowed for the GitHub App. Ask the operator."
            }
            Self::RateLimited => "Too many GitHub App token requests. Try again in a minute.",
            Self::RepoHostRefused => "This repository host is not allowed on this server.",
            Self::RepoNoCredential => {
                "Store a credential for this repository host first, then add the repository."
            }
            Self::RepoNotFound => {
                "The repository was not found, or your credential cannot access it."
            }
            Self::RepoUpstreamUnavailable => "The repository host is unavailable. Try again later.",
            Self::RepoTimeout => "The repository check timed out. Try again later.",
            Self::RepoInvalid => {
                "The repository reference was refused. Use host/owner/name or an https URL."
            }
            Self::RepoMissing => "No such repository.",
            Self::RepoLimit => {
                "Too many repository checks or repositories. Remove one or try again later."
            }
            Self::HostAdded => "The host was added.",
            Self::HostRemoved => "The host was removed.",
            Self::HostApproved => "The host is approved for its private addresses.",
            Self::HostRevoked => "The private approval of the host was revoked.",
            Self::HostRefused => {
                "This host is not allowed. If it is on a private network, ask an admin to approve it."
            }
            Self::HostNotForge => "This host does not answer as a Forgejo or Gitea server.",
            Self::HostUnknown => "This host is not registered. Add it first.",
            Self::HostInUse => "Remove the credentials and repositories of this host first.",
            Self::HostNoRequest => "No pending request for this host.",
            Self::HostAddressMismatch => {
                "The addresses differ from what the host resolves to now. List the requests and try again."
            }
            Self::HostNotApplicable => "Private approval does not apply to this host.",
            Self::HostNoCredential => "Store a credential for the host of this repository first.",
            Self::HostInvalid => {
                "The host was refused. Use a bare host name without a scheme, port or path."
            }
            Self::HostMissing => "No such host.",
            Self::HostLimit => "Too many hosts or host checks. Remove one or try again later.",
            Self::Failed => "The request failed.",
        }
    }

    /// Classifies a `FleetRepos` refusal into a fixed notice.
    ///
    /// It maps the statuses a repository call adds: `INVALID_ARGUMENT` to [`Self::RepoInvalid`],
    /// `NOT_FOUND` to [`Self::RepoMissing`] and `RESOURCE_EXHAUSTED` to [`Self::RepoLimit`]. Every
    /// other status reads the same closed set as [`Self::for_status`].
    #[must_use]
    pub fn for_repo_status(status: &Status) -> Self {
        match status.code() {
            Code::InvalidArgument => Self::RepoInvalid,
            Code::NotFound => Self::RepoMissing,
            Code::ResourceExhausted => Self::RepoLimit,
            _ => Self::for_status(status),
        }
    }

    /// Classifies a `FleetHosts` refusal into a fixed notice.
    ///
    /// It maps the statuses a host call adds: `INVALID_ARGUMENT` to [`Self::HostInvalid`],
    /// `NOT_FOUND` to [`Self::HostMissing`] and `RESOURCE_EXHAUSTED` to [`Self::HostLimit`], and
    /// the host reasons to their own notice. A private or refused host reads as
    /// [`Self::HostRefused`], the same notice for every cause. Every other status reads the same
    /// closed set as [`Self::for_status`]. The admin-only denial text is not a notice: the CLI
    /// prints its own fixed `ADMIN_ONLY` and `ADMIN_ONLY_PRIVATE` strings from `fleet_cli::host`.
    #[must_use]
    pub fn for_host_status(status: &Status) -> Self {
        match status.code() {
            Code::InvalidArgument => Self::HostInvalid,
            Code::NotFound => Self::HostMissing,
            Code::ResourceExhausted => Self::HostLimit,
            Code::FailedPrecondition => match classify(status.code(), status.message()) {
                Some(Reason::RepoNotAllowedHost) => Self::HostRefused,
                Some(Reason::HostNotForge) => Self::HostNotForge,
                Some(Reason::HostUnknown) => Self::HostUnknown,
                Some(Reason::HostInUse) => Self::HostInUse,
                Some(Reason::HostNoRequest) => Self::HostNoRequest,
                Some(Reason::HostAddressMismatch) => Self::HostAddressMismatch,
                Some(Reason::HostPrivateNotApplicable) => Self::HostNotApplicable,
                Some(Reason::HostNoCredential) => Self::HostNoCredential,
                _ => Self::for_status(status),
            },
            _ => Self::for_status(status),
        }
    }

    /// Classifies a credential RPC refusal. Only the code and a closed set of fixed server
    /// messages are read, so a message that echoes input falls into a generic notice.
    #[must_use]
    pub fn for_status(status: &Status) -> Self {
        let message = status.message();
        let reason = classify(status.code(), message);
        match status.code() {
            Code::InvalidArgument
                if message == CredentialError::GithubNotFineGrained.to_string() =>
            {
                Self::GithubClassic
            }
            Code::InvalidArgument if reason == Some(Reason::GithubRejected) => Self::GithubRefused,
            Code::InvalidArgument => Self::Invalid,
            Code::PermissionDenied if reason == Some(Reason::CapabilityNotGranted) => {
                Self::CapabilityRequired
            }
            Code::PermissionDenied if reason == Some(Reason::NeedsUserToken) => {
                Self::UserTokenRequired
            }
            Code::Unavailable => Self::Unavailable,
            Code::NotFound => Self::NotFound,
            Code::FailedPrecondition => match reason {
                Some(Reason::NoVerifyRepo) => Self::NoJob,
                Some(Reason::NotConfigured) => Self::NotConfigured,
                Some(Reason::Tombstoned) => Self::Tombstoned,
                Some(Reason::AppInstallation) => Self::InstallationRefused,
                Some(Reason::AppRepo) => Self::RepoRefused,
                Some(Reason::AppMintRate) => Self::RateLimited,
                Some(Reason::RepoNotAllowedHost) => Self::RepoHostRefused,
                Some(Reason::RepoNoCredential) => Self::RepoNoCredential,
                Some(Reason::RepoNotFoundOrNoAccess) => Self::RepoNotFound,
                Some(Reason::RepoUpstreamUnavailable) => Self::RepoUpstreamUnavailable,
                Some(Reason::RepoTimeout) => Self::RepoTimeout,
                Some(Reason::HostUnknown) => Self::HostUnknown,
                Some(Reason::HostNoCredential) => Self::HostNoCredential,
                _ => Self::NoVerifier,
            },
            _ => Self::Failed,
        }
    }
}

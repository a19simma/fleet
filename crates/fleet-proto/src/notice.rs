//! Fixed outcome notices of the credential commands, shared by the web page and the CLI.
//!
//! A notice carries a stable code and a fixed text. No notice ever holds user input, a server
//! message or a secret, so both surfaces can print one verbatim.

use fleet_core::credential::CredentialError;
use tonic::{Code, Status};

use crate::{
    ERR_CAPABILITY_NOT_GRANTED, ERR_GITHUB_REJECTED, ERR_NEEDS_USER_TOKEN,
    PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_REPO, PRECONDITION_CREDENTIAL_TOMBSTONED,
    PRECONDITION_NO_VERIFY_REPO, PRECONDITION_NOT_CONFIGURED,
};

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
            Self::Failed => "The request failed.",
        }
    }

    /// Classifies a credential RPC refusal. Only the code and a closed set of fixed server
    /// messages are read, so a message that echoes input falls into a generic notice.
    #[must_use]
    pub fn for_status(status: &Status) -> Self {
        let message = status.message();
        match status.code() {
            Code::InvalidArgument
                if message == CredentialError::GithubNotFineGrained.to_string() =>
            {
                Self::GithubClassic
            }
            Code::InvalidArgument if message == ERR_GITHUB_REJECTED => Self::GithubRefused,
            Code::InvalidArgument => Self::Invalid,
            Code::PermissionDenied if message == ERR_CAPABILITY_NOT_GRANTED => {
                Self::CapabilityRequired
            }
            Code::PermissionDenied if message == ERR_NEEDS_USER_TOKEN => Self::UserTokenRequired,
            Code::Unavailable => Self::Unavailable,
            Code::NotFound => Self::NotFound,
            Code::FailedPrecondition if message == PRECONDITION_NO_VERIFY_REPO => Self::NoJob,
            Code::FailedPrecondition if message == PRECONDITION_NOT_CONFIGURED => {
                Self::NotConfigured
            }
            Code::FailedPrecondition if message == PRECONDITION_CREDENTIAL_TOMBSTONED => {
                Self::Tombstoned
            }
            Code::FailedPrecondition if message == PRECONDITION_APP_INSTALLATION => {
                Self::InstallationRefused
            }
            Code::FailedPrecondition if message == PRECONDITION_APP_REPO => Self::RepoRefused,
            Code::FailedPrecondition => Self::NoVerifier,
            _ => Self::Failed,
        }
    }
}

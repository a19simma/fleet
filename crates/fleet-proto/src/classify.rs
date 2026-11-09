//! Classifies the fixed `(Code, message)` credential refusals.

use tonic::Code;

use crate::{
    ERR_CAPABILITY_NOT_GRANTED, ERR_GITHUB_REJECTED, ERR_LEASE_MISMATCH, ERR_NEEDS_USER_TOKEN,
    PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_MINT, PRECONDITION_APP_MINT_CAP,
    PRECONDITION_APP_MINT_RATE, PRECONDITION_APP_REPO, PRECONDITION_CREDENTIAL_TOMBSTONED,
    PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB,
    PRECONDITION_NO_VERIFY_REPO, PRECONDITION_NOT_CONFIGURED, PRECONDITION_REPO_NO_CREDENTIAL,
    PRECONDITION_REPO_NOT_ALLOWED_HOST, PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
    PRECONDITION_REPO_TIMEOUT, PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
};

/// A fixed server refusal, named by the code and message the server sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// `FAILED_PRECONDITION`: no GitHub credential stored.
    NoGithub,
    /// `FAILED_PRECONDITION`: no credential for the Job's agent.
    NoAgent,
    /// `FAILED_PRECONDITION`: a credential has expired.
    Expired,
    /// `FAILED_PRECONDITION`: the server has no credential store.
    NotConfigured,
    /// `FAILED_PRECONDITION`: the GitHub App token could not be minted.
    AppMint,
    /// `FAILED_PRECONDITION`: the Job reached its mint cap.
    AppMintCap,
    /// `FAILED_PRECONDITION`: the User reached the mint rate limit.
    AppMintRate,
    /// `FAILED_PRECONDITION`: the installation is refused.
    AppInstallation,
    /// `FAILED_PRECONDITION`: the Job repository is refused.
    AppRepo,
    /// `FAILED_PRECONDITION`: a `github_app` verify has no Job repository to scope its mint to.
    NoVerifyRepo,
    /// `FAILED_PRECONDITION`: a `PutCredential` hit a credential that was deleted and kept as a
    /// tombstone because it has mint history.
    Tombstoned,
    /// `FAILED_PRECONDITION`: the repository host is not allowed or has no verifier.
    RepoNotAllowedHost,
    /// `FAILED_PRECONDITION`: the User has no credential for the repository host.
    RepoNoCredential,
    /// `FAILED_PRECONDITION`: the forge answered 404 or 403 for the repository.
    RepoNotFoundOrNoAccess,
    /// `FAILED_PRECONDITION`: the forge could not be reached or answered badly.
    RepoUpstreamUnavailable,
    /// `FAILED_PRECONDITION`: the repository check ran out of budget.
    RepoTimeout,
    /// `PERMISSION_DENIED`: the user lacks a capability.
    CapabilityNotGranted,
    /// `PERMISSION_DENIED`: a per-user token is needed.
    NeedsUserToken,
    /// `PERMISSION_DENIED`: no running Job holds the lease.
    LeaseMismatch,
    /// `INVALID_ARGUMENT`: GitHub rejected the token.
    GithubRejected,
}

/// Names the fixed refusal behind `code` and `message`, or `None` when the pair is not one of
/// them. A known message under a different code is `None`.
#[must_use]
pub fn classify(code: Code, message: &str) -> Option<Reason> {
    match (code, message) {
        (Code::FailedPrecondition, PRECONDITION_NO_GITHUB) => Some(Reason::NoGithub),
        (Code::FailedPrecondition, PRECONDITION_NO_AGENT) => Some(Reason::NoAgent),
        (Code::FailedPrecondition, PRECONDITION_EXPIRED) => Some(Reason::Expired),
        (Code::FailedPrecondition, PRECONDITION_NOT_CONFIGURED) => Some(Reason::NotConfigured),
        (Code::FailedPrecondition, PRECONDITION_APP_MINT) => Some(Reason::AppMint),
        (Code::FailedPrecondition, PRECONDITION_APP_MINT_CAP) => Some(Reason::AppMintCap),
        (Code::FailedPrecondition, PRECONDITION_APP_MINT_RATE) => Some(Reason::AppMintRate),
        (Code::FailedPrecondition, PRECONDITION_APP_INSTALLATION) => Some(Reason::AppInstallation),
        (Code::FailedPrecondition, PRECONDITION_APP_REPO) => Some(Reason::AppRepo),
        (Code::FailedPrecondition, PRECONDITION_NO_VERIFY_REPO) => Some(Reason::NoVerifyRepo),
        (Code::FailedPrecondition, PRECONDITION_CREDENTIAL_TOMBSTONED) => Some(Reason::Tombstoned),
        (Code::FailedPrecondition, PRECONDITION_REPO_NOT_ALLOWED_HOST) => {
            Some(Reason::RepoNotAllowedHost)
        }
        (Code::FailedPrecondition, PRECONDITION_REPO_NO_CREDENTIAL) => {
            Some(Reason::RepoNoCredential)
        }
        (Code::FailedPrecondition, PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS) => {
            Some(Reason::RepoNotFoundOrNoAccess)
        }
        (Code::FailedPrecondition, PRECONDITION_REPO_UPSTREAM_UNAVAILABLE) => {
            Some(Reason::RepoUpstreamUnavailable)
        }
        (Code::FailedPrecondition, PRECONDITION_REPO_TIMEOUT) => Some(Reason::RepoTimeout),
        (Code::PermissionDenied, ERR_CAPABILITY_NOT_GRANTED) => Some(Reason::CapabilityNotGranted),
        (Code::PermissionDenied, ERR_NEEDS_USER_TOKEN) => Some(Reason::NeedsUserToken),
        (Code::PermissionDenied, ERR_LEASE_MISMATCH) => Some(Reason::LeaseMismatch),
        (Code::InvalidArgument, ERR_GITHUB_REJECTED) => Some(Reason::GithubRejected),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Reason, classify};
    use crate::{
        ERR_CAPABILITY_NOT_GRANTED, ERR_GITHUB_REJECTED, ERR_LEASE_MISMATCH, ERR_NEEDS_USER_TOKEN,
        PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_MINT, PRECONDITION_APP_MINT_CAP,
        PRECONDITION_APP_MINT_RATE, PRECONDITION_APP_REPO, PRECONDITION_CREDENTIAL_TOMBSTONED,
        PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB,
        PRECONDITION_NO_VERIFY_REPO, PRECONDITION_NOT_CONFIGURED, PRECONDITION_REPO_NO_CREDENTIAL,
        PRECONDITION_REPO_NOT_ALLOWED_HOST, PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
        PRECONDITION_REPO_TIMEOUT, PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
    };
    use tonic::Code;

    #[test]
    fn each_pair_maps_to_its_reason_and_no_other_code_does() {
        let fp = Code::FailedPrecondition;
        let pd = Code::PermissionDenied;
        let rows = [
            (fp, PRECONDITION_NO_GITHUB, Reason::NoGithub),
            (fp, PRECONDITION_NO_AGENT, Reason::NoAgent),
            (fp, PRECONDITION_EXPIRED, Reason::Expired),
            (fp, PRECONDITION_NOT_CONFIGURED, Reason::NotConfigured),
            (fp, PRECONDITION_APP_MINT, Reason::AppMint),
            (fp, PRECONDITION_APP_MINT_CAP, Reason::AppMintCap),
            (fp, PRECONDITION_APP_MINT_RATE, Reason::AppMintRate),
            (fp, PRECONDITION_APP_INSTALLATION, Reason::AppInstallation),
            (fp, PRECONDITION_APP_REPO, Reason::AppRepo),
            (fp, PRECONDITION_NO_VERIFY_REPO, Reason::NoVerifyRepo),
            (fp, PRECONDITION_CREDENTIAL_TOMBSTONED, Reason::Tombstoned),
            (
                fp,
                PRECONDITION_REPO_NOT_ALLOWED_HOST,
                Reason::RepoNotAllowedHost,
            ),
            (
                fp,
                PRECONDITION_REPO_NO_CREDENTIAL,
                Reason::RepoNoCredential,
            ),
            (
                fp,
                PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
                Reason::RepoNotFoundOrNoAccess,
            ),
            (
                fp,
                PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
                Reason::RepoUpstreamUnavailable,
            ),
            (fp, PRECONDITION_REPO_TIMEOUT, Reason::RepoTimeout),
            (pd, ERR_CAPABILITY_NOT_GRANTED, Reason::CapabilityNotGranted),
            (pd, ERR_NEEDS_USER_TOKEN, Reason::NeedsUserToken),
            (pd, ERR_LEASE_MISMATCH, Reason::LeaseMismatch),
            (
                Code::InvalidArgument,
                ERR_GITHUB_REJECTED,
                Reason::GithubRejected,
            ),
        ];
        for (code, message, want) in rows {
            assert_eq!(classify(code, message), Some(want), "{code:?} {message}");
            for other in [Code::Internal, Code::NotFound, Code::Unknown, Code::Ok] {
                assert_eq!(classify(other, message), None, "{other:?} {message}");
            }
        }
        assert_eq!(classify(fp, ERR_LEASE_MISMATCH), None);
        assert_eq!(classify(pd, PRECONDITION_NO_GITHUB), None);
        assert_eq!(classify(fp, ""), None);
        assert_eq!(classify(fp, "no github credential "), None);
    }
}

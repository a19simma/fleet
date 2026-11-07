//! The shared credential notices: stable codes, fixed texts and the mapping from gRPC status.

use std::collections::BTreeSet;

use fleet_proto::{
    CredentialNotice, ERR_CAPABILITY_NOT_GRANTED, ERR_GITHUB_REJECTED, ERR_LEASE_MISMATCH,
    ERR_NEEDS_USER_TOKEN, PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_MINT,
    PRECONDITION_APP_MINT_CAP, PRECONDITION_APP_MINT_RATE, PRECONDITION_APP_REPO,
    PRECONDITION_CREDENTIAL_TOMBSTONED, PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT,
    PRECONDITION_NO_GITHUB, PRECONDITION_NO_VERIFY_REPO, PRECONDITION_NOT_CONFIGURED,
    PRECONDITION_REPO_NO_CREDENTIAL, PRECONDITION_REPO_NOT_ALLOWED_HOST,
    PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS, PRECONDITION_REPO_TIMEOUT,
    PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
};
use tonic::{Code, Status};

#[test]
fn codes_are_unique_and_round_trip() {
    let codes: BTreeSet<&str> = CredentialNotice::ALL.iter().map(|n| n.code()).collect();
    assert_eq!(codes.len(), CredentialNotice::ALL.len());
    for notice in CredentialNotice::ALL {
        assert_eq!(CredentialNotice::from_code(notice.code()), Some(*notice));
        assert_ne!(notice.text(), "");
    }
    assert_eq!(CredentialNotice::from_code("bogus"), None);
    assert_eq!(CredentialNotice::from_code(""), None);
}

#[test]
fn a_repo_call_maps_its_own_statuses_and_leaves_the_rest_to_the_credential_mapping() {
    let cases = [
        (
            Code::InvalidArgument,
            "echoes <input>",
            CredentialNotice::RepoInvalid,
        ),
        (
            Code::NotFound,
            "echoes <input>",
            CredentialNotice::RepoMissing,
        ),
        (
            Code::ResourceExhausted,
            "echoes <input>",
            CredentialNotice::RepoLimit,
        ),
        (
            Code::Unavailable,
            "storage unavailable",
            CredentialNotice::Unavailable,
        ),
        (Code::Internal, "echoes <input>", CredentialNotice::Failed),
    ];
    for (code, message, want) in cases {
        let status = Status::new(code, message);
        assert_eq!(CredentialNotice::for_repo_status(&status), want, "{code:?}");
    }
    for (reason, want) in [
        (
            PRECONDITION_REPO_NOT_ALLOWED_HOST,
            CredentialNotice::RepoHostRefused,
        ),
        (
            PRECONDITION_REPO_NO_CREDENTIAL,
            CredentialNotice::RepoNoCredential,
        ),
        (
            PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
            CredentialNotice::RepoNotFound,
        ),
        (
            PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
            CredentialNotice::RepoUpstreamUnavailable,
        ),
        (PRECONDITION_REPO_TIMEOUT, CredentialNotice::RepoTimeout),
    ] {
        let status = Status::failed_precondition(reason);
        assert_eq!(CredentialNotice::for_repo_status(&status), want, "{reason}");
    }
    assert_eq!(CredentialNotice::RepoInvalid.code(), "repo_invalid");
    assert_eq!(CredentialNotice::RepoMissing.code(), "repo_missing");
    assert_eq!(CredentialNotice::RepoLimit.code(), "repo_limit");
    assert_eq!(CredentialNotice::RepoMissing.text(), "No such repository.");
}

#[test]
fn pinned_texts() {
    assert_eq!(
        CredentialNotice::NoJob.text(),
        "Submit a Job first. A GitHub App check mints a token for the repository of your latest Job."
    );
    assert_eq!(
        CredentialNotice::CapabilityRequired.text(),
        "This credential kind needs the forge:github_app capability. Ask an admin to grant it."
    );
    assert_eq!(CredentialNotice::NoJob.code(), "no_job");
    assert_eq!(CredentialNotice::Tombstoned.code(), "tombstoned");
    assert_eq!(
        CredentialNotice::Tombstoned.text(),
        "This credential was deleted and cannot be replaced. Ask an admin for help."
    );
}

#[test]
fn the_allowlist_refusals_have_fixed_codes_texts_and_messages() {
    assert_eq!(
        PRECONDITION_APP_INSTALLATION,
        "github app installation is not allowed"
    );
    assert_eq!(
        PRECONDITION_APP_REPO,
        "repository is not allowed for the github app"
    );
    assert_eq!(
        CredentialNotice::InstallationRefused.code(),
        "installation_refused"
    );
    assert_eq!(CredentialNotice::RepoRefused.code(), "repo_refused");
    assert_eq!(
        CredentialNotice::InstallationRefused.text(),
        "The GitHub App installation is not allowed on this server. Ask the operator."
    );
    assert_eq!(
        CredentialNotice::RepoRefused.text(),
        "The repository is not allowed for the GitHub App. Ask the operator."
    );
    for code in [Code::Internal, Code::NotFound, Code::PermissionDenied] {
        for message in [PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_REPO] {
            let got = CredentialNotice::for_status(&Status::new(code, message));
            assert!(
                !matches!(
                    got,
                    CredentialNotice::InstallationRefused | CredentialNotice::RepoRefused
                ),
                "{code:?}"
            );
        }
    }
}

#[test]
fn the_repo_reasons_have_fixed_messages_and_notices() {
    assert_eq!(
        PRECONDITION_REPO_NOT_ALLOWED_HOST,
        "repository host is not allowed"
    );
    assert_eq!(
        PRECONDITION_REPO_NO_CREDENTIAL,
        "no credential for the repository host"
    );
    assert_eq!(
        PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
        "repository not found or no access"
    );
    assert_eq!(
        PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
        "repository host unavailable"
    );
    assert_eq!(PRECONDITION_REPO_TIMEOUT, "repository check timed out");
    let pairs = [
        (CredentialNotice::RepoHostRefused, "repo_host_refused"),
        (CredentialNotice::RepoNoCredential, "repo_no_credential"),
        (CredentialNotice::RepoNotFound, "repo_not_found"),
        (
            CredentialNotice::RepoUpstreamUnavailable,
            "repo_upstream_unavailable",
        ),
        (CredentialNotice::RepoTimeout, "repo_timeout"),
    ];
    for (notice, code) in pairs {
        assert_eq!(notice.code(), code);
        assert_eq!(CredentialNotice::from_code(code), Some(notice));
        assert!(notice.text().ends_with('.'), "{code}");
    }
}

#[test]
fn status_mapping() {
    let cases = [
        (Code::InvalidArgument, "x", CredentialNotice::Invalid),
        (Code::NotFound, "x", CredentialNotice::NotFound),
        (
            Code::PermissionDenied,
            ERR_CAPABILITY_NOT_GRANTED,
            CredentialNotice::CapabilityRequired,
        ),
        (
            Code::PermissionDenied,
            ERR_NEEDS_USER_TOKEN,
            CredentialNotice::UserTokenRequired,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_NO_VERIFY_REPO,
            CredentialNotice::NoJob,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_NOT_CONFIGURED,
            CredentialNotice::NotConfigured,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_NO_GITHUB,
            CredentialNotice::NoVerifier,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_NO_AGENT,
            CredentialNotice::NoVerifier,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_EXPIRED,
            CredentialNotice::NoVerifier,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_APP_MINT,
            CredentialNotice::NoVerifier,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_APP_MINT_RATE,
            CredentialNotice::RateLimited,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_CREDENTIAL_TOMBSTONED,
            CredentialNotice::Tombstoned,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_APP_INSTALLATION,
            CredentialNotice::InstallationRefused,
        ),
        (
            Code::FailedPrecondition,
            PRECONDITION_APP_REPO,
            CredentialNotice::RepoRefused,
        ),
        (Code::Unavailable, "x", CredentialNotice::Unavailable),
        (Code::Internal, "x", CredentialNotice::Failed),
        (Code::Unknown, "x", CredentialNotice::Failed),
    ];
    for (code, message, want) in cases {
        let got = CredentialNotice::for_status(&Status::new(code, message));
        assert_eq!(got, want, "{code:?} {message}");
    }
    let rejected = Status::new(Code::InvalidArgument, ERR_GITHUB_REJECTED);
    assert_eq!(
        CredentialNotice::for_status(&rejected),
        CredentialNotice::GithubRefused
    );
    let _ = PRECONDITION_NOT_CONFIGURED;
}

#[test]
fn every_code_and_message_pair_maps_to_one_notice() {
    use CredentialNotice as N;
    let fp = Code::FailedPrecondition;
    let cases = [
        (fp, PRECONDITION_NO_VERIFY_REPO, N::NoJob),
        (fp, PRECONDITION_NOT_CONFIGURED, N::NotConfigured),
        (fp, PRECONDITION_CREDENTIAL_TOMBSTONED, N::Tombstoned),
        (fp, PRECONDITION_APP_INSTALLATION, N::InstallationRefused),
        (fp, PRECONDITION_APP_REPO, N::RepoRefused),
        (fp, PRECONDITION_APP_MINT_RATE, N::RateLimited),
        (fp, PRECONDITION_REPO_NOT_ALLOWED_HOST, N::RepoHostRefused),
        (fp, PRECONDITION_REPO_NO_CREDENTIAL, N::RepoNoCredential),
        (
            fp,
            PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
            N::RepoNotFound,
        ),
        (
            fp,
            PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
            N::RepoUpstreamUnavailable,
        ),
        (fp, PRECONDITION_REPO_TIMEOUT, N::RepoTimeout),
        (Code::Internal, PRECONDITION_REPO_TIMEOUT, N::Failed),
        (Code::NotFound, PRECONDITION_REPO_NO_CREDENTIAL, N::NotFound),
        (fp, PRECONDITION_NO_GITHUB, N::NoVerifier),
        (fp, PRECONDITION_NO_AGENT, N::NoVerifier),
        (fp, PRECONDITION_EXPIRED, N::NoVerifier),
        (fp, PRECONDITION_APP_MINT, N::NoVerifier),
        (fp, PRECONDITION_APP_MINT_CAP, N::NoVerifier),
        (fp, ERR_LEASE_MISMATCH, N::NoVerifier),
        (fp, "", N::NoVerifier),
        (
            Code::PermissionDenied,
            ERR_CAPABILITY_NOT_GRANTED,
            N::CapabilityRequired,
        ),
        (
            Code::PermissionDenied,
            ERR_NEEDS_USER_TOKEN,
            N::UserTokenRequired,
        ),
        (Code::PermissionDenied, ERR_LEASE_MISMATCH, N::Failed),
        (Code::PermissionDenied, "", N::Failed),
        (Code::InvalidArgument, ERR_GITHUB_REJECTED, N::GithubRefused),
        (
            Code::InvalidArgument,
            PRECONDITION_NOT_CONFIGURED,
            N::Invalid,
        ),
        (Code::NotFound, PRECONDITION_NO_VERIFY_REPO, N::NotFound),
        (
            Code::Unavailable,
            PRECONDITION_APP_MINT_RATE,
            N::Unavailable,
        ),
        (Code::Internal, PRECONDITION_APP_REPO, N::Failed),
        (Code::Unknown, PRECONDITION_NOT_CONFIGURED, N::Failed),
        (
            Code::ResourceExhausted,
            PRECONDITION_APP_MINT_RATE,
            N::Failed,
        ),
    ];
    for (code, message, want) in cases {
        let got = CredentialNotice::for_status(&Status::new(code, message));
        assert_eq!(got, want, "{code:?} {message}");
    }
}

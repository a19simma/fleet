//! The shared credential notices: stable codes, fixed texts and the mapping from gRPC status.

use std::collections::BTreeSet;

use fleet_proto::{
    CredentialNotice, ERR_CAPABILITY_NOT_GRANTED, ERR_GITHUB_REJECTED, ERR_LEASE_MISMATCH,
    ERR_NEEDS_USER_TOKEN, PRECONDITION_APP_INSTALLATION, PRECONDITION_APP_MINT,
    PRECONDITION_APP_MINT_CAP, PRECONDITION_APP_MINT_RATE, PRECONDITION_APP_REPO,
    PRECONDITION_CREDENTIAL_TOMBSTONED, PRECONDITION_EXPIRED, PRECONDITION_NO_AGENT,
    PRECONDITION_NO_GITHUB, PRECONDITION_NO_VERIFY_REPO, PRECONDITION_NOT_CONFIGURED,
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

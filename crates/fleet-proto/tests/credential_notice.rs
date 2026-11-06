//! The shared credential notices: stable codes, fixed texts and the mapping from gRPC status.

use std::collections::BTreeSet;

use fleet_proto::{
    CredentialNotice, ERR_CAPABILITY_NOT_GRANTED, ERR_GITHUB_REJECTED, ERR_NEEDS_USER_TOKEN,
    PRECONDITION_APP_MINT, PRECONDITION_CREDENTIAL_TOMBSTONED, PRECONDITION_EXPIRED,
    PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB, PRECONDITION_NO_VERIFY_REPO,
    PRECONDITION_NOT_CONFIGURED,
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
            PRECONDITION_CREDENTIAL_TOMBSTONED,
            CredentialNotice::Tombstoned,
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

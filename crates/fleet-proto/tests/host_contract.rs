//! The `FleetHosts` wire contract, the host reasons and notices that share one constant table.

use std::collections::BTreeSet;

use fleet_proto::v1::fleet_hosts_server::SERVICE_NAME;
use fleet_proto::v1::{
    AddHostRequest, ApproveHostPrivateRequest, HostInfo, HostRequestInfo, JobCredential,
    JobHostCredential, ListHostRequestsReply, ListHostsReply, RemoveHostRequest,
    RevokeHostPrivateRequest,
};
use fleet_proto::{
    CredentialNotice, ERR_CAPABILITY_NOT_GRANTED, ERR_GITHUB_REJECTED, ERR_HOST_LIMIT,
    ERR_HOST_NOT_FOUND, ERR_LEASE_MISMATCH, ERR_NEEDS_USER_TOKEN, MAX_HOST_APPROVED_IPS,
    MAX_HOSTS_PER_USER, MAX_HOSTS_TOTAL, PRECONDITION_HOST_ADDRESS_MISMATCH,
    PRECONDITION_HOST_IN_USE, PRECONDITION_HOST_NO_CREDENTIAL, PRECONDITION_HOST_NO_REQUEST,
    PRECONDITION_HOST_NOT_FORGE, PRECONDITION_HOST_PRIVATE_NOT_APPLICABLE,
    PRECONDITION_HOST_UNKNOWN, PRECONDITION_REPO_NOT_ALLOWED_HOST, Reason, classify,
};
use tonic::{Code, Status};
use tonic_prost::prost::Message;

fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(message: &M) {
    let decoded = M::decode(message.encode_to_vec().as_slice());
    assert_eq!(decoded.as_ref().ok(), Some(message), "{decoded:?}");
}

fn info(approved_by: Option<u64>, approved_at_ms: Option<u64>) -> HostInfo {
    HostInfo {
        host: "git.example.org".to_owned(),
        kind: "forgejo".to_owned(),
        allow_private: approved_by.is_some(),
        approved_ips: vec!["192.0.2.7".to_owned(), "2001:db8::1".to_owned()],
        added_by: 4,
        approved_by,
        approved_at_ms,
        created_at_ms: 1_700_000_000_000,
    }
}

#[test]
fn the_service_has_its_wire_name() {
    assert_eq!(SERVICE_NAME, "fleet.v1.FleetHosts");
}

#[test]
fn every_message_round_trips() {
    round_trip(&AddHostRequest {
        host: "git.example.org".to_owned(),
    });
    round_trip(&RemoveHostRequest {
        host: "git.example.org".to_owned(),
    });
    round_trip(&RevokeHostPrivateRequest {
        host: "git.example.org".to_owned(),
    });
    round_trip(&ApproveHostPrivateRequest {
        host: "git.example.org".to_owned(),
        approved_ips: vec!["192.0.2.7".to_owned(), "192.0.2.8".to_owned()],
    });
    round_trip(&info(Some(2), Some(1_700_000_000_500)));
    round_trip(&ListHostsReply {
        hosts: vec![info(None, None), info(Some(2), Some(9))],
    });
    let request = HostRequestInfo {
        host: "git.example.org".to_owned(),
        requested_by: 4,
        resolved_ips: vec!["192.0.2.7".to_owned()],
        requested_at_ms: 1_700_000_000_000,
    };
    round_trip(&request);
    round_trip(&ListHostRequestsReply {
        requests: vec![request.clone(), request],
    });
}

#[test]
fn each_field_survives_a_round_trip_alone() {
    let decoded = HostInfo::decode(info(Some(2), Some(9)).encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded.host, "git.example.org");
    assert_eq!(decoded.kind, "forgejo");
    assert!(decoded.allow_private);
    assert_eq!(decoded.approved_ips, ["192.0.2.7", "2001:db8::1"]);
    assert_eq!(decoded.added_by, 4);
    assert_eq!(decoded.approved_by, Some(2));
    assert_eq!(decoded.approved_at_ms, Some(9));
    assert_eq!(decoded.created_at_ms, 1_700_000_000_000);
    let request = HostRequestInfo::decode(
        HostRequestInfo {
            host: "h".to_owned(),
            requested_by: 7,
            resolved_ips: vec!["192.0.2.1".to_owned()],
            requested_at_ms: 8,
        }
        .encode_to_vec()
        .as_slice(),
    )
    .unwrap();
    assert_eq!(request.requested_by, 7);
    assert_eq!(request.requested_at_ms, 8);
    assert_eq!(request.resolved_ips, ["192.0.2.1"]);
}

#[test]
fn approval_fields_are_optional_and_unset_differs_from_zero() {
    for (by, at) in [(None, None), (Some(0), None), (None, Some(0))] {
        let decoded = HostInfo::decode(info(by, at).encode_to_vec().as_slice()).unwrap();
        assert_eq!((decoded.approved_by, decoded.approved_at_ms), (by, at));
    }
    assert_ne!(
        info(None, None).encode_to_vec(),
        info(Some(0), None).encode_to_vec()
    );
    assert_ne!(
        info(None, None).encode_to_vec(),
        info(None, Some(0)).encode_to_vec()
    );
}

#[test]
fn a_job_host_credential_round_trips_and_hides_the_value() {
    const SECRET: &str = "0123456789abcdef0123456789abcdef01234567";
    let message = JobHostCredential {
        host: "git.example.org".to_owned(),
        host_kind: "forgejo".to_owned(),
        allow_private: true,
        approved_ips: vec!["192.0.2.7".to_owned()],
        credential: Some(JobCredential {
            kind: "forgejo_pat".to_owned(),
            shape: "static_secret".to_owned(),
            value: SECRET.to_owned(),
            expires_at_ms: None,
            git_identity: None,
        }),
    };
    round_trip(&message);
    let text = format!("{message:?}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(text.contains("git.example.org"), "{text}");
}

#[test]
fn the_host_reason_messages_are_pinned() {
    assert_eq!(
        PRECONDITION_HOST_NOT_FORGE,
        "host is not a forgejo or gitea server"
    );
    assert_eq!(PRECONDITION_HOST_UNKNOWN, "host is not registered");
    assert_eq!(
        PRECONDITION_HOST_IN_USE,
        "host still has credentials or repositories"
    );
    assert_eq!(
        PRECONDITION_HOST_NO_REQUEST,
        "no pending request for the host"
    );
    assert_eq!(
        PRECONDITION_HOST_ADDRESS_MISMATCH,
        "named addresses do not match the resolved addresses"
    );
    assert_eq!(
        PRECONDITION_HOST_PRIVATE_NOT_APPLICABLE,
        "private approval does not apply to this host"
    );
    assert_eq!(
        PRECONDITION_HOST_NO_CREDENTIAL,
        "no credential for the job host"
    );
    assert_eq!(ERR_HOST_LIMIT, "too many hosts");
    assert_eq!(ERR_HOST_NOT_FOUND, "host not found");
    assert_eq!(MAX_HOSTS_PER_USER, 20);
    assert_eq!(MAX_HOSTS_TOTAL, 500);
    assert_eq!(MAX_HOST_APPROVED_IPS, 16);
}

#[test]
fn each_host_constant_is_the_message_of_its_reason_on_both_sides() {
    let rows = [
        (Reason::HostNotForge, PRECONDITION_HOST_NOT_FORGE),
        (Reason::HostUnknown, PRECONDITION_HOST_UNKNOWN),
        (Reason::HostInUse, PRECONDITION_HOST_IN_USE),
        (Reason::HostNoRequest, PRECONDITION_HOST_NO_REQUEST),
        (
            Reason::HostAddressMismatch,
            PRECONDITION_HOST_ADDRESS_MISMATCH,
        ),
        (
            Reason::HostPrivateNotApplicable,
            PRECONDITION_HOST_PRIVATE_NOT_APPLICABLE,
        ),
        (Reason::HostNoCredential, PRECONDITION_HOST_NO_CREDENTIAL),
    ];
    for (reason, message) in rows {
        assert_eq!(reason.status_parts(), (Code::FailedPrecondition, message));
        assert_eq!(
            classify(Code::FailedPrecondition, message),
            Some(reason),
            "{message}"
        );
        for other in [Code::Internal, Code::NotFound, Code::PermissionDenied] {
            assert_eq!(classify(other, message), None, "{other:?} {message}");
        }
    }
}

#[test]
fn every_reason_round_trips_through_its_status_parts_and_messages_are_distinct() {
    let mut seen = BTreeSet::new();
    for reason in Reason::ALL {
        let (code, message) = reason.status_parts();
        assert_eq!(classify(code, message), Some(*reason), "{reason:?}");
        assert!(seen.insert((code as i32, message)), "{reason:?}");
    }
    assert_eq!(seen.len(), Reason::ALL.len());
}

#[test]
fn a_status_built_from_a_reason_reads_back_as_its_notice() {
    use CredentialNotice as N;
    let rows = [
        (Reason::RepoNotAllowedHost, N::HostRefused),
        (Reason::HostNotForge, N::HostNotForge),
        (Reason::HostUnknown, N::HostUnknown),
        (Reason::HostInUse, N::HostInUse),
        (Reason::HostNoRequest, N::HostNoRequest),
        (Reason::HostAddressMismatch, N::HostAddressMismatch),
        (Reason::HostPrivateNotApplicable, N::HostNotApplicable),
        (Reason::HostNoCredential, N::HostNoCredential),
    ];
    for (reason, want) in rows {
        let (code, message) = reason.status_parts();
        let status = Status::new(code, message);
        assert_eq!(N::for_host_status(&status), want, "{reason:?}");
    }
    assert_eq!(
        N::for_host_status(&Status::failed_precondition(
            PRECONDITION_REPO_NOT_ALLOWED_HOST
        )),
        N::HostRefused
    );
}

#[test]
fn the_credential_path_reads_the_two_host_reasons_a_put_can_raise() {
    for (reason, want) in [
        (Reason::HostUnknown, CredentialNotice::HostUnknown),
        (Reason::HostNoCredential, CredentialNotice::HostNoCredential),
    ] {
        let (code, message) = reason.status_parts();
        assert_eq!(
            CredentialNotice::for_status(&Status::new(code, message)),
            want
        );
    }
    let (code, message) = Reason::HostInUse.status_parts();
    assert_eq!(
        CredentialNotice::for_status(&Status::new(code, message)),
        CredentialNotice::NoVerifier
    );
}

#[test]
fn a_host_call_maps_its_own_statuses_and_leaves_the_rest_to_the_credential_mapping() {
    use CredentialNotice as N;
    let rows = [
        (Code::InvalidArgument, "echoes <input>", N::HostInvalid),
        (Code::NotFound, ERR_HOST_NOT_FOUND, N::HostMissing),
        (Code::ResourceExhausted, ERR_HOST_LIMIT, N::HostLimit),
        (Code::Unavailable, "storage unavailable", N::Unavailable),
        (Code::Internal, "echoes <input>", N::Failed),
        (Code::FailedPrecondition, "echoes <input>", N::NoVerifier),
    ];
    for (code, message, want) in rows {
        assert_eq!(
            N::for_host_status(&Status::new(code, message)),
            want,
            "{code:?}"
        );
    }
    let (code, message) = Reason::NotConfigured.status_parts();
    assert_eq!(
        N::for_host_status(&Status::new(code, message)),
        N::NotConfigured
    );
}

#[test]
fn host_notice_codes_and_texts_are_pinned() {
    use CredentialNotice as N;
    let rows = [
        (N::HostAdded, "host_added", "The host was added."),
        (N::HostRemoved, "host_removed", "The host was removed."),
        (
            N::HostApproved,
            "host_approved",
            "The host is approved for its private addresses.",
        ),
        (
            N::HostRevoked,
            "host_revoked",
            "The private approval of the host was revoked.",
        ),
        (
            N::HostRefused,
            "host_refused",
            "This host is not allowed. If it is on a private network, ask an admin to approve it.",
        ),
        (
            N::HostNotForge,
            "host_not_forge",
            "This host does not answer as a Forgejo or Gitea server.",
        ),
        (
            N::HostUnknown,
            "host_unknown",
            "This host is not registered. Add it first.",
        ),
        (
            N::HostInUse,
            "host_in_use",
            "Remove the credentials and repositories of this host first.",
        ),
        (
            N::HostNoRequest,
            "host_no_request",
            "No pending request for this host.",
        ),
        (
            N::HostAddressMismatch,
            "host_address_mismatch",
            "The addresses differ from what the host resolves to now. List the requests and try again.",
        ),
        (
            N::HostNotApplicable,
            "host_not_applicable",
            "Private approval does not apply to this host.",
        ),
        (
            N::HostNoCredential,
            "host_no_credential",
            "Store a credential for the host of this repository first.",
        ),
        (
            N::HostInvalid,
            "host_invalid",
            "The host was refused. Use a bare host name without a scheme, port or path.",
        ),
        (N::HostMissing, "host_missing", "No such host."),
        (
            N::HostLimit,
            "host_limit",
            "Too many hosts or host checks. Remove one or try again later.",
        ),
    ];
    for (notice, code, text) in rows {
        assert_eq!(notice.code(), code);
        assert_eq!(notice.text(), text);
        assert_eq!(N::from_code(code), Some(notice));
        assert!(N::ALL.contains(&notice), "{code}");
    }
}

#[test]
fn the_reason_table_lists_every_reason_with_its_pair() {
    let fp = Code::FailedPrecondition;
    let pd = Code::PermissionDenied;
    let rows = [
        (Reason::CapabilityNotGranted, pd, ERR_CAPABILITY_NOT_GRANTED),
        (Reason::NeedsUserToken, pd, ERR_NEEDS_USER_TOKEN),
        (Reason::LeaseMismatch, pd, ERR_LEASE_MISMATCH),
        (
            Reason::GithubRejected,
            Code::InvalidArgument,
            ERR_GITHUB_REJECTED,
        ),
        (
            Reason::RepoNotAllowedHost,
            fp,
            PRECONDITION_REPO_NOT_ALLOWED_HOST,
        ),
    ];
    for (reason, code, message) in rows {
        assert_eq!(reason.status_parts(), (code, message));
    }
    assert_eq!(Reason::ALL.len(), 27);
    for reason in [
        Reason::NoGithub,
        Reason::NoAgent,
        Reason::Expired,
        Reason::NotConfigured,
        Reason::AppMint,
        Reason::AppMintCap,
        Reason::AppMintRate,
        Reason::AppInstallation,
        Reason::AppRepo,
        Reason::NoVerifyRepo,
        Reason::Tombstoned,
        Reason::RepoNotAllowedHost,
        Reason::RepoNoCredential,
        Reason::RepoNotFoundOrNoAccess,
        Reason::RepoUpstreamUnavailable,
        Reason::RepoTimeout,
        Reason::HostNotForge,
        Reason::HostUnknown,
        Reason::HostInUse,
        Reason::HostNoRequest,
        Reason::HostAddressMismatch,
        Reason::HostPrivateNotApplicable,
        Reason::HostNoCredential,
        Reason::CapabilityNotGranted,
        Reason::NeedsUserToken,
        Reason::LeaseMismatch,
        Reason::GithubRejected,
    ] {
        assert!(Reason::ALL.contains(&reason), "{reason:?}");
    }
}

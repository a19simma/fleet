//! Secret-bearing proto messages never print their value under Debug.

use fleet_proto::v1::{GetJobCredentialsReply, JobCredential, PutCredentialRequest};

const SECRET: &str = "ghp_SECRET_VALUE_0123456789";

fn put() -> PutCredentialRequest {
    PutCredentialRequest {
        kind: "forge".into(),
        shape: "token".into(),
        value: SECRET.into(),
        expires_at_ms: Some(7),
        host: String::new(),
    }
}

fn job() -> JobCredential {
    JobCredential {
        kind: "forge".into(),
        shape: "token".into(),
        value: SECRET.into(),
        expires_at_ms: None,
        git_identity: None,
    }
}

#[test]
fn put_credential_request_debug_hides_the_value() {
    let message = put();
    for text in [format!("{message:?}"), format!("{message:#?}")] {
        assert!(!text.contains(SECRET), "{text}");
        assert!(text.contains("PutCredentialRequest"), "{text}");
        assert!(text.contains("forge"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }
}

#[test]
fn job_credential_debug_hides_the_value() {
    let message = job();
    for text in [format!("{message:?}"), format!("{message:#?}")] {
        assert!(!text.contains(SECRET), "{text}");
        assert!(text.contains("JobCredential"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }
}

#[test]
fn job_credential_debug_shows_the_expiry_and_identity_but_not_the_value() {
    let mut message = job();
    message.expires_at_ms = Some(1_234_567);
    message.git_identity = Some(fleet_proto::v1::GitIdentity {
        name: "fleet-bot[bot]".into(),
        email: "1+fleet-bot[bot]@users.noreply.github.com".into(),
    });
    let text = format!("{message:?}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(text.contains("1234567"), "{text}");
    assert!(text.contains("fleet-bot[bot]"), "{text}");
}

#[test]
fn a_reply_holding_credentials_hides_every_value() {
    let reply = GetJobCredentialsReply {
        credentials: vec![job(), job()],
        hosts: Vec::new(),
    };
    for text in [format!("{reply:?}"), format!("{reply:#?}")] {
        assert!(!text.contains(SECRET), "{text}");
    }
}

//! Secret-bearing proto messages never print their value under Debug.

use fleet_proto::v1::{GetJobCredentialsReply, JobCredential, PutCredentialRequest};

const SECRET: &str = "ghp_SECRET_VALUE_0123456789";

fn put() -> PutCredentialRequest {
    PutCredentialRequest {
        kind: "forge".into(),
        shape: "token".into(),
        value: SECRET.into(),
        expires_at_ms: Some(7),
    }
}

fn job() -> JobCredential {
    JobCredential {
        kind: "forge".into(),
        shape: "token".into(),
        value: SECRET.into(),
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
fn a_reply_holding_credentials_hides_every_value() {
    let reply = GetJobCredentialsReply {
        credentials: vec![job(), job()],
    };
    for text in [format!("{reply:?}"), format!("{reply:#?}")] {
        assert!(!text.contains(SECRET), "{text}");
    }
}

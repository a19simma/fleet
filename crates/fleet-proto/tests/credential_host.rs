//! The credential host fields and the per-host job credential reply keep the old wire shape.

use fleet_proto::v1::{
    CredentialInfo, DeleteCredentialRequest, GetJobCredentialsReply, JobCredential,
    JobHostCredential, PutCredentialRequest,
};
use tonic_prost::prost::Message;

#[derive(Clone, PartialEq, Message)]
struct OldJobCredential {
    #[prost(string, tag = "1")]
    kind: String,
    #[prost(string, tag = "2")]
    shape: String,
    #[prost(string, tag = "3")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct OldReply {
    #[prost(message, repeated, tag = "1")]
    credentials: Vec<OldJobCredential>,
}

#[derive(Clone, PartialEq, Message)]
struct OldPut {
    #[prost(string, tag = "1")]
    kind: String,
    #[prost(string, tag = "2")]
    shape: String,
    #[prost(string, tag = "3")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct OldDelete {
    #[prost(uint64, tag = "1")]
    id: u64,
}

fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(message: &M) {
    let decoded = M::decode(message.encode_to_vec().as_slice());
    assert_eq!(decoded.as_ref().ok(), Some(message), "{decoded:?}");
}

#[test]
fn an_old_shaped_reply_decodes_with_empty_hosts() {
    let old = OldReply {
        credentials: vec![OldJobCredential {
            kind: "github_pat".to_owned(),
            shape: "static_secret".to_owned(),
            value: "v".to_owned(),
        }],
    };
    let decoded = GetJobCredentialsReply::decode(old.encode_to_vec().as_slice()).ok();
    let reply = decoded.as_ref();
    assert_eq!(reply.map(|r| r.credentials.len()), Some(1));
    assert_eq!(
        reply.map(|r| r.credentials[0].kind.as_str()),
        Some("github_pat")
    );
    assert_eq!(reply.map(|r| r.hosts.len()), Some(0));
}

#[test]
fn old_shaped_requests_decode_with_an_empty_host() {
    let put = OldPut {
        kind: "github_pat".to_owned(),
        shape: "static_secret".to_owned(),
        value: "v".to_owned(),
    };
    let decoded = PutCredentialRequest::decode(put.encode_to_vec().as_slice()).ok();
    assert_eq!(decoded.map(|p| p.host), Some(String::new()));
    let delete = OldDelete { id: 9 };
    let decoded = DeleteCredentialRequest::decode(delete.encode_to_vec().as_slice()).ok();
    assert_eq!(decoded.map(|d| (d.id, d.host)), Some((9, String::new())));
}

#[test]
fn the_host_fields_round_trip() {
    round_trip(&PutCredentialRequest {
        kind: "forgejo_pat".to_owned(),
        shape: "static_secret".to_owned(),
        value: "v".to_owned(),
        expires_at_ms: None,
        host: "git.example.org".to_owned(),
    });
    round_trip(&CredentialInfo {
        id: 1,
        kind: "forgejo_pat".to_owned(),
        shape: "static_secret".to_owned(),
        fingerprint: "f".to_owned(),
        login: None,
        expires_at_ms: None,
        host: "git.example.org".to_owned(),
    });
    round_trip(&DeleteCredentialRequest {
        id: 2,
        host: "git.example.org".to_owned(),
    });
    round_trip(&GetJobCredentialsReply {
        credentials: Vec::new(),
        hosts: vec![JobHostCredential {
            host: "git.example.org".to_owned(),
            host_kind: "forgejo".to_owned(),
            allow_private: true,
            approved_ips: vec!["192.0.2.7".to_owned()],
            credential: Some(JobCredential {
                kind: "forgejo_pat".to_owned(),
                ..JobCredential::default()
            }),
        }],
    });
}

#[test]
fn the_put_debug_shows_the_host_and_hides_the_value() {
    let put = PutCredentialRequest {
        value: "s3cret-value".to_owned(),
        host: "git.example.org".to_owned(),
        ..PutCredentialRequest::default()
    };
    let text = format!("{put:?}");
    assert!(text.contains("git.example.org"), "{text}");
    assert!(!text.contains("s3cret-value"), "{text}");
}

#[derive(Clone, PartialEq, Message)]
struct HostOnly {
    #[prost(string, tag = "1")]
    host: String,
}

#[derive(Clone, PartialEq, Message)]
struct PutHost {
    #[prost(string, tag = "5")]
    host: String,
}

#[derive(Clone, PartialEq, Message)]
struct InfoHost {
    #[prost(string, tag = "7")]
    host: String,
}

#[derive(Clone, PartialEq, Message)]
struct DeleteHost {
    #[prost(string, tag = "2")]
    host: String,
}

#[derive(Clone, PartialEq, Message)]
struct ReplyHosts {
    #[prost(message, repeated, tag = "2")]
    hosts: Vec<HostOnly>,
}

#[test]
fn the_new_fields_sit_on_their_pinned_wire_tags() {
    let host = "git.example.org".to_owned();
    let put = PutHost { host: host.clone() }.encode_to_vec();
    assert_eq!(
        PutCredentialRequest::decode(put.as_slice())
            .ok()
            .map(|m| m.host),
        Some(host.clone())
    );
    let info = InfoHost { host: host.clone() }.encode_to_vec();
    assert_eq!(
        CredentialInfo::decode(info.as_slice()).ok().map(|m| m.host),
        Some(host.clone())
    );
    let delete = DeleteHost { host: host.clone() }.encode_to_vec();
    assert_eq!(
        DeleteCredentialRequest::decode(delete.as_slice())
            .ok()
            .map(|m| m.host),
        Some(host.clone())
    );
    let reply = ReplyHosts {
        hosts: vec![HostOnly { host: host.clone() }],
    }
    .encode_to_vec();
    assert_eq!(
        GetJobCredentialsReply::decode(reply.as_slice())
            .ok()
            .map(|m| m.hosts.into_iter().map(|h| h.host).collect::<Vec<_>>()),
        Some(vec![host])
    );
}

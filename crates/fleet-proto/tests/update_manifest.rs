//! The signed update manifest fields of the heartbeat and their shared limits.

use fleet_proto::v1::{HeartbeatReply, HeartbeatRequest};
use fleet_proto::{MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, PROTOCOL_VERSION, update_within_caps};
use prost::Message;

#[derive(Clone, PartialEq, Message)]
struct OldReply {
    #[prost(uint32, tag = "1")]
    next_in_s: u32,
}

#[derive(Clone, PartialEq, Message)]
struct OldRequest {
    #[prost(string, tag = "1")]
    r#box: String,
    #[prost(string, tag = "5")]
    fleetd_version: String,
    #[prost(uint64, tag = "6")]
    uptime_s: u64,
}

fn reply(manifest: usize, signature: usize) -> HeartbeatReply {
    HeartbeatReply {
        next_in_s: 30,
        update_manifest: Some(vec![1; manifest]),
        update_signature: Some(vec![2; signature]),
    }
}

#[test]
fn an_old_fleetd_ignores_the_new_reply_fields() {
    let bytes = reply(64, 64).encode_to_vec();
    let old = OldReply::decode(bytes.as_slice()).expect("old decode");
    assert_eq!(old.next_in_s, 30);
}

#[test]
fn an_old_reply_decodes_with_no_update() {
    let bytes = OldReply { next_in_s: 7 }.encode_to_vec();
    let new = HeartbeatReply::decode(bytes.as_slice()).expect("new decode");
    assert_eq!(new.next_in_s, 7);
    assert_eq!(new.update_manifest, None);
    assert_eq!(new.update_signature, None);
}

#[test]
fn an_old_server_ignores_the_new_request_field() {
    let request = HeartbeatRequest {
        r#box: format!("box-{}", 1),
        fleetd_version: "1.2.3".to_owned(),
        protocol_version: PROTOCOL_VERSION,
        uptime_s: 9,
        ..HeartbeatRequest::default()
    };
    let old = OldRequest::decode(request.encode_to_vec().as_slice()).expect("old decode");
    assert_eq!(old.fleetd_version, "1.2.3");
    assert_eq!(old.uptime_s, 9);
}

#[test]
fn an_old_request_decodes_with_protocol_zero() {
    let bytes = OldRequest {
        r#box: format!("box-{}", 1),
        fleetd_version: "1.2.3".to_owned(),
        uptime_s: 1,
    }
    .encode_to_vec();
    let new = HeartbeatRequest::decode(bytes.as_slice()).expect("new decode");
    assert_eq!(new.protocol_version, 0);
}

#[test]
fn the_protocol_version_starts_at_one() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn a_reply_at_the_caps_is_within_them() {
    assert!(update_within_caps(&reply(
        MAX_MANIFEST_BYTES,
        MAX_SIGNATURE_BYTES
    )));
}

#[test]
fn a_manifest_just_over_the_cap_is_refused() {
    assert!(!update_within_caps(&reply(MAX_MANIFEST_BYTES + 1, 64)));
}

#[test]
fn a_signature_just_over_the_cap_is_refused() {
    assert!(!update_within_caps(&reply(64, MAX_SIGNATURE_BYTES + 1)));
}

#[test]
fn a_manifest_without_a_signature_is_refused() {
    let mut half = reply(64, 64);
    half.update_signature = None;
    assert!(!update_within_caps(&half));
    let mut other = reply(64, 64);
    other.update_manifest = None;
    assert!(!update_within_caps(&other));
}

#[test]
fn a_reply_with_no_update_is_within_the_caps() {
    assert!(update_within_caps(&HeartbeatReply {
        next_in_s: 30,
        ..HeartbeatReply::default()
    }));
}

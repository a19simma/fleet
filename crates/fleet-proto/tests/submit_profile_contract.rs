//! The submit profile contract: the request field, the shared snapshot caps, the message
//! budget and the migration that stores the job snapshot.

use fleet_proto::v1::SubmitJobRequest;
use fleet_proto::{
    MAX_BLOB_CATALOG_BYTES, MAX_BLOB_CATALOG_ITEMS, MAX_BLOB_CATALOG_WIRE_BYTES,
    MAX_PROFILE_JSON_BYTES, MAX_PROFILE_MESSAGE_BYTES,
};
use prost::Message;

const MIGRATION: &str = include_str!("../../fleet-server/migrations/0029_job_profile_snapshot.sql");
const PROTO: &str = include_str!("../proto/fleet/v1/fleet.proto");

const OLD_CLIENT_BYTES: [u8; 14] = [
    0x0a, 0x01, b'k', 0x12, 0x01, b'p', 0x1a, 0x01, b'r', 0x22, 0x01, b'b', 0x28, 0x01,
];

fn old_request() -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: "k".into(),
        prompt: "p".into(),
        repo: "r".into(),
        base_ref: "b".into(),
        open_pr: true,
        ..SubmitJobRequest::default()
    }
}

#[test]
fn the_profile_field_is_number_seven_and_its_bytes_are_pinned() {
    let request = SubmitJobRequest {
        agent: "a".into(),
        profile: "alice".into(),
        ..old_request()
    };
    let mut want = OLD_CLIENT_BYTES.to_vec();
    want.extend_from_slice(&[0x32, 0x01, b'a', 0x3a, 0x05]);
    want.extend_from_slice(b"alice");
    assert_eq!(request.encode_to_vec(), want);
    assert_eq!(
        SubmitJobRequest::decode(want.as_slice()).unwrap_or_default(),
        request
    );
    assert!(PROTO.contains("string profile = 7;"));
}

#[test]
fn a_request_without_the_field_decodes_with_no_profile() {
    let decoded = SubmitJobRequest::decode(OLD_CLIENT_BYTES.as_slice()).unwrap_or_default();
    assert_eq!(decoded, old_request());
    assert_eq!(decoded.profile, "");
    assert_eq!(old_request().encode_to_vec(), OLD_CLIENT_BYTES);
}

#[test]
fn the_snapshot_caps_are_the_blob_catalog_caps() {
    assert_eq!(MAX_BLOB_CATALOG_ITEMS, 256);
    assert_eq!(MAX_BLOB_CATALOG_BYTES, 4 * 1024 * 1024);
    assert_eq!(MAX_BLOB_CATALOG_WIRE_BYTES, 4 * 1024 * 1024 + 256 * 1024);
    assert!(MIGRATION.contains(&format!("<= {MAX_BLOB_CATALOG_ITEMS}")));
}

#[test]
fn the_message_cap_budgets_the_largest_profile_json_and_the_catalog() {
    assert_eq!(MAX_PROFILE_JSON_BYTES, 8 * 1024 * 1024);
    assert_eq!(
        MAX_PROFILE_MESSAGE_BYTES,
        MAX_PROFILE_JSON_BYTES + MAX_BLOB_CATALOG_WIRE_BYTES + 1024 * 1024
    );
    assert_eq!(MAX_PROFILE_MESSAGE_BYTES, 13 * 1024 * 1024 + 256 * 1024);
}

#[test]
fn the_migration_adds_the_nullable_snapshot_columns() {
    for column in [
        "ADD COLUMN snapshot_catalog jsonb,",
        "ADD COLUMN snapshot_notes jsonb,",
        "ADD COLUMN snapshot_hash bytea,",
        "jobs_snapshot_columns_together",
    ] {
        assert!(MIGRATION.contains(column), "{column}");
    }
    assert!(!MIGRATION.contains("DEFAULT"));
}

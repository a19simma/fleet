//! The `FleetEdit` wire contract: service name, rpc set, shared bounds and round trips.

use fleet_proto::v1::fleet_edit_server::SERVICE_NAME;
use fleet_proto::v1::{EditKind, EditState, SuggestedEdit};
use fleet_proto::{MAX_EDIT_PAYLOAD_BYTES, MAX_PENDING_EDITS_PER_PROJECT};
use tonic_prost::prost::Message;

#[test]
fn the_service_has_its_wire_name() {
    assert_eq!(SERVICE_NAME, "fleet.v1.FleetEdit");
}

#[test]
fn every_rpc_path_is_served() {
    let rpcs = ["FileEdit", "ListEdits", "GetEdit", "DecideEdit"];
    let proto = include_str!("../proto/fleet/v1/fleet.proto");
    let block = proto
        .split("service FleetEdit {")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert_eq!(block.matches("rpc ").count(), rpcs.len());
    for rpc in rpcs {
        assert!(block.contains(&format!("rpc {rpc}(")), "{rpc}");
    }
}

#[test]
fn the_payload_bound_matches_the_table_check() {
    let migration = include_str!("../../fleet-server/migrations/0038_retro.sql");
    assert!(migration.contains(&format!(
        "octet_length(payload) <= {MAX_EDIT_PAYLOAD_BYTES}"
    )));
}

#[test]
fn the_pending_cap_is_positive() {
    assert_eq!(MAX_PENDING_EDITS_PER_PROJECT, 100);
}

#[test]
fn a_suggested_edit_round_trips() {
    let edit = SuggestedEdit {
        id: 7,
        kind: EditKind::SliceOp.into(),
        state: EditState::Stale.into(),
        target: "core".to_owned(),
        base_hash: "ab".repeat(32),
        payload: "add-path\tsrc/new".to_owned(),
        filed_by: "user 1".to_owned(),
        decided_by: Some(2),
        decided_at_ms: Some(3),
        created_at_ms: 4,
    };
    assert_eq!(
        SuggestedEdit::decode(edit.encode_to_vec().as_slice()).unwrap(),
        edit
    );
}

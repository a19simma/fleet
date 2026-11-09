//! The `FleetWork` wire contract: service name, rpc set, field presence and round trips.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::fleet_work_server::SERVICE_NAME;
use fleet_proto::v1::{
    ClaimWorkRequest, GetWorkItemReply, NextWorkReply, WorkAttempt, WorkDefer, WorkDeferState,
    WorkDep, WorkItem, WorkItemState, WorkProject, WorkSlice, WorkVerdict,
};
use tonic_prost::prost::Message;

fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(m: &M) {
    assert_eq!(&M::decode(m.encode_to_vec().as_slice()).unwrap(), m);
}

fn item() -> WorkItem {
    WorkItem {
        key: "WRK-2".to_owned(),
        title: "tables".to_owned(),
        body: String::new(),
        state: WorkItemState::Open.into(),
        slices: vec!["contract".to_owned()],
        deps: vec![WorkDep {
            depends_on: "WRK-0".to_owned(),
            why: "needs the ADR".to_owned(),
        }],
        passes: 1,
        fails: 2,
        ready: true,
        held: false,
        created_at_ms: 1,
        updated_at_ms: 2,
    }
}

#[test]
fn the_service_has_its_wire_name() {
    assert_eq!(SERVICE_NAME, "fleet.v1.FleetWork");
}

#[test]
fn every_rpc_path_is_served() {
    let rpcs = [
        "CreateWorkProject",
        "ListWorkProjects",
        "SetWorkSlices",
        "AddWorkItem",
        "ListWorkItems",
        "GetWorkItem",
        "AddWorkDep",
        "RemoveWorkDep",
        "CancelWork",
        "UnblockWork",
        "NextWork",
        "ClaimWork",
        "RenewLease",
        "ReportAttempt",
        "AddWorkNote",
        "RecordWorkDefer",
        "ResolveWorkDefer",
        "ListWorkDefers",
        "ImportWork",
        "ExportWork",
    ];
    let proto = include_str!("../proto/fleet/v1/fleet.proto");
    let block = proto
        .split("service FleetWork {")
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
fn messages_round_trip() {
    round_trip(&item());
    round_trip(&WorkProject {
        name: "fleet".to_owned(),
        repo: Some("github.com/owner/name".to_owned()),
        slices: vec![WorkSlice {
            name: "contract".to_owned(),
            paths: vec!["crates/fleet-proto".to_owned()],
        }],
        mergeable: vec!["docs/adr".to_owned()],
        created_at_ms: 3,
    });
    round_trip(&GetWorkItemReply {
        item: Some(item()),
        attempts: vec![],
        events: vec![],
    });
    round_trip(&ClaimWorkRequest {
        key: "k".to_owned(),
        project: "fleet".to_owned(),
        item_key: "WRK-2".to_owned(),
        holder: "worker".to_owned(),
        ttl_secs: 600,
    });
}

#[test]
fn verdict_and_closed_at_are_optional_so_an_open_attempt_differs_from_a_closed_one() {
    let open = WorkAttempt {
        id: 1,
        item_key: "WRK-2".to_owned(),
        holder: "worker".to_owned(),
        claimed_at_ms: 1,
        expires_at_ms: 2,
        verdict: None,
        note: String::new(),
        evidence_tail: String::new(),
        closed_at_ms: None,
    };
    let lost = WorkAttempt {
        verdict: Some(WorkVerdict::Lost.into()),
        closed_at_ms: Some(0),
        ..open.clone()
    };
    for a in [&open, &lost] {
        round_trip(a);
    }
    assert_ne!(open.encode_to_vec(), lost.encode_to_vec());
    assert_eq!(
        WorkAttempt::decode(open.encode_to_vec().as_slice())
            .unwrap()
            .verdict,
        None
    );
}

#[test]
fn an_absent_next_item_and_an_absent_defer_item_are_distinct_from_empty() {
    assert_eq!(
        NextWorkReply::decode(NextWorkReply { item: None }.encode_to_vec().as_slice())
            .unwrap()
            .item,
        None
    );
    let defer = |item_key: Option<&str>| WorkDefer {
        id: 1,
        item_key: item_key.map(str::to_owned),
        attempt_id: None,
        title: "t".to_owned(),
        reason: "r".to_owned(),
        vertical: "core".to_owned(),
        state: WorkDeferState::Open.into(),
        promoted_item_key: None,
        created_at_ms: 0,
    };
    assert_ne!(defer(None).encode_to_vec(), defer(Some("")).encode_to_vec());
    round_trip(&defer(Some("WRK-2")));
}

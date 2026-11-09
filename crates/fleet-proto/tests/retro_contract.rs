//! The `FleetRetro` wire contract: service name, rpc set, field presence and round trips.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::fleet_retro_server::SERVICE_NAME;
use fleet_proto::v1::{
    GetWorkBriefReply, Improvement, ImprovementDisposition, ImprovementKind, Pitfall, Retro,
    RetroState,
};
use tonic_prost::prost::Message;

fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(m: &M) {
    assert_eq!(&M::decode(m.encode_to_vec().as_slice()).unwrap(), m);
}

#[test]
fn the_service_has_its_wire_name() {
    assert_eq!(SERVICE_NAME, "fleet.v1.FleetRetro");
}

#[test]
fn every_rpc_path_is_served() {
    let rpcs = [
        "OpenRetro",
        "CloseRetro",
        "ListRetros",
        "FileImprovement",
        "ListImprovements",
        "DispositionImprovement",
        "RecordPitfall",
        "ListPitfalls",
        "GetWorkBrief",
    ];
    let proto = include_str!("../proto/fleet/v1/fleet.proto");
    let block = proto
        .split("service FleetRetro {")
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
    round_trip(&Retro {
        id: 1,
        title: "after WRK-6".to_owned(),
        state: RetroState::Open.into(),
        span_from_item_key: Some("WRK-2".to_owned()),
        span_to_item_key: None,
        opened_at_ms: 1,
        closed_at_ms: None,
    });
    round_trip(&Pitfall {
        id: 2,
        project: Some("fleet".to_owned()),
        symptom: "s".to_owned(),
        cause: "c".to_owned(),
        fix: "f".to_owned(),
        hits: 3,
        last_hit_at_ms: Some(4),
        created_at_ms: 5,
    });
    round_trip(&GetWorkBriefReply {
        text: "brief".to_owned(),
        dropped: 2,
    });
}

#[test]
fn an_undecided_improvement_differs_from_a_decided_one() {
    let undecided = Improvement {
        id: 1,
        retro_id: None,
        item_key: None,
        vertical: "core".to_owned(),
        title: "t".to_owned(),
        body: String::new(),
        kind: ImprovementKind::Process.into(),
        occurrences: 1,
        disposition: None,
        disposition_reason: None,
        created_at_ms: 0,
    };
    let decided = Improvement {
        disposition: Some(ImprovementDisposition::Deferred.into()),
        disposition_reason: Some("later".to_owned()),
        ..undecided.clone()
    };
    round_trip(&undecided);
    round_trip(&decided);
    assert_ne!(undecided.encode_to_vec(), decided.encode_to_vec());
    assert_eq!(
        Improvement::decode(undecided.encode_to_vec().as_slice())
            .unwrap()
            .disposition,
        None
    );
}

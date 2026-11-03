//! The capability grant contract: wire shapes, the shared validators, the admin path constant,
//! the server-stamped Job field and the migration that backs them.

use fleet_core::capability::Capability;
use fleet_proto::v1::{
    GrantCapabilityRequest, Job, ListCapabilitiesReply, ListCapabilitiesRequest,
    RevokeCapabilityReply, RevokeCapabilityRequest, SubmitJobRequest, UserCapability,
};
use fleet_proto::{CAPABILITY_ADMIN_PATH, capability_from_wire, user_id_from_wire};
use prost::Message;

const MIGRATION: &str = include_str!("../../fleet-server/migrations/0026_user_capabilities.sql");
const PROTO: &str = include_str!("../proto/fleet/v1/fleet.proto");

fn block<'a>(open: &str) -> &'a str {
    let rest = PROTO.split(open).nth(1).unwrap_or("");
    rest.split("\n}").next().unwrap_or("")
}

#[test]
fn admin_path_is_the_service_with_a_trailing_slash() {
    assert_eq!(CAPABILITY_ADMIN_PATH, "/fleet.v1.FleetCapabilityAdmin/");
    assert!(CAPABILITY_ADMIN_PATH.ends_with('/'));
    assert!(PROTO.contains("service FleetCapabilityAdmin {"));
}

#[test]
fn the_three_rpcs_sit_in_the_admin_service() {
    let service = block("service FleetCapabilityAdmin {");
    for rpc in [
        "rpc GrantCapability(GrantCapabilityRequest) returns (UserCapability);",
        "rpc RevokeCapability(RevokeCapabilityRequest) returns (RevokeCapabilityReply);",
        "rpc ListCapabilities(ListCapabilitiesRequest) returns (ListCapabilitiesReply);",
    ] {
        assert!(service.contains(rpc), "{rpc}");
    }
    assert_eq!(service.matches("rpc ").count(), 3);
}

#[test]
fn no_other_service_carries_a_capability_rpc() {
    let before = PROTO
        .split("service FleetCapabilityAdmin {")
        .next()
        .unwrap_or("");
    assert!(!before.contains("GrantCapability"));
    let after = PROTO
        .split("service FleetCapabilityAdmin {")
        .nth(1)
        .and_then(|rest| rest.split_once("\n}").map(|(_, tail)| tail))
        .unwrap_or("");
    assert!(
        !after
            .lines()
            .any(|line| line.trim().starts_with("rpc ") && line.contains("Capabilit"))
    );
}

#[test]
fn the_stamp_is_field_34_of_job_and_defaults_false() {
    assert!(block("message Job {").contains("bool profile_tools_granted = 34;"));
    assert!(!Job::default().profile_tools_granted);
    let wire = Job {
        profile_tools_granted: true,
        ..Job::default()
    }
    .encode_to_vec();
    assert_eq!(wire, [0x90, 0x02, 0x01]);
}

#[test]
fn no_request_message_carries_the_stamp() {
    let requests = PROTO.split("\nmessage ").skip(1).filter(|m| {
        m.split_whitespace()
            .next()
            .is_some_and(|n| n.ends_with("Request"))
    });
    for message in requests {
        assert!(
            !message
                .split("\n}")
                .next()
                .unwrap_or("")
                .contains("profile_tools_granted")
        );
    }
}

#[test]
fn a_stamp_on_a_submit_request_is_dropped_on_decode() {
    let mut forged = SubmitJobRequest {
        prompt: "p".into(),
        ..SubmitJobRequest::default()
    }
    .encode_to_vec();
    let clean = forged.clone();
    forged.extend_from_slice(&[0x90, 0x02, 0x01]);
    let decoded = SubmitJobRequest::decode(forged.as_slice()).unwrap_or_default();
    assert_eq!(decoded.prompt, "p");
    assert_eq!(decoded.encode_to_vec(), clean);
}

#[test]
fn request_fields_are_pinned() {
    let grant = GrantCapabilityRequest {
        user_id: 7,
        capability: "profile:tools".into(),
    };
    assert_eq!(
        grant.encode_to_vec(),
        [
            0x08, 0x07, 0x12, 13, b'p', b'r', b'o', b'f', b'i', b'l', b'e', b':', b't', b'o', b'o',
            b'l', b's'
        ]
    );
    assert_eq!(
        RevokeCapabilityRequest {
            user_id: 7,
            capability: String::new()
        }
        .encode_to_vec(),
        [0x08, 0x07]
    );
    assert_eq!(
        ListCapabilitiesRequest { user_id: 7 }.encode_to_vec(),
        [0x08, 0x07]
    );
}

#[test]
fn capability_text_is_the_core_canonical_text_and_nothing_else() {
    assert_eq!(
        capability_from_wire("profile:tools"),
        Some(Capability::ProfileTools)
    );
    for cap in Capability::ALL {
        assert_eq!(capability_from_wire(cap.as_str()), Some(*cap));
    }
}

#[test]
fn capability_hostile_table() {
    let long = "p".repeat(10_000);
    let hostile: [&str; 30] = [
        "",
        " ",
        "profile:tools\n",
        "\nprofile:tools",
        "profile:tools\r\n",
        "profile:tools\r",
        "profile:tools\u{85}",
        "profile:tools\u{2028}",
        "profile:tools\u{2029}",
        "profile:tools ",
        " profile:tools",
        "profile:tools\0",
        "profile: tools",
        "Profile:Tools",
        "PROFILE:TOOLS",
        "profile:tool",
        "profile:tools:",
        "profile:tools/",
        "profile\\:tools",
        "profile:tools@h",
        "u@profile:tools",
        "[::1]",
        "profile:tools,profile:tools",
        "profile%3Atools",
        "profile\u{ff1a}tools",
        "pr\u{43e}file:tools",
        "profile:tools\u{202e}",
        "*",
        "profile:*",
        &long,
    ];
    for raw in hostile {
        assert_eq!(capability_from_wire(raw), None, "{raw:?}");
    }
}

#[test]
fn user_id_range() {
    assert_eq!(user_id_from_wire(0), None);
    assert_eq!(user_id_from_wire(1), Some(1));
    assert_eq!(user_id_from_wire(i64::MAX as u64), Some(i64::MAX));
    assert_eq!(user_id_from_wire(i64::MAX as u64 + 1), None);
    assert_eq!(user_id_from_wire(u64::MAX), None);
}

#[test]
fn the_migration_check_lists_exactly_the_core_capabilities() {
    let list = MIGRATION
        .split("capability IN (")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .unwrap_or_default();
    let listed: Vec<&str> = list
        .split(',')
        .map(|p| p.trim().trim_matches('\''))
        .collect();
    let expected: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(listed, expected);
}

#[test]
fn the_migration_keys_and_references() {
    assert!(MIGRATION.contains("user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE"));
    assert!(MIGRATION.contains("granted_by bigint NOT NULL REFERENCES users (id)"));
    assert!(MIGRATION.contains("PRIMARY KEY (user_id, capability)"));
}

#[test]
fn reply_fields_are_pinned() {
    let row = UserCapability {
        user_id: 1,
        capability: "a".into(),
        granted_by: 3,
        granted_at_ms: 4,
    };
    assert_eq!(
        row.encode_to_vec(),
        [0x08, 1, 0x12, 1, b'a', 0x18, 3, 0x20, 4]
    );
    assert_eq!(
        RevokeCapabilityReply { removed: true }.encode_to_vec(),
        [0x08, 1]
    );
    let list = ListCapabilitiesReply {
        capabilities: vec![row],
    };
    assert_eq!(list.encode_to_vec()[..2], [0x0a, 9]);
}

//! The Profile ownership contract: enum values, field shape and the migration that backs it.

use fleet_core::Visibility;
use fleet_proto::v1::{Profile, ProfileVisibility, SelectionEntry};
use prost::Message;

const MIGRATION: &str = include_str!("../../fleet-server/migrations/0023_profile_ownership.sql");
const PROTO: &str = include_str!("../proto/fleet/v1/fleet.proto");

#[test]
fn visibility_values_are_pinned() {
    assert_eq!(ProfileVisibility::Unspecified as i32, 0);
    assert_eq!(ProfileVisibility::Private as i32, 1);
    assert_eq!(ProfileVisibility::Shared as i32, 2);
}

#[test]
fn visibility_names_match_the_core_enum() {
    for (wire, core) in [
        (ProfileVisibility::Private, Visibility::Private),
        (ProfileVisibility::Shared, Visibility::Shared),
    ] {
        let suffix = core.as_str().to_ascii_uppercase();
        assert_eq!(wire.as_str_name(), format!("PROFILE_VISIBILITY_{suffix}"));
    }
}

#[test]
fn the_migration_check_lists_every_core_visibility() {
    for core in [Visibility::Private, Visibility::Shared] {
        assert!(
            MIGRATION.contains(&format!("'{}'", core.as_str())),
            "{core}"
        );
    }
}

#[test]
fn a_profile_round_trips_with_an_opt_out_selection() {
    let profile = Profile {
        name: "p".to_owned(),
        owner_user_id: 7,
        visibility: ProfileVisibility::Shared as i32,
        selection: vec![SelectionEntry {
            item_id: "skill-a".to_owned(),
            enabled: false,
        }],
        authored_prompt: "be brief".to_owned(),
    };
    let decoded = Profile::decode(profile.encode_to_vec().as_slice()).unwrap_or_default();
    assert_eq!(decoded, profile);
}

#[test]
fn the_proto_documents_the_opt_out_meaning() {
    assert!(PROTO.contains("only switched-off items"), "opt-out comment");
    assert!(PROTO.contains("enabled = true"), "refusal comment");
}

#[test]
fn ownership_is_unique_per_owner_and_name() {
    assert!(MIGRATION.contains("UNIQUE (owner_user_id, name)"));
}

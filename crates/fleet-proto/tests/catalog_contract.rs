//! The catalog contract: kind values, the shared content limit and the migration that backs it.

use fleet_core::catalog::{CatalogItem as CoreItem, CatalogKind as CoreKind};
use fleet_proto::v1::{CatalogItem, CatalogKind};
use fleet_proto::{MAX_CATALOG_CONTENT_BYTES, validate_catalog_content};
use prost::Message;

const MIGRATION: &str = include_str!("../../fleet-server/migrations/0024_catalog_items.sql");
const PROTO: &str = include_str!("../proto/fleet/v1/fleet.proto");

const CORE_KINDS: [CoreKind; 4] = [
    CoreKind::Skill,
    CoreKind::Subagent,
    CoreKind::Tool,
    CoreKind::Context,
];

#[test]
fn kind_values_are_pinned() {
    assert_eq!(CatalogKind::Unspecified as i32, 0);
    assert_eq!(CatalogKind::Skill as i32, 1);
    assert_eq!(CatalogKind::Subagent as i32, 2);
    assert_eq!(CatalogKind::Tool as i32, 3);
    assert_eq!(CatalogKind::Context as i32, 4);
}

#[test]
fn wire_kind_names_match_the_core_kinds() {
    let wire = [
        CatalogKind::Skill,
        CatalogKind::Subagent,
        CatalogKind::Tool,
        CatalogKind::Context,
    ];
    for (wire, core) in wire.into_iter().zip(CORE_KINDS) {
        let suffix = core.as_str().to_ascii_uppercase();
        assert_eq!(wire.as_str_name(), format!("CATALOG_KIND_{suffix}"));
    }
}

#[test]
fn the_migration_kind_check_lists_exactly_the_core_kinds() {
    let list = MIGRATION
        .split("kind IN (")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .unwrap_or_default();
    let listed: Vec<&str> = list
        .split(',')
        .map(|part| part.trim().trim_matches('\''))
        .collect();
    let expected: Vec<&str> = CORE_KINDS.iter().map(|kind| kind.as_str()).collect();
    assert_eq!(listed, expected);
}

#[test]
fn the_migration_content_limit_equals_the_shared_const() {
    let literal: usize = MIGRATION
        .split("octet_length(content) BETWEEN 1 AND ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .and_then(|digits| digits.trim().parse().ok())
        .unwrap_or_default();
    assert_eq!(literal, MAX_CATALOG_CONTENT_BYTES);
}

#[test]
fn the_shared_limit_is_the_core_limit() {
    assert_eq!(
        MAX_CATALOG_CONTENT_BYTES,
        fleet_core::catalog::MAX_BODY_BYTES
    );
    let at = "a".repeat(MAX_CATALOG_CONTENT_BYTES);
    assert!(CoreItem::new(CoreKind::Skill, "s", "s", &at).is_ok());
    assert!(CoreItem::new(CoreKind::Skill, "s", "s", &format!("{at}a")).is_err());
}

#[test]
fn content_validator_accepts_one_to_the_limit_only() {
    assert!(!validate_catalog_content(""));
    assert!(validate_catalog_content("a"));
    assert!(validate_catalog_content(
        &"a".repeat(MAX_CATALOG_CONTENT_BYTES)
    ));
    assert!(!validate_catalog_content(
        &"a".repeat(MAX_CATALOG_CONTENT_BYTES + 1)
    ));
    let wide = "\u{e9}".repeat(MAX_CATALOG_CONTENT_BYTES / 2 + 1);
    assert!(!validate_catalog_content(&wide), "bytes, not chars");
}

#[test]
fn an_item_round_trips() {
    let item = CatalogItem {
        id: "skill-a".to_owned(),
        kind: CatalogKind::Skill as i32,
        name: "skill-a".to_owned(),
        content: "body".to_owned(),
        digest: vec![7; 32],
        admin_enabled: true,
    };
    let decoded = CatalogItem::decode(item.encode_to_vec().as_slice()).unwrap_or_default();
    assert_eq!(decoded, item);
}

#[test]
fn the_proto_splits_read_and_admin_services() {
    let service = |name: &str| {
        PROTO
            .split(&format!("service {name} {{"))
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .unwrap_or_default()
    };
    let read = service("FleetCatalog");
    let admin = service("FleetCatalogAdmin");
    assert!(read.contains("rpc ListCatalog(") && !read.contains("Upsert"));
    assert!(admin.contains("rpc UpsertCatalogItem("));
    assert!(admin.contains("rpc SetCatalogItemEnabled("));
    assert!(!admin.contains("ListCatalog"));
}

#[test]
fn the_migration_pins_uniqueness_and_default_off() {
    assert!(MIGRATION.contains("UNIQUE (kind, name)"));
    assert!(MIGRATION.contains("admin_enabled boolean NOT NULL DEFAULT false"));
}

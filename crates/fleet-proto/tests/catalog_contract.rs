//! The catalog contract: kind values, the shared content limit and the migration that backs it.

use fleet_core::catalog::{CatalogItem as CoreItem, CatalogKind as CoreKind};
use fleet_proto::v1::{CatalogItem, CatalogKind, ListCatalogReply, ListCatalogRequest};
use fleet_proto::{
    DEFAULT_CATALOG_PAGE, MAX_CATALOG_CONTENT_BYTES, MAX_CATALOG_CURSOR_BYTES, MAX_CATALOG_PAGE,
    validate_catalog_content, validate_catalog_cursor,
};
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

const SERVER_CATALOG: &str = include_str!("../../fleet-server/src/catalog.rs");

fn server_const(name: &str) -> u32 {
    SERVER_CATALOG
        .split(&format!("pub const {name}: u32 = "))
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

#[test]
fn list_request_and_reply_field_numbers_are_pinned() {
    let request = ListCatalogRequest {
        kind: CatalogKind::Context as i32,
        page_size: 7,
        after_id: "abc".to_owned(),
    };
    assert_eq!(
        request.encode_to_vec(),
        [0x08, 4, 0x10, 7, 0x1a, 3, b'a', b'b', b'c']
    );
    let reply = ListCatalogReply {
        items: Vec::new(),
        next_id: "z".to_owned(),
    };
    assert_eq!(reply.encode_to_vec(), [0x12, 1, b'z']);
}

#[test]
fn page_caps_have_their_values_and_match_the_server() {
    assert_eq!(DEFAULT_CATALOG_PAGE, 50);
    assert_eq!(MAX_CATALOG_PAGE, 200);
    assert_eq!(server_const("DEFAULT_CATALOG_PAGE"), DEFAULT_CATALOG_PAGE);
    assert_eq!(server_const("MAX_CATALOG_PAGE"), MAX_CATALOG_PAGE);
}

#[test]
fn cursor_cap_is_the_item_id_cap() {
    assert_eq!(MAX_CATALOG_CURSOR_BYTES, 64);
    assert!(validate_catalog_cursor(
        &"a".repeat(MAX_CATALOG_CURSOR_BYTES)
    ));
    assert!(!validate_catalog_cursor(
        &"a".repeat(MAX_CATALOG_CURSOR_BYTES + 1)
    ));
}

#[test]
fn cursor_hostile_input_table() {
    let accepted = ["", "a", "skill-1", "a_b-c9", "0"];
    for input in accepted {
        assert!(validate_catalog_cursor(input), "{input:?}");
    }
    let refused = [
        "a\0b",
        "\0",
        "a\rb",
        "a\r\nb",
        "a\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{2029}b",
        " ",
        "a b",
        "A",
        "a/b",
        "a\\b",
        "a%00",
        "caf\u{e9}",
        "\u{1F600}",
        "a\u{200B}",
    ];
    for input in refused {
        assert!(!validate_catalog_cursor(input), "{input:?}");
    }
}

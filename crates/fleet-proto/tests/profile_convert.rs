//! Wire to core conversion of visibility, selection, catalog items, capabilities and the model
//! allowlist. Every conversion runs through the fleet-core validators.

use fleet_core::capability::Capability;
use fleet_core::catalog::{CatalogEntry, CatalogError, CatalogItem, CatalogKind};
use fleet_core::model_allowlist::ModelAllowlistError;
use fleet_core::{ItemId, MAX_SELECTION, Selection, SelectionError, Visibility};
use fleet_proto::v1::{self, CatalogKind as WireKind, ProfileVisibility, SelectionEntry};
use fleet_proto::{
    ProfileConvertError, capability_from_text, capability_to_text, catalog_entry_from_wire,
    catalog_entry_to_wire, catalog_kind_from_wire, catalog_kind_to_wire, model_allowlist_from_wire,
    model_allowlist_to_wire, selection_from_wire, selection_to_wire, visibility_from_wire,
    visibility_to_wire,
};

const SCAN: std::ops::RangeInclusive<i32> = -3..=64;

fn long(n: usize) -> String {
    "a".repeat(n)
}

fn hostile() -> Vec<String> {
    let mut out: Vec<String> = [
        "",
        " ",
        "a b",
        " a",
        "a ",
        "a\r",
        "a\n",
        "a\r\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a@b",
        "user:pw@host",
        "a\\b",
        "[::1]",
        "a..b",
        "-a",
        "_a",
        "A",
        "aB",
        "a\0b",
        "\u{e9}",
        "a/b",
        "a%2fb",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    out.push(long(ItemId::MAX_LEN + 1));
    out
}

fn entry(id: &str, enabled: bool) -> SelectionEntry {
    SelectionEntry {
        item_id: id.to_owned(),
        enabled,
    }
}

macro_rules! sample {
    ($kind:expr) => {{
        let kind = $kind;
        let built = match kind {
            CatalogKind::Skill => CatalogItem::new(kind, "skill-one", "skill-one", "body"),
            CatalogKind::Subagent => CatalogItem::new(kind, "agent-one", "agent-one", "prompt"),
            CatalogKind::Tool => CatalogItem::new(kind, "node", "node", "22.1.0"),
            CatalogKind::Context => CatalogItem::new(kind, "ctx-one", "ctx-one", "text"),
        };
        built.unwrap_or_else(|e| panic!("{e}"))
    }};
}

#[test]
fn visibility_round_trips_every_wire_variant() {
    let mut seen = 0;
    for raw in SCAN {
        let known = ProfileVisibility::try_from(raw).is_ok();
        let result = visibility_from_wire(raw);
        if known && raw != ProfileVisibility::Unspecified as i32 {
            let core = result.unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(visibility_to_wire(core) as i32, raw);
            match core {
                Visibility::Private | Visibility::Shared => {}
            }
            seen += 1;
        } else {
            assert_eq!(result, Err(ProfileConvertError::UnknownVisibility), "{raw}");
        }
    }
    assert_eq!(seen, 2);
}

#[test]
fn visibility_text_matches_the_wire_name() {
    for raw in SCAN {
        if let Ok(core) = visibility_from_wire(raw) {
            let wire = ProfileVisibility::try_from(raw).unwrap_or_else(|e| panic!("{e}"));
            assert!(wire.as_str_name().ends_with(&core.as_str().to_uppercase()));
        }
    }
}

#[test]
fn selection_round_trips_through_core() {
    let wire = vec![
        entry("zeta", false),
        entry("alpha", false),
        entry("m-1", false),
    ];
    let core = selection_from_wire(&wire).unwrap_or_else(|e| panic!("{e}"));
    let ids: Vec<&str> = core.ids().map(ItemId::as_str).collect();
    assert_eq!(ids, ["alpha", "m-1", "zeta"]);
    let back = selection_to_wire(&core);
    assert!(back.iter().all(|e| !e.enabled));
    assert_eq!(selection_from_wire(&back), Ok(core));
    assert_eq!(selection_from_wire(&[]), Ok(Selection::default()));
    assert_eq!(selection_to_wire(&Selection::default()), Vec::new());
}

#[test]
fn selection_refuses_an_enabled_entry_and_a_duplicate() {
    assert_eq!(
        selection_from_wire(&[entry("a", true)]),
        Err(ProfileConvertError::Selection(SelectionError::EnabledEntry))
    );
    assert_eq!(
        selection_from_wire(&[entry("a", false), entry("a", false)]),
        Err(ProfileConvertError::Selection(SelectionError::Duplicate))
    );
}

#[test]
fn selection_refuses_hostile_ids() {
    for id in hostile() {
        assert_eq!(
            selection_from_wire(&[entry(&id, false)]),
            Err(ProfileConvertError::Selection(SelectionError::InvalidId)),
            "{id:?}"
        );
    }
}

#[test]
fn selection_limit_is_exact() {
    let ids: Vec<String> = (0..=MAX_SELECTION).map(|n| format!("i{n}")).collect();
    let at: Vec<SelectionEntry> = ids
        .iter()
        .take(MAX_SELECTION)
        .map(|i| entry(i, false))
        .collect();
    assert_eq!(selection_from_wire(&at).map(|s| s.len()), Ok(MAX_SELECTION));
    let over: Vec<SelectionEntry> = ids.iter().map(|i| entry(i, false)).collect();
    assert_eq!(
        selection_from_wire(&over),
        Err(ProfileConvertError::Selection(SelectionError::TooMany))
    );
}

#[test]
fn catalog_kind_round_trips_every_wire_variant() {
    let mut seen = 0;
    for raw in SCAN {
        let known = WireKind::try_from(raw).is_ok();
        let result = catalog_kind_from_wire(raw);
        if known && raw != WireKind::Unspecified as i32 {
            let core = result.unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(catalog_kind_to_wire(core) as i32, raw);
            let wire = WireKind::try_from(raw).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                wire.as_str_name(),
                format!("CATALOG_KIND_{}", core.as_str().to_uppercase())
            );
            match core {
                CatalogKind::Skill
                | CatalogKind::Subagent
                | CatalogKind::Tool
                | CatalogKind::Context => {}
            }
            seen += 1;
        } else {
            assert_eq!(
                result,
                Err(ProfileConvertError::UnknownCatalogKind),
                "{raw}"
            );
        }
    }
    assert_eq!(seen, 4);
}

#[test]
fn catalog_entry_round_trips_every_kind_and_flag() {
    for raw in SCAN {
        let Ok(kind) = catalog_kind_from_wire(raw) else {
            continue;
        };
        for enabled in [false, true] {
            let entry = CatalogEntry::new(sample!(kind), enabled);
            let wire = catalog_entry_to_wire(&entry);
            assert_eq!(wire.admin_enabled, enabled);
            assert_eq!(wire.digest, entry.item().digest().to_vec());
            assert_eq!(wire.kind, raw);
            assert_eq!(catalog_entry_from_wire(&wire), Ok(entry), "{raw} {enabled}");
        }
    }
}

#[test]
fn catalog_entry_ignores_the_wire_digest() {
    let entry = CatalogEntry::new(sample!(CatalogKind::Skill), false);
    let mut wire = catalog_entry_to_wire(&entry);
    wire.digest = vec![9; 3];
    assert_eq!(catalog_entry_from_wire(&wire), Ok(entry));
}

#[test]
fn catalog_entry_refuses_hostile_ids_and_names() {
    for text in hostile() {
        let mut wire = catalog_entry_to_wire(&CatalogEntry::new(sample!(CatalogKind::Skill), true));
        wire.id = text.clone();
        assert_eq!(
            catalog_entry_from_wire(&wire),
            Err(ProfileConvertError::Catalog(CatalogError::InvalidId)),
            "{text:?}"
        );
        let mut wire = catalog_entry_to_wire(&CatalogEntry::new(sample!(CatalogKind::Skill), true));
        wire.name = text.clone();
        assert_eq!(
            catalog_entry_from_wire(&wire),
            Err(ProfileConvertError::Catalog(CatalogError::InvalidName)),
            "{text:?}"
        );
    }
}

#[test]
fn catalog_entry_refuses_bad_kind_body_and_tool() {
    let base = catalog_entry_to_wire(&CatalogEntry::new(sample!(CatalogKind::Skill), true));
    let mut wire = base.clone();
    wire.kind = WireKind::Unspecified as i32;
    assert_eq!(
        catalog_entry_from_wire(&wire),
        Err(ProfileConvertError::UnknownCatalogKind)
    );
    let mut wire = base.clone();
    wire.content = String::new();
    assert_eq!(
        catalog_entry_from_wire(&wire),
        Err(ProfileConvertError::Catalog(CatalogError::InvalidBody))
    );
    let mut wire = base;
    wire.content = long(fleet_proto::MAX_CATALOG_CONTENT_BYTES + 1);
    assert_eq!(
        catalog_entry_from_wire(&wire),
        Err(ProfileConvertError::Catalog(CatalogError::InvalidBody))
    );
    wire.content = long(fleet_proto::MAX_CATALOG_CONTENT_BYTES);
    assert!(catalog_entry_from_wire(&wire).is_ok());
    let tool = v1::CatalogItem {
        id: "t".into(),
        kind: WireKind::Tool as i32,
        name: "rust".into(),
        content: "1.0.0".into(),
        digest: Vec::new(),
        admin_enabled: false,
    };
    assert_eq!(
        catalog_entry_from_wire(&tool),
        Err(ProfileConvertError::Catalog(CatalogError::UnknownTool))
    );
}

#[test]
fn capability_round_trips_every_capability() {
    for cap in Capability::ALL {
        assert_eq!(capability_to_text(*cap), cap.as_str());
        assert_eq!(capability_from_text(capability_to_text(*cap)), Ok(*cap));
    }
}

#[test]
fn capability_refuses_hostile_text() {
    let mut cases = hostile();
    for cap in Capability::ALL {
        let text = cap.as_str();
        cases.extend([
            text.to_uppercase(),
            format!(" {text}"),
            format!("{text} "),
            format!("{text}\n"),
            format!("{text}\r\n"),
            format!("{text}\u{85}"),
            format!("{text}\u{2028}"),
            format!("{text}@x"),
            text.replace(':', "\\:"),
            text[..text.len() - 1].to_owned(),
        ]);
    }
    for text in cases {
        assert_eq!(
            capability_from_text(&text),
            Err(ProfileConvertError::UnknownCapability),
            "{text:?}"
        );
    }
}

#[test]
fn model_allowlist_round_trips_in_order() {
    let wire = vec!["claude-opus-4-1".to_owned(), "gpt-5:x/y[1]".to_owned()];
    let core = model_allowlist_from_wire(&wire).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(model_allowlist_to_wire(&core), wire);
    assert_eq!(
        model_allowlist_from_wire(&model_allowlist_to_wire(&core)),
        Ok(core)
    );
}

#[test]
fn model_allowlist_refuses_through_the_core_rules() {
    let err = |e| Err(ProfileConvertError::ModelAllowlist(e));
    assert_eq!(
        model_allowlist_from_wire(&[]),
        err(ModelAllowlistError::Empty)
    );
    assert_eq!(
        model_allowlist_from_wire(&[String::new()]),
        err(ModelAllowlistError::EmptyEntry)
    );
    assert_eq!(
        model_allowlist_from_wire(&["a".into(), "a".into()]),
        err(ModelAllowlistError::Duplicate)
    );
    for text in hostile()
        .into_iter()
        .filter(|t| !t.is_empty() && t.len() <= ItemId::MAX_LEN)
    {
        let got = model_allowlist_from_wire(std::slice::from_ref(&text));
        if matches!(
            text.as_str(),
            "a/b" | "[::1]" | "a..b" | "-a" | "_a" | "A" | "aB"
        ) {
            assert!(got.is_ok(), "{text:?}");
        } else {
            assert_eq!(got, err(ModelAllowlistError::BadEntry), "{text:?}");
        }
    }
    let edge = "a".repeat(fleet_core::model_allowlist::MAX_ENTRY_BYTES);
    assert!(model_allowlist_from_wire(std::slice::from_ref(&edge)).is_ok());
    assert_eq!(
        model_allowlist_from_wire(&[format!("{edge}a")]),
        err(ModelAllowlistError::EntryTooLong)
    );
    let at: Vec<String> = (0..fleet_core::model_allowlist::MAX_ENTRIES)
        .map(|n| format!("m{n}"))
        .collect();
    assert!(model_allowlist_from_wire(&at).is_ok());
    let mut over = at;
    over.push("extra".into());
    assert_eq!(
        model_allowlist_from_wire(&over),
        err(ModelAllowlistError::TooMany)
    );
}

#[test]
fn errors_carry_no_input() {
    let secret = "s3cr3t-token";
    let text = format!("{secret}\n");
    let shown = [
        selection_from_wire(&[entry(&text, false)])
            .map(|_| ())
            .err(),
        capability_from_text(&text).map(|_| ()).err(),
        model_allowlist_from_wire(std::slice::from_ref(&text))
            .map(|_| ())
            .err(),
    ];
    for err in shown.into_iter().flatten() {
        assert!(!err.to_string().contains(secret));
    }
    let mut wire = catalog_entry_to_wire(&CatalogEntry::new(sample!(CatalogKind::Skill), true));
    wire.id = text;
    let err = catalog_entry_from_wire(&wire).err().map(|e| e.to_string());
    assert!(err.is_some_and(|m| !m.contains(secret)));
}

#[test]
fn a_blob_reply_catalog_round_trips_through_encode_and_convert() {
    use prost::Message;
    let entries: Vec<CatalogEntry> = [CatalogKind::Skill, CatalogKind::Subagent, CatalogKind::Tool]
        .into_iter()
        .zip([true, false, true])
        .map(|(kind, enabled)| CatalogEntry::new(sample!(kind), enabled))
        .collect();
    let reply = v1::GetProfileBlobReply {
        profile: None,
        content: b"{}".to_vec(),
        catalog: entries.iter().map(catalog_entry_to_wire).collect(),
    };
    let decoded = v1::GetProfileBlobReply::decode(reply.encode_to_vec().as_slice())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decoded, reply);
    let back: Result<Vec<CatalogEntry>, ProfileConvertError> = decoded
        .catalog
        .iter()
        .map(catalog_entry_from_wire)
        .collect();
    assert_eq!(back, Ok(entries));
    assert!(fleet_proto::validate_blob_catalog(&decoded.catalog));
}

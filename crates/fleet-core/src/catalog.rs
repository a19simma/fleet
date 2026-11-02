//! Catalog items and their resolution.
//!
//! An item is built through [`CatalogItem::new`], which validates every field, so a
//! held item is always well formed.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::ItemId;
use crate::tools::{ToolName, Version};

/// Domain-separation prefix of the item digest.
pub const CATALOG_ITEM_DOMAIN: &[u8] = b"fleet-catalog-item-v1\0";

/// Longest item name in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// Longest item body in bytes.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// What an item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CatalogKind {
    /// A skill.
    Skill,
    /// A subagent.
    Subagent,
    /// A registry tool; the body is its pinned version.
    Tool,
    /// A context file.
    Context,
}

impl CatalogKind {
    /// The wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Subagent => "subagent",
            Self::Tool => "tool",
            Self::Context => "context",
        }
    }
}

impl fmt::Display for CatalogKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an item was refused. Messages are fixed and never echo input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogError {
    /// The id is not a valid item id.
    InvalidId,
    /// The name is not a valid item name.
    InvalidName,
    /// A tool item names a tool outside the registry.
    UnknownTool,
    /// A tool item body is not an exact pinned version.
    InvalidVersion,
    /// The body is empty or over the size cap.
    InvalidBody,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "catalog item id is invalid",
            Self::InvalidName => "catalog item name is invalid",
            Self::UnknownTool => "catalog tool is not in the registry",
            Self::InvalidVersion => "catalog tool version is invalid",
            Self::InvalidBody => "catalog item body is empty or too large",
        })
    }
}

impl std::error::Error for CatalogError {}

/// A validated catalog item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogItem {
    kind: CatalogKind,
    id: ItemId,
    name: String,
    body: String,
}

/// Checks an item name: the item id shape, at most [`MAX_NAME_BYTES`] bytes.
///
/// # Errors
///
/// Returns [`CatalogError::InvalidName`] for any other input.
pub fn validate_name(raw: &str) -> Result<(), CatalogError> {
    ItemId::new(raw)
        .ok()
        .filter(|_| raw.len() <= MAX_NAME_BYTES)
        .map(|_| ())
        .ok_or(CatalogError::InvalidName)
}

/// Checks an item id.
///
/// # Errors
///
/// Returns [`CatalogError::InvalidId`] for any input outside the [`ItemId`] shape.
pub fn validate_id(raw: &str) -> Result<ItemId, CatalogError> {
    ItemId::new(raw).map_err(|_| CatalogError::InvalidId)
}

impl CatalogItem {
    /// Builds an item.
    ///
    /// A tool item takes a registry tool name and an exact version as the body.
    ///
    /// # Errors
    ///
    /// Returns the [`CatalogError`] of the first invalid field.
    pub fn new(kind: CatalogKind, id: &str, name: &str, body: &str) -> Result<Self, CatalogError> {
        let id = validate_id(id)?;
        validate_name(name)?;
        if kind == CatalogKind::Tool {
            ToolName::new(name).map_err(|_| CatalogError::UnknownTool)?;
            Version::new(body).map_err(|_| CatalogError::InvalidVersion)?;
        } else if body.is_empty() || body.len() > MAX_BODY_BYTES {
            return Err(CatalogError::InvalidBody);
        }
        Ok(Self {
            kind,
            id,
            name: name.to_owned(),
            body: body.to_owned(),
        })
    }

    /// The item kind.
    pub const fn kind(&self) -> CatalogKind {
        self.kind
    }

    /// The item id.
    pub const fn id(&self) -> &ItemId {
        &self.id
    }

    /// The item name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The item body.
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The content digest: sha256 over the domain prefix and each field, with its
    /// length as eight big-endian bytes before it.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CATALOG_ITEM_DOMAIN);
        for field in [
            self.kind.as_str().as_bytes(),
            self.id.as_str().as_bytes(),
            self.name.as_bytes(),
            self.body.as_bytes(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(id: &str, name: &str, body: &str) -> Result<CatalogItem, CatalogError> {
        CatalogItem::new(CatalogKind::Skill, id, name, body)
    }

    fn hostile() -> Vec<String> {
        vec![
            String::new(),
            "a\r".into(),
            "a\r\nb".into(),
            "a\nb".into(),
            "a\u{85}b".into(),
            "a\u{2028}b".into(),
            "a\u{2029}b".into(),
            "a\\b".into(),
            "a/b".into(),
            "a b".into(),
            " a".into(),
            "a ".into(),
            "a\tb".into(),
            "a\0b".into(),
            "caf\u{e9}".into(),
            "\u{ff41}".into(),
            "Abc".into(),
            "ABC".into(),
            "-a".into(),
            "_a".into(),
            "a.b".into(),
            "a".repeat(65),
        ]
    }

    #[test]
    fn hostile_ids_are_refused() {
        for raw in hostile() {
            assert_eq!(validate_id(&raw), Err(CatalogError::InvalidId), "{raw:?}");
            assert_eq!(
                skill(&raw, "ok", "x"),
                Err(CatalogError::InvalidId),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn hostile_names_are_refused() {
        let mut table = hostile();
        table.push("a".repeat(1000));
        for raw in table {
            assert_eq!(
                validate_name(&raw),
                Err(CatalogError::InvalidName),
                "{raw:?}"
            );
            assert_eq!(
                skill("ok", &raw, "x"),
                Err(CatalogError::InvalidName),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn good_ids_and_the_length_edge_pass() {
        for raw in ["a", "0", "a-b_c9", &"a".repeat(64)] {
            assert!(validate_id(raw).is_ok(), "{raw:?}");
            assert!(validate_name(raw).is_ok(), "{raw:?}");
        }
    }

    #[test]
    fn body_rules_for_non_tool_kinds() {
        assert_eq!(skill("a", "a", ""), Err(CatalogError::InvalidBody));
        let over = "x".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(skill("a", "a", &over), Err(CatalogError::InvalidBody));
        let edge = "x".repeat(MAX_BODY_BYTES);
        assert!(skill("a", "a", &edge).is_ok());
    }

    #[test]
    fn tool_items_must_be_in_the_registry() {
        let ok = CatalogItem::new(CatalogKind::Tool, "node", "node", "22.1.0");
        assert!(ok.is_ok());
        for name in ["nodejs", "rust"] {
            assert_eq!(
                CatalogItem::new(CatalogKind::Tool, "t", name, "1.0.0"),
                Err(CatalogError::UnknownTool),
                "{name}"
            );
        }
        for body in ["", "latest", "^1.0", "1.0.0\n", "1..0"] {
            assert_eq!(
                CatalogItem::new(CatalogKind::Tool, "node", "node", body),
                Err(CatalogError::InvalidVersion),
                "{body:?}"
            );
        }
    }

    #[test]
    fn every_registry_tool_is_accepted() {
        for tool in ToolName::ALL {
            let name = tool.as_str();
            assert!(CatalogItem::new(CatalogKind::Tool, name, name, "1.0.0").is_ok());
        }
    }

    #[test]
    fn digest_uses_the_domain_prefix_and_framing() {
        let item = skill("a", "n", "body").unwrap_or_else(|_| unreachable!());
        let mut hasher = Sha256::new();
        hasher.update(b"fleet-catalog-item-v1\0");
        for field in ["skill", "a", "n", "body"] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        let want: [u8; 32] = hasher.finalize().into();
        assert_eq!(item.digest(), want);
        let bare = Sha256::digest(b"skillanbody");
        assert_ne!(item.digest().as_slice(), bare.as_slice());
    }

    #[test]
    fn every_field_changes_the_digest() {
        let base = skill("a", "n", "b")
            .unwrap_or_else(|_| unreachable!())
            .digest();
        let variants = [
            CatalogItem::new(CatalogKind::Context, "a", "n", "b"),
            skill("c", "n", "b"),
            skill("a", "m", "b"),
            skill("a", "n", "c"),
        ];
        for v in variants {
            assert_ne!(v.unwrap_or_else(|_| unreachable!()).digest(), base);
        }
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        let one = skill("ab", "c", "d").unwrap_or_else(|_| unreachable!());
        let two = skill("a", "bc", "d").unwrap_or_else(|_| unreachable!());
        assert_ne!(one.digest(), two.digest());
    }

    #[test]
    fn errors_never_echo_input() {
        let err = skill("Secret\r", "n", "b").unwrap_err();
        assert!(!err.to_string().contains("Secret"));
    }

    #[test]
    fn kind_wire_names() {
        let names = [
            (CatalogKind::Skill, "skill"),
            (CatalogKind::Subagent, "subagent"),
            (CatalogKind::Tool, "tool"),
            (CatalogKind::Context, "context"),
        ];
        for (kind, want) in names {
            assert_eq!(kind.to_string(), want);
        }
    }
}

//! The model allowlist: the exact model ids an operator approved.
//!
//! Match is exact and case-sensitive. There is no prefix, glob, alias or trimming. The server
//! and fleetd both build a [`ModelAllowlist`] from their own config and call
//! [`ModelAllowlist::check`].

use std::fmt;

/// Longest accepted entry in bytes. Equal to the profile `model` cap.
pub const MAX_ENTRY_BYTES: usize = crate::MAX_MODEL_BYTES;

/// Most entries a list may hold.
pub const MAX_ENTRIES: usize = 256;

/// Most bytes of a raw list accepted by [`ModelAllowlist::parse`].
pub const MAX_LIST_BYTES: usize = MAX_ENTRIES * (MAX_ENTRY_BYTES + 1);

/// Most chars of a denied model name kept for display.
const MAX_DENIED_CHARS: usize = MAX_ENTRY_BYTES;

/// Why a list or entry was refused.
///
/// Carries no input: callers must not echo a configured or client-supplied value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelAllowlistError {
    /// The list holds no entries.
    Empty,
    /// An entry is empty.
    EmptyEntry,
    /// An entry is longer than [`MAX_ENTRY_BYTES`].
    EntryTooLong,
    /// An entry holds a byte outside the allowed set.
    BadEntry,
    /// The same entry appears twice.
    Duplicate,
    /// The list holds more than [`MAX_ENTRIES`] entries or [`MAX_LIST_BYTES`] bytes.
    TooMany,
}

impl fmt::Display for ModelAllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "model allowlist is empty",
            Self::EmptyEntry => "model allowlist has an empty entry",
            Self::EntryTooLong => "model allowlist entry is too long",
            Self::BadEntry => "model allowlist entry has a disallowed character",
            Self::Duplicate => "model allowlist has a duplicate entry",
            Self::TooMany => "model allowlist is too large",
        })
    }
}

impl std::error::Error for ModelAllowlistError {}

/// A model is not in the allowlist.
///
/// Holds the requested name in a sanitised, capped form that is safe to log or show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDenied {
    model: String,
}

impl ModelDenied {
    /// The denied model name, escaped and capped.
    ///
    /// Unsafe characters are escaped as `\u{..}`, but `<`, `>`, `"`, `'`, `&` and the backtick
    /// are kept. A caller that renders the name as HTML or markdown must escape it.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
}

impl fmt::Display for ModelDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model {} is not in the allowlist", self.model)
    }
}

impl std::error::Error for ModelDenied {}

/// A non-empty, duplicate-free set of exact model ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelAllowlist {
    entries: Vec<String>,
}

/// Whether a char is escaped in a displayed model name.
///
/// Only ASCII graphic chars and chars for which [`char::is_alphanumeric`] holds are kept. That
/// excludes the general categories Cc, Cf, Zl, Zp, Zs, Co and Cn without a hand-kept range list.
fn is_unsafe_char(c: char) -> bool {
    !(c.is_ascii_graphic() || c.is_alphanumeric())
}

fn sanitise(model: &str) -> String {
    let mut out = String::new();
    for (kept, c) in model.chars().take(MAX_DENIED_CHARS + 1).enumerate() {
        if kept == MAX_DENIED_CHARS {
            out.push('\u{2026}');
            break;
        }
        if is_unsafe_char(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

impl ModelAllowlist {
    /// Validates one entry: non-empty, at most [`MAX_ENTRY_BYTES`] bytes, and only ASCII letters,
    /// digits and `.`, `_`, `-`, `:`, `/`, `[`, `]`.
    ///
    /// # Errors
    ///
    /// Returns the first rule the entry breaks.
    pub fn validate_entry(entry: &str) -> Result<(), ModelAllowlistError> {
        if entry.is_empty() {
            return Err(ModelAllowlistError::EmptyEntry);
        }
        if entry.len() > MAX_ENTRY_BYTES {
            return Err(ModelAllowlistError::EntryTooLong);
        }
        let ok = entry.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/' | b'[' | b']')
        });
        if ok {
            Ok(())
        } else {
            Err(ModelAllowlistError::BadEntry)
        }
    }

    /// Builds a list from entries.
    ///
    /// # Errors
    ///
    /// Returns [`ModelAllowlistError`] for an empty list, an invalid entry, a duplicate, or more
    /// than [`MAX_ENTRIES`] entries.
    pub fn new<I, S>(entries: I) -> Result<Self, ModelAllowlistError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut out: Vec<String> = Vec::new();
        for entry in entries {
            if out.len() == MAX_ENTRIES {
                return Err(ModelAllowlistError::TooMany);
            }
            let entry = entry.into();
            Self::validate_entry(&entry)?;
            if out.contains(&entry) {
                return Err(ModelAllowlistError::Duplicate);
            }
            out.push(entry);
        }
        if out.is_empty() {
            return Err(ModelAllowlistError::Empty);
        }
        Ok(Self { entries: out })
    }

    /// Parses a comma-separated list. The comma is the only separator and nothing is trimmed.
    ///
    /// # Errors
    ///
    /// Returns [`ModelAllowlistError`] as [`ModelAllowlist::new`] does, and
    /// [`ModelAllowlistError::TooMany`] for a raw list over [`MAX_LIST_BYTES`] bytes.
    pub fn parse(raw: &str) -> Result<Self, ModelAllowlistError> {
        if raw.len() > MAX_LIST_BYTES {
            return Err(ModelAllowlistError::TooMany);
        }
        Self::new(raw.split(','))
    }

    /// The entries in configured order.
    #[must_use]
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Whether the model equals an entry exactly.
    #[must_use]
    pub fn allows(&self, model: &str) -> bool {
        self.entries.iter().any(|e| e == model)
    }

    /// Checks a model against the list.
    ///
    /// # Errors
    ///
    /// Returns [`ModelDenied`] carrying the sanitised model name when it matches no entry.
    pub fn check(&self, model: &str) -> Result<(), ModelDenied> {
        if self.allows(model) {
            Ok(())
        } else {
            Err(ModelDenied {
                model: sanitise(model),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(raw: &str) -> ModelAllowlist {
        ModelAllowlist::parse(raw).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn exact_match_passes() {
        let l = list("claude-opus-4-1,claude-sonnet-4-5");
        assert_eq!(l.check("claude-opus-4-1"), Ok(()));
        assert_eq!(l.check("claude-sonnet-4-5"), Ok(()));
        assert_eq!(l.entries().len(), 2);
    }

    #[test]
    fn near_misses_are_denied() {
        let l = list("claude-opus-4-1");
        for model in [
            "Claude-Opus-4-1",
            "CLAUDE-OPUS-4-1",
            "claude-opus",
            "claude-opus-4-1-20250805",
            "claude-opus-4-1 ",
            " claude-opus-4-1",
            "claude-*",
            "claude-opus-4-1\n",
            "",
        ] {
            assert!(l.check(model).is_err(), "{model:?}");
        }
    }

    #[test]
    fn denied_carries_the_model_name() {
        let denied = list("a").check("gpt-5").err();
        assert_eq!(denied.as_ref().map(ModelDenied::model), Some("gpt-5"));
        assert_eq!(
            denied.map(|d| d.to_string()).as_deref(),
            Some("model gpt-5 is not in the allowlist")
        );
    }

    #[test]
    fn denied_name_is_escaped_and_capped() {
        let l = list("a");
        let cases: &[(&str, &str)] = &[
            ("lf", "x\ny"),
            ("cr", "x\ry"),
            ("crlf", "x\r\ny"),
            ("nel", "x\u{85}y"),
            ("line separator", "x\u{2028}y"),
            ("paragraph separator", "x\u{2029}y"),
            ("space", "x y"),
            ("nbsp", "x\u{a0}y"),
            ("nul", "x\0y"),
            ("escape", "x\u{1b}[31my"),
            ("bidi override", "x\u{202e}y"),
            ("zero width", "x\u{200b}y"),
            ("private use", "x\u{e000}y"),
            ("noncharacter", "x\u{fffe}y"),
        ];
        for (label, raw) in cases {
            let shown = l
                .check(raw)
                .err()
                .map(|d| d.model().to_owned())
                .unwrap_or_default();
            assert!(
                shown
                    .chars()
                    .all(|c| c.is_ascii_graphic() || c.is_alphanumeric()),
                "{label}: {shown:?}"
            );
            assert!(shown.contains("\\u{"), "{label}: {shown:?}");
        }
        let long = "m".repeat(1 << 20);
        let shown = l
            .check(&long)
            .err()
            .map(|d| d.model().to_owned())
            .unwrap_or_default();
        assert_eq!(shown.chars().count(), MAX_ENTRY_BYTES + 1);
        assert!(shown.ends_with('\u{2026}'));
        let exact = "m".repeat(MAX_ENTRY_BYTES);
        let shown = l
            .check(&exact)
            .err()
            .map(|d| d.model().to_owned())
            .unwrap_or_default();
        assert_eq!(shown, exact);
    }

    #[test]
    fn empty_list_is_an_error() {
        assert_eq!(
            ModelAllowlist::new(Vec::<String>::new()),
            Err(ModelAllowlistError::Empty)
        );
        assert_eq!(
            ModelAllowlist::parse(""),
            Err(ModelAllowlistError::EmptyEntry)
        );
    }

    #[test]
    fn hostile_entries_are_refused() {
        let long = "a".repeat(MAX_ENTRY_BYTES + 1);
        let table: &[(&str, &str, ModelAllowlistError)] = &[
            ("empty", "", ModelAllowlistError::EmptyEntry),
            ("trailing comma", "a,", ModelAllowlistError::EmptyEntry),
            ("leading comma", ",a", ModelAllowlistError::EmptyEntry),
            ("double comma", "a,,b", ModelAllowlistError::EmptyEntry),
            ("only comma", ",", ModelAllowlistError::EmptyEntry),
            ("space after comma", "a, b", ModelAllowlistError::BadEntry),
            ("space before comma", "a ,b", ModelAllowlistError::BadEntry),
            ("tab", "a\t", ModelAllowlistError::BadEntry),
            ("lf", "a\n", ModelAllowlistError::BadEntry),
            ("cr", "a\r", ModelAllowlistError::BadEntry),
            ("crlf", "a\r\n", ModelAllowlistError::BadEntry),
            ("nel", "a\u{85}", ModelAllowlistError::BadEntry),
            ("line separator", "a\u{2028}", ModelAllowlistError::BadEntry),
            (
                "paragraph separator",
                "a\u{2029}",
                ModelAllowlistError::BadEntry,
            ),
            ("nbsp", "a\u{a0}", ModelAllowlistError::BadEntry),
            ("nul", "a\0", ModelAllowlistError::BadEntry),
            ("userinfo at", "user@host", ModelAllowlistError::BadEntry),
            (
                "userinfo colon at",
                "user:pw@host",
                ModelAllowlistError::BadEntry,
            ),
            ("backslash", "a\\b", ModelAllowlistError::BadEntry),
            ("ipv6", "[::1]%eth0", ModelAllowlistError::BadEntry),
            ("quote", "\"a\"", ModelAllowlistError::BadEntry),
            ("glob star", "a*", ModelAllowlistError::BadEntry),
            ("glob question", "a?", ModelAllowlistError::BadEntry),
            ("percent", "a%20b", ModelAllowlistError::BadEntry),
            (
                "non-ascii letter",
                "clau\u{e9}",
                ModelAllowlistError::BadEntry,
            ),
            ("fullwidth", "\u{ff41}", ModelAllowlistError::BadEntry),
            ("zero width", "a\u{200b}", ModelAllowlistError::BadEntry),
            ("kelvin", "\u{212a}", ModelAllowlistError::BadEntry),
            (
                "over long",
                long.as_str(),
                ModelAllowlistError::EntryTooLong,
            ),
            ("duplicate", "a,a", ModelAllowlistError::Duplicate),
        ];
        for (label, raw, want) in table {
            assert_eq!(ModelAllowlist::parse(raw), Err(*want), "{label}");
        }
    }

    #[test]
    fn case_variants_are_distinct_entries() {
        let l = list("a,A");
        assert_eq!(l.entries(), ["a", "A"]);
    }

    #[test]
    fn entry_at_the_cap_passes_and_one_over_fails() {
        let at = "a".repeat(MAX_ENTRY_BYTES);
        assert_eq!(ModelAllowlist::validate_entry(&at), Ok(()));
        let over = "a".repeat(MAX_ENTRY_BYTES + 1);
        assert_eq!(
            ModelAllowlist::validate_entry(&over),
            Err(ModelAllowlistError::EntryTooLong)
        );
    }

    #[test]
    fn entry_cap_matches_the_profile_model_cap() {
        assert_eq!(MAX_ENTRY_BYTES, crate::MAX_MODEL_BYTES);
    }

    #[test]
    fn list_size_cap_is_enforced_on_both_paths() {
        let at: Vec<String> = (0..MAX_ENTRIES).map(|i| format!("m{i}")).collect();
        assert!(ModelAllowlist::new(at.clone()).is_ok());
        assert!(ModelAllowlist::parse(&at.join(",")).is_ok());
        let mut over = at;
        over.push("extra".to_owned());
        assert_eq!(
            ModelAllowlist::new(over.clone()),
            Err(ModelAllowlistError::TooMany)
        );
        assert_eq!(
            ModelAllowlist::parse(&over.join(",")),
            Err(ModelAllowlistError::TooMany)
        );
        let huge = "a".repeat(MAX_LIST_BYTES + 1);
        assert_eq!(
            ModelAllowlist::parse(&huge),
            Err(ModelAllowlistError::TooMany)
        );
    }

    #[test]
    fn realistic_ids_pass() {
        for id in [
            "claude-opus-4-1",
            "claude-opus-4-1[1m]",
            "us.anthropic.claude-sonnet-4-5-v1:0",
            "vendor/model_name-1.5",
        ] {
            assert_eq!(ModelAllowlist::validate_entry(id), Ok(()), "{id}");
        }
    }

    #[test]
    fn errors_carry_no_input() {
        let msg = ModelAllowlist::parse("secret value")
            .err()
            .map(|e| e.to_string());
        assert_eq!(
            msg.as_deref(),
            Some("model allowlist entry has a disallowed character")
        );
    }
}

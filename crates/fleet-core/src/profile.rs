use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::tools::ToolSpec;

/// Domain-separation prefix hashed before the canonical bytes of a [`Profile`].
pub const PROFILE_HASH_DOMAIN: &[u8] = b"fleet-profile-v1\0";

/// Domain-separation prefix for a [`Profile`] that sets `tools` (ADR-0048).
pub const PROFILE_HASH_DOMAIN_V2: &[u8] = b"fleet-profile-v2\0";

/// Failures from parsing a [`Profile`] or a [`ProfileHash`].
///
/// Messages are fixed and never echo input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileError {
    /// The bytes are not a valid Profile: bad JSON, an unknown field, a wrong type or a bad value.
    Malformed,
    /// A hash string is not 64 lowercase hex characters.
    InvalidHash,
    /// The input is JSON and sets a non-empty `tools` field; only TOML input accepts it.
    ToolsNotAllowed,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("profile is not valid profile JSON"),
            Self::InvalidHash => f.write_str("profile hash is not 64 lowercase hex characters"),
            Self::ToolsNotAllowed => f.write_str("profile tools are accepted only from TOML input"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// A file with a relative path and inline text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFile {
    /// The file path.
    pub path: String,
    /// The file content.
    pub text: String,
}

/// A skill: a name and the inline files that make it up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Skill {
    /// The skill name.
    pub name: String,
    /// The skill files, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<ContextFile>,
}

/// An environment flag value: only `"0"` or `"1"` is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvFlag {
    /// The string `"0"`.
    Off,
    /// The string `"1"`.
    On,
}

impl Serialize for EnvFlag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Off => "0",
            Self::On => "1",
        })
    }
}

impl<'de> Deserialize<'de> for EnvFlag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "0" => Ok(Self::Off),
            "1" => Ok(Self::On),
            _ => Err(de::Error::custom("env flag must be \"0\" or \"1\"")),
        }
    }
}

struct EnvFlagsVisitor;

impl<'de> de::Visitor<'de> for EnvFlagsVisitor {
    type Value = BTreeMap<String, EnvFlag>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map of env flag names to \"0\" or \"1\"")
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut map = BTreeMap::new();
        while let Some((key, value)) = access.next_entry::<String, EnvFlag>()? {
            if map.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate env flag name"));
            }
        }
        Ok(map)
    }
}

fn deserialize_env_flags<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, EnvFlag>, D::Error> {
    deserializer.deserialize_map(EnvFlagsVisitor)
}

/// Permission rule lists inside [`Settings`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPermissions {
    /// Allow rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Deny rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

/// Attribution text for commits and pull requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    /// Commit attribution text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Pull request attribution text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
}

/// Agent settings carried by a [`Profile`]: permissions, model and attribution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Permission rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<SettingsPermissions>,
    /// Model name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Attribution text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
}

/// The agent config of one Job, as typed JSON (ADR-0034).
///
/// Every field is optional: `{}` is a valid Profile. Unknown fields are rejected at every depth,
/// so `claude_version` is not accepted. In the canonical form an absent field and an empty
/// list or map are the same, and both are omitted. A `null` equals an absent field only for
/// the `Option` fields (text, `model`, `max_turns`, `max_budget_usd`, `settings`); `null` for
/// `allow`, `deny`, `skills`, `context_files` or `env_flags` fails as
/// [`ProfileError::Malformed`].
///
/// `max_budget_usd` is a whole number of US cents, never a float, so each budget has one text form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Text of the `CLAUDE.md` file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_md: Option<String>,
    /// Extra context files, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_files: Vec<ContextFile>,
    /// Text placed before the prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_prefix: Option<String>,
    /// Prompt template; content rules are checked elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_template: Option<String>,
    /// Inline skills, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<Skill>,
    /// Allow rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Deny rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Model name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Turn limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_turns: Option<u32>,
    /// Budget limit in whole US cents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_budget_usd: Option<u64>,
    /// Environment flags by name.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_env_flags"
    )]
    pub env_flags: BTreeMap<String, EnvFlag>,
    /// Agent settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Settings>,
    /// Tool pins; accepted only from TOML input (ADR-0048).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolSpec>,
}

/// The sha256 identity of a [`Profile`]; displays as 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileHash([u8; 32]);

impl ProfileHash {
    /// The raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses 64 lowercase hex characters.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidHash`] on any other input.
    pub fn from_hex(raw: &str) -> Result<Self, ProfileError> {
        fn nibble(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            }
        }
        let bytes = raw.as_bytes();
        if bytes.len() != 64 {
            return Err(ProfileError::InvalidHash);
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
            let (Some(hi), Some(lo)) = (nibble(pair[0]), nibble(pair[1])) else {
                return Err(ProfileError::InvalidHash);
            };
            *slot = hi << 4 | lo;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for ProfileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ProfileHash {
    type Err = ProfileError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::from_hex(raw)
    }
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(item, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        leaf => out.push_str(&leaf.to_string()),
    }
}

impl Profile {
    /// Parses a Profile from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Malformed`] for bad JSON, a top level that is not an object,
    /// unknown fields, wrong types or an env flag other than `"0"` or `"1"`, and
    /// [`ProfileError::ToolsNotAllowed`] for a non-empty `tools`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.trim_ascii_start().first() != Some(&b'{') {
            return Err(ProfileError::Malformed);
        }
        let profile: Self = serde_json::from_slice(bytes).map_err(|_| ProfileError::Malformed)?;
        if profile.tools.is_empty() {
            Ok(profile)
        } else {
            Err(ProfileError::ToolsNotAllowed)
        }
    }

    /// Parses a Profile from the canonical JSON the server stores, which may carry `tools`.
    ///
    /// Only a caller that re-validates the profile and checks its hash against a trusted
    /// reference may use this; [`Profile::from_json`] stays the entry for untrusted input.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Malformed`] for bad JSON, a top level that is not an object,
    /// unknown fields, wrong types, an unknown tool or a version that is not an exact pin.
    pub fn from_stored_json(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.trim_ascii_start().first() != Some(&b'{') {
            return Err(ProfileError::Malformed);
        }
        serde_json::from_slice(bytes).map_err(|_| ProfileError::Malformed)
    }

    /// Parses a Profile from TOML text, the only input that accepts `tools`.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Malformed`] for bad TOML, unknown fields, wrong types, an unknown
    /// tool or a version that is not an exact pin.
    pub fn from_toml(text: &str) -> Result<Self, ProfileError> {
        toml::from_str(text).map_err(|_| ProfileError::Malformed)
    }

    /// The canonical JSON: keys sorted by byte at every depth, no whitespace, absent fields omitted.
    ///
    /// # Panics
    ///
    /// Never in practice: serialising a Profile to a JSON value cannot fail.
    pub fn canonical_json(&self) -> Vec<u8> {
        #[expect(
            clippy::expect_used,
            reason = "a Profile holds only strings, integers and lists, which always serialise"
        )]
        let value = if self.tools.len() > 1 {
            let mut sorted = self.clone();
            sorted.tools.sort_by(|a, b| {
                (a.name(), a.version().as_str()).cmp(&(b.name(), b.version().as_str()))
            });
            serde_json::to_value(&sorted)
        } else {
            serde_json::to_value(self)
        }
        .expect("profile serialises to a JSON value");
        let mut out = String::new();
        write_canonical(&value, &mut out);
        out.into_bytes()
    }

    /// The Profile hash: `sha256(PROFILE_HASH_DOMAIN + canonical bytes)`, or with
    /// [`PROFILE_HASH_DOMAIN_V2`] when `tools` is non-empty. Tools hash in sorted order.
    pub fn hash(&self) -> ProfileHash {
        let mut hasher = Sha256::new();
        hasher.update(if self.tools.is_empty() {
            PROFILE_HASH_DOMAIN
        } else {
            PROFILE_HASH_DOMAIN_V2
        });
        hasher.update(self.canonical_json());
        ProfileHash(hasher.finalize().into())
    }
}

/// Failure from parsing a [`Visibility`]. The message never echoes input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VisibilityError {
    /// The text is not exactly `private` or `shared`.
    Unknown,
}

impl fmt::Display for VisibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("visibility must be \"private\" or \"shared\""),
        }
    }
}

impl std::error::Error for VisibilityError {}

/// Who besides the owner may see a Profile (ADR-0052). Not part of the profile hash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// Only the owner sees the Profile. The default.
    #[default]
    Private,
    /// Every authenticated user sees published versions.
    Shared,
}

impl Visibility {
    /// The canonical text: `private` or `shared`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Shared => "shared",
        }
    }
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Visibility {
    type Err = VisibilityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "private" => Ok(Self::Private),
            "shared" => Ok(Self::Shared),
            _ => Err(VisibilityError::Unknown),
        }
    }
}

/// Failure from building an [`OwnerId`]. The message never echoes input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnerIdError {
    /// The id is zero or negative.
    NotPositive,
}

impl fmt::Display for OwnerIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPositive => f.write_str("owner id must be positive"),
        }
    }
}

impl std::error::Error for OwnerIdError {}

/// The user that owns a Profile: a positive user id (ADR-0052). Not part of the profile hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerId(i64);

impl OwnerId {
    /// Wraps a user id.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerIdError::NotPositive`] when `raw` is zero or negative.
    pub const fn new(raw: i64) -> Result<Self, OwnerIdError> {
        if raw > 0 {
            Ok(Self(raw))
        } else {
            Err(OwnerIdError::NotPositive)
        }
    }

    /// The user id.
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for OwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    const FULL: &str = r##"{
        "claude_md": "# hi",
        "context_files": [{"path": "a.md", "text": "A"}, {"path": "b.md", "text": "B"}],
        "prompt_prefix": "pre",
        "prompt_template": "do {prompt}",
        "skills": [{"name": "s", "files": [{"path": "SKILL.md", "text": "x"}]}],
        "allow": ["Read"],
        "deny": ["Bash(rm:*)"],
        "model": "opus",
        "max_turns": 5,
        "max_budget_usd": 250,
        "env_flags": {"A": "1", "B": "0"},
        "settings": {
            "permissions": {"allow": ["Read"], "deny": ["Edit"]},
            "model": "sonnet",
            "attribution": {"commit": "c", "pr": "p"}
        }
    }"##;

    fn parse(text: &str) -> Profile {
        Profile::from_json(text.as_bytes()).unwrap()
    }

    fn hash_of(value: &Value) -> ProfileHash {
        parse(&value.to_string()).hash()
    }

    #[test]
    fn empty_profile_is_stable() {
        let p = parse("{}");
        assert_eq!(p.canonical_json(), b"{}");
        assert_eq!(
            p.hash().to_string(),
            "ae3b72b934976ade67b839a89fe9467ab263185bf98f8b4e8bc2640bee3dd85d"
        );
    }

    #[test]
    fn order_and_whitespace_do_not_matter() {
        let compact = serde_json::to_string(&serde_json::from_str::<Value>(FULL).unwrap()).unwrap();
        let reordered = r##"{"settings":{"attribution":{"pr":"p","commit":"c"},"model":"sonnet","permissions":{"deny":["Edit"],"allow":["Read"]}},"env_flags":{"B":"0","A":"1"},"max_budget_usd":250,"max_turns":5,"model":"opus","deny":["Bash(rm:*)"],"allow":["Read"],"skills":[{"files":[{"text":"x","path":"SKILL.md"}],"name":"s"}],"prompt_template":"do {prompt}","prompt_prefix":"pre","context_files":[{"text":"A","path":"a.md"},{"text":"B","path":"b.md"}],"claude_md":"# hi"}"##;
        let base = parse(FULL).hash();
        assert_eq!(parse(&compact).hash(), base);
        assert_eq!(parse(reordered).hash(), base);
    }

    #[test]
    fn canonical_is_sorted_compact_and_idempotent() {
        let once = parse(FULL).canonical_json();
        let text = String::from_utf8(once.clone()).unwrap();
        assert!(text.starts_with(
            r##"{"allow":["Read"],"claude_md":"# hi","context_files":[{"path":"a.md","text":"A"}"##
        ));
        assert!(!text.contains(' ') || text.contains("# hi"));
        assert_eq!(Profile::from_json(&once).unwrap().canonical_json(), once);
    }

    #[test]
    fn every_field_change_changes_hash() {
        let base: Value = serde_json::from_str(FULL).unwrap();
        let base_hash = hash_of(&base);
        let mutations: [(&str, Value); 12] = [
            ("claude_md", "x".into()),
            (
                "context_files",
                serde_json::json!([{"path": "a.md", "text": "Z"}]),
            ),
            ("prompt_prefix", "x".into()),
            ("prompt_template", "x {prompt}".into()),
            ("skills", serde_json::json!([{"name": "t"}])),
            ("allow", serde_json::json!(["Grep"])),
            ("deny", serde_json::json!(["Grep"])),
            ("model", "haiku".into()),
            ("max_turns", 6.into()),
            ("max_budget_usd", 251.into()),
            ("env_flags", serde_json::json!({"A": "0"})),
            ("settings", serde_json::json!({"model": "haiku"})),
        ];
        let Value::Object(fields) = &base else {
            unreachable!()
        };
        assert_eq!(fields.len(), mutations.len());
        for (name, value) in mutations {
            let mut changed = base.clone();
            changed[name] = value;
            assert_ne!(hash_of(&changed), base_hash, "{name}");
        }
    }

    #[test]
    fn nested_setting_changes_change_hash() {
        let base = parse(FULL);
        let mut p = base.clone();
        p.settings
            .as_mut()
            .unwrap()
            .attribution
            .as_mut()
            .unwrap()
            .pr = Some("q".into());
        assert_ne!(p.hash(), base.hash());
        let mut p = base.clone();
        p.settings
            .as_mut()
            .unwrap()
            .permissions
            .as_mut()
            .unwrap()
            .deny
            .clear();
        assert_ne!(p.hash(), base.hash());
    }

    #[test]
    fn unknown_fields_rejected_at_every_depth() {
        let cases = [
            r#"{"claude_version":"1.0"}"#,
            r#"{"x":1}"#,
            r#"{"context_files":[{"path":"a","text":"b","x":1}]}"#,
            r#"{"skills":[{"name":"a","x":1}]}"#,
            r#"{"skills":[{"name":"a","files":[{"path":"a","text":"b","x":1}]}]}"#,
            r#"{"settings":{"x":1}}"#,
            r#"{"settings":{"permissions":{"x":1}}}"#,
            r#"{"settings":{"attribution":{"x":1}}}"#,
        ];
        for case in cases {
            assert_eq!(
                Profile::from_json(case.as_bytes()),
                Err(ProfileError::Malformed),
                "{case}"
            );
        }
    }

    #[test]
    fn env_flag_values_restricted() {
        for bad in [r#""2""#, r#""true""#, r#""""#, "1", "true", "null"] {
            let text = format!(r#"{{"env_flags":{{"A":{bad}}}}}"#);
            assert!(Profile::from_json(text.as_bytes()).is_err(), "{bad}");
        }
        let p = parse(r#"{"env_flags":{"A":"0","B":"1"}}"#);
        assert_eq!(p.canonical_json(), br#"{"env_flags":{"A":"0","B":"1"}}"#);
    }

    #[test]
    fn null_absent_and_empty_are_equal() {
        let empty = parse("{}").hash();
        assert_eq!(parse(r#"{"model":null,"max_turns":null}"#).hash(), empty);
        assert_eq!(
            parse(r#"{"allow":[],"env_flags":{},"skills":[]}"#).hash(),
            empty
        );
        assert_ne!(parse(r#"{"model":""}"#).hash(), empty);
    }

    #[test]
    fn array_order_matters() {
        let ab = parse(r#"{"allow":["a","b"]}"#).hash();
        let ba = parse(r#"{"allow":["b","a"]}"#).hash();
        assert_ne!(ab, ba);
    }

    #[test]
    fn floats_and_bad_types_rejected() {
        for text in [
            r#"{"max_budget_usd":1.0}"#,
            r#"{"max_turns":1.5}"#,
            r#"{"max_turns":-1}"#,
            r#"{"model":3}"#,
            "[]",
            "",
            "{",
        ] {
            assert_eq!(
                Profile::from_json(text.as_bytes()),
                Err(ProfileError::Malformed),
                "{text}"
            );
        }
    }

    #[test]
    fn duplicate_keys_rejected() {
        assert!(Profile::from_json(br#"{"model":"a","model":"b"}"#).is_err());
    }

    #[test]
    fn duplicate_env_flag_keys_rejected() {
        for text in [
            r#"{"env_flags":{"A":"1","A":"0"}}"#,
            r#"{"env_flags":{"A":"1","A":"1"}}"#,
            r#"{"env_flags":{"B":"0","A":"1","B":"0"}}"#,
        ] {
            assert_eq!(
                Profile::from_json(text.as_bytes()),
                Err(ProfileError::Malformed)
            );
        }
    }

    #[test]
    fn distinct_env_flag_keys_accepted() {
        let p = parse(r#"{"env_flags":{"A":"1","B":"0"}}"#);
        assert_eq!(p.env_flags.len(), 2);
    }

    #[test]
    fn nested_duplicate_keys_rejected() {
        for text in [
            r#"{"skills":[{"name":"a","name":"b","files":[]}]}"#,
            r#"{"skills":[{"name":"a","files":[{"path":"p","path":"q","text":"t"}]}]}"#,
            r#"{"context_files":[{"path":"p","text":"a","text":"b"}]}"#,
            r#"{"settings":{"model":"a","model":"b"}}"#,
            r#"{"settings":{"permissions":{"allow":[],"allow":["x"]}}}"#,
            r#"{"settings":{"attribution":{"pr":"a","pr":"b"}}}"#,
        ] {
            assert_eq!(
                Profile::from_json(text.as_bytes()),
                Err(ProfileError::Malformed)
            );
        }
    }

    #[test]
    fn unicode_round_trips() {
        let text = "h\u{e9}llo \u{1f600} \"q\" \\ \n";
        let p = Profile {
            claude_md: Some(text.to_owned()),
            ..Profile::default()
        };
        let back = Profile::from_json(&p.canonical_json()).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.hash(), p.hash());
        assert!(
            String::from_utf8(p.canonical_json())
                .unwrap()
                .contains('\u{e9}')
        );
    }

    #[test]
    fn errors_never_echo_input() {
        let err = Profile::from_json(br#"{"secret_field_name":1}"#).unwrap_err();
        assert!(!err.to_string().contains("secret_field_name"));
    }

    #[test]
    fn hash_hex_round_trips() {
        let h = parse(FULL).hash();
        let hex = h.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(ProfileHash::from_hex(&hex), Ok(h));
        assert_eq!(hex.parse::<ProfileHash>(), Ok(h));
        assert_eq!(h.as_bytes().len(), 32);
        for bad in [
            String::new(),
            hex.to_uppercase(),
            hex[..63].to_owned(),
            format!("{hex}0"),
            format!("g{}", &hex[1..]),
            format!("{}\u{e9}", &hex[2..]),
        ] {
            assert_eq!(
                ProfileHash::from_hex(&bad),
                Err(ProfileError::InvalidHash),
                "{bad}"
            );
        }
    }

    #[test]
    fn existing_profile_hash_is_unchanged() {
        assert_eq!(
            parse(FULL).hash().to_string(),
            "953f0c1f80437603baf0fba5868d12631a4e82651140146fa7ab4edd6c165baf"
        );
    }

    const TOOLS_TOML: &str = "model = \"opus\"\n[[tools]]\nname = \"node\"\nversion = \"20.11.1\"\n[[tools]]\nname = \"jq\"\nversion = \"1.7.1\"\n";

    fn toml_profile(tools: &[(&str, &str)]) -> Profile {
        let mut text = String::new();
        for (name, version) in tools {
            let _ = write!(
                text,
                "[[tools]]\nname = \"{name}\"\nversion = \"{version}\"\n"
            );
        }
        Profile::from_toml(&text).unwrap()
    }

    #[test]
    fn empty_tools_keep_v1_hash() {
        let p = Profile::from_toml("model = \"opus\"\n").unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"fleet-profile-v1\0");
        hasher.update(p.canonical_json());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(p.hash().as_bytes(), &expected);
        assert_eq!(p.canonical_json(), br#"{"model":"opus"}"#);
    }

    #[test]
    fn tools_use_v2_prefix_and_appear_in_canonical_json() {
        let p = toml_profile(&[("node", "20.11.1")]);
        let mut hasher = Sha256::new();
        hasher.update(b"fleet-profile-v2\0");
        hasher.update(p.canonical_json());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(p.hash().as_bytes(), &expected);
        assert_eq!(
            p.canonical_json(),
            br#"{"tools":[{"name":"node","version":"20.11.1"}]}"#
        );
    }

    #[test]
    fn tools_change_the_hash() {
        let none = Profile::default().hash();
        let one = toml_profile(&[("node", "20.11.1")]).hash();
        let other_version = toml_profile(&[("node", "20.11.2")]).hash();
        let other_tool = toml_profile(&[("jq", "20.11.1")]).hash();
        let both = toml_profile(&[("node", "20.11.1"), ("jq", "1.7.1")]).hash();
        let all = [none, one, other_version, other_tool, both];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn tool_order_does_not_change_the_hash() {
        let ab = toml_profile(&[("node", "20.11.1"), ("jq", "1.7.1"), ("uv", "0.4.0")]);
        let ba = toml_profile(&[("uv", "0.4.0"), ("node", "20.11.1"), ("jq", "1.7.1")]);
        assert_eq!(ab.hash(), ba.hash());
        assert_eq!(ab.canonical_json(), ba.canonical_json());
        assert_eq!(Profile::from_toml(TOOLS_TOML).unwrap().tools.len(), 2);
    }

    #[test]
    fn stored_json_accepts_tools_and_still_rejects_bad_entries() {
        let text = br#"{"tools":[{"name":"node","version":"20.11.1"}]}"#;
        assert_eq!(Profile::from_stored_json(text).unwrap().tools.len(), 1);
        for bad in [
            &br#"{"tools":[{"name":"emacs","version":"1"}]}"#[..],
            br#"{"tools":[{"name":"node","version":"latest"}]}"#,
            br"[]",
        ] {
            assert_eq!(Profile::from_stored_json(bad), Err(ProfileError::Malformed));
        }
    }

    #[test]
    fn json_input_with_tools_is_rejected() {
        let text = br#"{"tools":[{"name":"node","version":"20.11.1"}]}"#;
        assert_eq!(Profile::from_json(text), Err(ProfileError::ToolsNotAllowed));
        assert_eq!(
            ProfileError::ToolsNotAllowed.to_string(),
            "profile tools are accepted only from TOML input"
        );
        assert!(Profile::from_json(br#"{"tools":[]}"#).is_ok());
        assert!(Profile::from_json(br#"{"tools":null}"#).is_err());
    }

    #[test]
    fn toml_rejects_unknown_fields_tools_and_versions() {
        for text in [
            "claude_version = \"1\"\n",
            "[[tools]]\nname = \"node\"\nversion = \"20\"\nx = 1\n",
            "[[tools]]\nname = \"emacs\"\nversion = \"1\"\n",
            "[[tools]]\nname = \"node\"\nversion = \"latest\"\n",
            "[[tools]]\nname = \"node\"\n",
        ] {
            assert_eq!(
                Profile::from_toml(text),
                Err(ProfileError::Malformed),
                "{text}"
            );
        }
    }

    #[test]
    fn domain_prefix_is_applied() {
        let mut hasher = Sha256::new();
        hasher.update(b"fleet-profile-v1\0{}");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(parse("{}").hash().as_bytes(), &expected);
    }
}

#[cfg(test)]
mod visibility_tests {
    use super::*;

    #[test]
    fn visibility_default_is_private() {
        assert_eq!(Visibility::default(), Visibility::Private);
    }

    #[test]
    fn visibility_round_trips_canonical_text() {
        assert_eq!("private".parse::<Visibility>(), Ok(Visibility::Private));
        assert_eq!("shared".parse::<Visibility>(), Ok(Visibility::Shared));
        assert_eq!(Visibility::Private.as_str(), "private");
        assert_eq!(Visibility::Shared.to_string(), "shared");
    }

    #[test]
    fn visibility_rejects_hostile_text() {
        let long = "a".repeat(4096);
        let cases = [
            "",
            "Private",
            "SHARED",
            "Shared",
            " private",
            "shared ",
            "private\n",
            "shared\r",
            "private\r\n",
            "shared\u{85}",
            "private\u{2028}",
            "shared\0",
            "public",
            "privаte",
            "ｓhared",
            long.as_str(),
        ];
        for case in cases {
            assert_eq!(
                case.parse::<Visibility>(),
                Err(VisibilityError::Unknown),
                "{case:?}"
            );
        }
    }

    #[test]
    fn visibility_error_message_is_fixed() {
        let shown = VisibilityError::Unknown.to_string();
        assert_eq!(shown, "visibility must be \"private\" or \"shared\"");
    }

    #[test]
    fn owner_id_accepts_positive() {
        let owner = OwnerId::new(7).unwrap();
        assert_eq!(owner.get(), 7);
        assert_eq!(OwnerId::new(i64::MAX).unwrap().get(), i64::MAX);
        assert_eq!(OwnerId::new(1).unwrap().to_string(), "1");
    }

    #[test]
    fn owner_id_rejects_zero_and_negative() {
        for raw in [0, -1, i64::MIN] {
            assert_eq!(OwnerId::new(raw), Err(OwnerIdError::NotPositive));
        }
    }

    #[test]
    fn visibility_and_owner_do_not_change_profile_hash() {
        let profile: Profile = serde_json::from_str(r#"{"claude_md":"x"}"#).unwrap();
        let before = profile.hash();
        let _ = (Visibility::Shared, OwnerId::new(3).unwrap());
        assert_eq!(profile.hash(), before);
    }
}

/// Most entries a [`Selection`] holds.
pub const MAX_SELECTION: usize = 256;

/// Failures from building an [`ItemId`] or a [`Selection`]. Messages never echo input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectionError {
    /// The bytes are not a selection: bad JSON, a non-array, an unknown or duplicate key, a wrong type.
    Malformed,
    /// An item id breaks the id shape.
    InvalidId,
    /// Two entries name the same item id.
    Duplicate,
    /// An entry sets `enabled` to `true`; only switched-off items are stored (ADR-0053).
    EnabledEntry,
    /// More than [`MAX_SELECTION`] entries.
    TooMany,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "selection is not a valid list of entries",
            Self::InvalidId => "selection item id has an invalid shape",
            Self::Duplicate => "selection names an item id twice",
            Self::EnabledEntry => "selection stores only disabled items",
            Self::TooMany => "selection has too many entries",
        })
    }
}

impl std::error::Error for SelectionError {}

/// A catalog item id: 1 to [`ItemId::MAX_LEN`] bytes of `[a-z0-9_-]`, starting with `[a-z0-9]`.
///
/// Inferred, not part of the design: the shape is lowercase ASCII only, so an id has one
/// spelling and a case variant is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId(String);

impl ItemId {
    /// Longest id in bytes.
    pub const MAX_LEN: usize = 64;

    /// Checks the id shape.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionError::InvalidId`] for any other input.
    pub fn new(raw: &str) -> Result<Self, SelectionError> {
        let bytes = raw.as_bytes();
        let head_ok = bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let rest_ok = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
        if head_ok && rest_ok && bytes.len() <= Self::MAX_LEN {
            Ok(Self(raw.to_owned()))
        } else {
            Err(SelectionError::InvalidId)
        }
    }

    /// The id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Longest authored prompt text in bytes; mirrors the job prompt cap of 64 KiB.
pub const MAX_PROMPT_TEXT_BYTES: usize = 64 * 1024;

/// Failures from building a [`PromptText`]. Messages never echo input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PromptTextError {
    /// The text is longer than [`MAX_PROMPT_TEXT_BYTES`].
    TooLong,
    /// The text holds a refused character: NUL, a control character other than newline and tab
    /// (CR and NEL included), U+2028, U+2029 or a bidirectional control.
    ForbiddenChar,
}

impl fmt::Display for PromptTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "prompt text is too long",
            Self::ForbiddenChar => "prompt text has a forbidden character",
        })
    }
}

impl std::error::Error for PromptTextError {}

fn is_refused_char(c: char) -> bool {
    (c.is_control() && !matches!(c, '\n' | '\t'))
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{2028}' | '\u{2029}'
                | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// User-authored prompt text: 1 to [`MAX_PROMPT_TEXT_BYTES`] bytes, no NUL, no control
/// character other than newline and tab, no CR, no U+2028, U+2029 or bidirectional control.
///
/// Inferred, not part of the design: CR is refused so a text has one line ending, and
/// backslash and non-ASCII text are allowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PromptText(String);

impl PromptText {
    /// Longest text in bytes.
    pub const MAX_BYTES: usize = MAX_PROMPT_TEXT_BYTES;

    /// Checks the text. Empty text means absent and gives `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PromptTextError::TooLong`] past the cap and [`PromptTextError::ForbiddenChar`]
    /// for a refused character.
    pub fn new(raw: &str) -> Result<Option<Self>, PromptTextError> {
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.len() > Self::MAX_BYTES {
            return Err(PromptTextError::TooLong);
        }
        if raw.chars().any(is_refused_char) {
            return Err(PromptTextError::ForbiddenChar);
        }
        Ok(Some(Self(raw.to_owned())))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    item_id: String,
    #[serde(default)]
    enabled: Option<bool>,
}

/// The catalog items a Profile switches off, sorted by id with no duplicates (ADR-0053).
///
/// The wire form is an array of `{"item_id", "enabled"}` objects. A missing `enabled` and
/// `false` both mean switched off and are stored as `false`; `true` is refused with
/// [`SelectionError::EnabledEntry`], because a Profile inherits every enabled item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection(Vec<ItemId>);

impl Selection {
    /// Parses a Selection from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SelectionError::Malformed`] for bad JSON, a non-array, an unknown or duplicate
    /// key or a wrong type, and the other variants for a bad id, a repeated id, an enabled
    /// entry or more than [`MAX_SELECTION`] entries.
    pub fn from_json(bytes: &[u8]) -> Result<Self, SelectionError> {
        if bytes.trim_ascii_start().first() != Some(&b'[') {
            return Err(SelectionError::Malformed);
        }
        let raw: Vec<RawEntry> =
            serde_json::from_slice(bytes).map_err(|_| SelectionError::Malformed)?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: Vec<RawEntry>) -> Result<Self, SelectionError> {
        if raw.len() > MAX_SELECTION {
            return Err(SelectionError::TooMany);
        }
        let mut ids = Vec::with_capacity(raw.len());
        for entry in raw {
            if entry.enabled == Some(true) {
                return Err(SelectionError::EnabledEntry);
            }
            ids.push(ItemId::new(&entry.item_id)?);
        }
        ids.sort();
        if ids.iter().zip(ids.iter().skip(1)).any(|(a, b)| a == b) {
            return Err(SelectionError::Duplicate);
        }
        Ok(Self(ids))
    }

    /// The switched-off ids in sorted order.
    pub fn ids(&self) -> impl Iterator<Item = &ItemId> {
        self.0.iter()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing is switched off.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Selection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Entry<'a> {
            item_id: &'a str,
            enabled: bool,
        }
        serializer.collect_seq(self.0.iter().map(|id| Entry {
            item_id: id.as_str(),
            enabled: false,
        }))
    }
}

impl<'de> Deserialize<'de> for Selection {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Vec::<RawEntry>::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    fn parse(json: &str) -> Result<Selection, SelectionError> {
        Selection::from_json(json.as_bytes())
    }

    #[test]
    fn hostile_ids_are_refused() {
        let long = "a".repeat(ItemId::MAX_LEN + 1);
        let hostile = [
            "",
            " ",
            "a b",
            " a",
            "a ",
            "a\r",
            "a\r\nb",
            "a\nb",
            "a\u{85}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\\b",
            "a/b",
            "a\0b",
            "a\tb",
            "é",
            "caf\u{e9}",
            "\u{ff41}bc",
            "A",
            "Skill",
            "-a",
            "_a",
            "a.b",
            "a@b",
            long.as_str(),
        ];
        for id in hostile {
            assert_eq!(ItemId::new(id), Err(SelectionError::InvalidId), "{id:?}");
        }
    }

    #[test]
    fn well_formed_ids_are_accepted() {
        let max = "a".repeat(ItemId::MAX_LEN);
        for id in ["a", "0", "tdd", "my-skill_2", "a0", max.as_str()] {
            assert_eq!(
                ItemId::new(id).map(|i| i.as_str().to_owned()),
                Ok(id.to_owned())
            );
        }
    }

    #[test]
    fn disabled_entries_are_kept() {
        let s = parse(r#"[{"item_id":"b","enabled":false},{"item_id":"a"}]"#).unwrap_or_default();
        let ids: Vec<_> = s.ids().map(ItemId::as_str).collect();
        assert_eq!(ids, ["a", "b"]);
    }

    #[test]
    fn enabled_true_is_refused() {
        assert_eq!(
            parse(r#"[{"item_id":"a","enabled":true}]"#),
            Err(SelectionError::EnabledEntry)
        );
    }

    #[test]
    fn duplicate_ids_are_refused() {
        assert_eq!(
            parse(r#"[{"item_id":"a"},{"item_id":"a","enabled":false}]"#),
            Err(SelectionError::Duplicate)
        );
    }

    #[test]
    fn duplicate_keys_in_an_entry_are_refused() {
        assert_eq!(
            parse(r#"[{"item_id":"a","item_id":"b"}]"#),
            Err(SelectionError::Malformed)
        );
        assert_eq!(
            parse(r#"[{"item_id":"a","enabled":false,"enabled":false}]"#),
            Err(SelectionError::Malformed)
        );
    }

    #[test]
    fn malformed_shapes_are_refused() {
        for json in [
            "{}",
            "null",
            r#"["a"]"#,
            "[{}]",
            r#"[{"item_id":1}]"#,
            r#"[{"item_id":"a","extra":1}]"#,
            r#"[{"item_id":"a","enabled":"no"}]"#,
            r#"[{"item_id":null}]"#,
        ] {
            assert_eq!(parse(json), Err(SelectionError::Malformed), "{json}");
        }
    }

    #[test]
    fn invalid_id_in_json_is_refused() {
        assert_eq!(
            parse(r#"[{"item_id":"A"}]"#),
            Err(SelectionError::InvalidId)
        );
    }

    #[test]
    fn cap_is_enforced_just_over() {
        let build = |n: usize| {
            let items: Vec<_> = (0..n).map(|i| format!(r#"{{"item_id":"i{i}"}}"#)).collect();
            format!("[{}]", items.join(","))
        };
        assert_eq!(
            parse(&build(MAX_SELECTION)).map(|s| s.len()),
            Ok(MAX_SELECTION)
        );
        assert_eq!(
            parse(&build(MAX_SELECTION + 1)),
            Err(SelectionError::TooMany)
        );
    }

    #[test]
    fn serde_round_trip_is_canonical() {
        let s = parse(r#"[{"item_id":"b"},{"item_id":"a","enabled":false}]"#).unwrap_or_default();
        let json = serde_json::to_string(&s).unwrap_or_default();
        assert_eq!(
            json,
            r#"[{"item_id":"a","enabled":false},{"item_id":"b","enabled":false}]"#
        );
        assert_eq!(parse(&json), Ok(s));
    }

    #[test]
    fn deserialize_refuses_enabled_true() {
        let r: Result<Selection, _> = serde_json::from_str(r#"[{"item_id":"a","enabled":true}]"#);
        assert!(r.is_err());
    }
}

#[cfg(test)]
mod prompt_text_tests {
    use super::*;

    fn text(raw: &str) -> Result<Option<String>, PromptTextError> {
        PromptText::new(raw).map(|o| o.map(|t| t.as_str().to_owned()))
    }

    #[test]
    fn empty_means_absent() {
        assert_eq!(text(""), Ok(None));
    }

    #[test]
    fn cap_is_accepted_and_one_over_is_refused() {
        let at = "a".repeat(MAX_PROMPT_TEXT_BYTES);
        assert_eq!(text(&at), Ok(Some(at.clone())));
        let over = "a".repeat(MAX_PROMPT_TEXT_BYTES + 1);
        assert_eq!(text(&over), Err(PromptTextError::TooLong));
    }

    #[test]
    fn cap_counts_bytes_not_chars() {
        let at = "é".repeat(MAX_PROMPT_TEXT_BYTES / 2);
        assert_eq!(at.len(), MAX_PROMPT_TEXT_BYTES);
        assert!(text(&at).is_ok());
        let over = format!("{at}a");
        assert_eq!(text(&over), Err(PromptTextError::TooLong));
    }

    #[test]
    fn hostile_characters_are_refused() {
        let hostile = [
            "a\0b",
            "a\rb",
            "a\r\nb",
            "a\u{85}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{1b}b",
            "a\u{7f}b",
            "a\u{8}b",
            "a\u{b}b",
            "a\u{c}b",
            "a\u{9f}b",
            "a\u{61C}b",
            "a\u{200E}b",
            "a\u{200F}b",
            "a\u{202A}b",
            "a\u{202B}b",
            "a\u{202C}b",
            "a\u{202D}b",
            "a\u{202E}b",
            "a\u{2066}b",
            "a\u{2067}b",
            "a\u{2068}b",
            "a\u{2069}b",
            "\r",
        ];
        for raw in hostile {
            assert_eq!(text(raw), Err(PromptTextError::ForbiddenChar), "{raw:?}");
        }
    }

    #[test]
    fn plain_text_is_kept_verbatim() {
        let ok = [
            "a\nb\tc",
            "path C:\\x \\n",
            "h\u{e9}llo \u{4e16}\u{754c} \u{1f600}",
            "  padded  ",
            "\n",
        ];
        for raw in ok {
            assert_eq!(text(raw), Ok(Some(raw.to_owned())), "{raw:?}");
        }
    }

    #[test]
    fn errors_never_echo_input() {
        for e in [PromptTextError::TooLong, PromptTextError::ForbiddenChar] {
            assert!(!e.to_string().contains("secret"));
        }
        let shown = PromptText::new("secret\0").unwrap_err().to_string();
        assert!(!shown.contains("secret"));
    }
}

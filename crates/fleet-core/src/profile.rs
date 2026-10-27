use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Domain-separation prefix hashed before the canonical bytes of a [`Profile`].
pub const PROFILE_HASH_DOMAIN: &[u8] = b"fleet-profile-v1\0";

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
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("profile is not valid profile JSON"),
            Self::InvalidHash => f.write_str("profile hash is not 64 lowercase hex characters"),
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
/// so `claude_version` is not accepted. In the canonical form an absent field, a `null` and an
/// empty list or map are the same, and all are omitted.
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
    /// Returns [`ProfileError::Malformed`] for bad JSON, a top level that is not an object, unknown fields, wrong types or an env
    /// flag other than `"0"` or `"1"`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.trim_ascii_start().first() != Some(&b'{') {
            return Err(ProfileError::Malformed);
        }
        serde_json::from_slice(bytes).map_err(|_| ProfileError::Malformed)
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
        let value = serde_json::to_value(self).expect("profile serialises to a JSON value");
        let mut out = String::new();
        write_canonical(&value, &mut out);
        out.into_bytes()
    }

    /// The Profile hash: `sha256(PROFILE_HASH_DOMAIN + canonical bytes)`.
    pub fn hash(&self) -> ProfileHash {
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_HASH_DOMAIN);
        hasher.update(self.canonical_json());
        ProfileHash(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn domain_prefix_is_applied() {
        let mut hasher = Sha256::new();
        hasher.update(b"fleet-profile-v1\0{}");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(parse("{}").hash().as_bytes(), &expected);
    }
}

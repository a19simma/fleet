//! Profile tool registry, exact version pins and tool specs (ADR-0048).
//!
//! The registry is a closed list kept by the Box operator. A version is an exact pin.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest accepted version, in bytes.
pub const MAX_VERSION_BYTES: usize = 64;

/// Why a tool name, version or spec was refused. Messages carry no input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolError {
    /// The name is not in the operator registry.
    UnknownTool,
    /// The version is empty.
    EmptyVersion,
    /// The version exceeds [`MAX_VERSION_BYTES`].
    VersionTooLong,
    /// The version is not an exact pin.
    InvalidVersion,
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownTool => "tool is not in the registry",
            Self::EmptyVersion => "tool version is empty",
            Self::VersionTooLong => "tool version is too long",
            Self::InvalidVersion => "tool version is not an exact pin",
        })
    }
}

impl std::error::Error for ToolError {}

/// A tool in the operator registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ToolName {
    /// Node.js.
    Node,
    /// Python.
    Python,
    /// Go.
    Go,
    /// Java.
    Java,
    /// jq.
    Jq,
    /// just.
    Just,
    /// uv.
    Uv,
}

impl ToolName {
    /// Every registered tool, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::Node,
        Self::Python,
        Self::Go,
        Self::Java,
        Self::Jq,
        Self::Just,
        Self::Uv,
    ];

    /// The wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Python => "python",
            Self::Go => "go",
            Self::Java => "java",
            Self::Jq => "jq",
            Self::Just => "just",
            Self::Uv => "uv",
        }
    }

    /// Looks a wire name up in the registry.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::UnknownTool`] for any name outside the registry. Matching is
    /// exact and case-sensitive.
    pub fn new(raw: &str) -> Result<Self, ToolError> {
        Self::ALL
            .into_iter()
            .find(|name| name.as_str() == raw)
            .ok_or(ToolError::UnknownTool)
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ToolName {
    type Err = ToolError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}

impl Serialize for ToolName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ToolName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// An exact pinned version: dot-separated ASCII digit groups, then an optional
/// `-` prerelease of dot-separated ASCII alphanumeric groups.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version(String);

impl Version {
    /// Validates and wraps an exact version pin.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::EmptyVersion`], [`ToolError::VersionTooLong`] or
    /// [`ToolError::InvalidVersion`]. Ranges, aliases such as `latest`, wildcards,
    /// whitespace, control and non-ASCII bytes are all invalid.
    pub fn new(raw: &str) -> Result<Self, ToolError> {
        if raw.is_empty() {
            return Err(ToolError::EmptyVersion);
        }
        if raw.len() > MAX_VERSION_BYTES {
            return Err(ToolError::VersionTooLong);
        }
        let (core, pre) = match raw.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (raw, None),
        };
        let core_ok = core
            .split('.')
            .all(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_digit()));
        let pre_ok = pre.is_none_or(|p| {
            p.split('.').all(|g| {
                !g.is_empty()
                    && g.bytes().all(|b| b.is_ascii_alphanumeric())
                    && !g.eq_ignore_ascii_case("x")
                    && !g.eq_ignore_ascii_case("latest")
            })
        });
        if core_ok && pre_ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(ToolError::InvalidVersion)
        }
    }

    /// The version as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Version {
    type Err = ToolError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// One tool pin: a registry name and an exact version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    name: ToolName,
    version: Version,
}

impl ToolSpec {
    /// Builds a spec from a registry name and an exact version.
    ///
    /// # Errors
    ///
    /// Returns the [`ToolError`] of whichever part is invalid.
    pub fn new(name: &str, version: &str) -> Result<Self, ToolError> {
        Ok(Self {
            name: ToolName::new(name)?,
            version: Version::new(version)?,
        })
    }

    /// The tool name.
    pub const fn name(&self) -> ToolName {
        self.name
    }

    /// The pinned version.
    pub const fn version(&self) -> &Version {
        &self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long(n: usize) -> String {
        "1".repeat(n)
    }

    #[test]
    fn version_accepts_exact_pins() {
        for ok in [
            "1",
            "20.11.1",
            "3.12.0",
            "1.0.0-rc.1",
            "1.0.0-beta",
            "0.0.0",
        ] {
            assert_eq!(Version::new(ok).unwrap().as_str(), ok, "{ok}");
        }
        assert!(Version::new(&long(MAX_VERSION_BYTES)).is_ok());
    }

    #[test]
    fn version_rejects_hostile_table() {
        let over = long(MAX_VERSION_BYTES + 1);
        let rows: Vec<(&str, ToolError)> = vec![
            ("", ToolError::EmptyVersion),
            (&over, ToolError::VersionTooLong),
            ("latest", ToolError::InvalidVersion),
            ("LATEST", ToolError::InvalidVersion),
            ("stable", ToolError::InvalidVersion),
            ("lts", ToolError::InvalidVersion),
            ("~1.2.3", ToolError::InvalidVersion),
            ("^1.2.3", ToolError::InvalidVersion),
            (">1.2.3", ToolError::InvalidVersion),
            ("<1.2.3", ToolError::InvalidVersion),
            (">=1.2", ToolError::InvalidVersion),
            ("*", ToolError::InvalidVersion),
            ("1.*", ToolError::InvalidVersion),
            ("x", ToolError::InvalidVersion),
            ("1.x", ToolError::InvalidVersion),
            ("1.X.0", ToolError::InvalidVersion),
            ("1.0.0-x", ToolError::InvalidVersion),
            ("1.0.0-latest", ToolError::InvalidVersion),
            ("1.2 - 1.4", ToolError::InvalidVersion),
            ("1.2 || 1.3", ToolError::InvalidVersion),
            ("1.2,1.3", ToolError::InvalidVersion),
            (" 1.2.3", ToolError::InvalidVersion),
            ("1.2.3 ", ToolError::InvalidVersion),
            ("1. 2", ToolError::InvalidVersion),
            ("1\t2", ToolError::InvalidVersion),
            ("1.2.3\n", ToolError::InvalidVersion),
            ("1.2.3\r", ToolError::InvalidVersion),
            ("1.2.3\r\n", ToolError::InvalidVersion),
            ("1.2\u{85}", ToolError::InvalidVersion),
            ("1.2\u{2028}", ToolError::InvalidVersion),
            ("1.2\0", ToolError::InvalidVersion),
            ("１.２", ToolError::InvalidVersion),
            ("1.2.3é", ToolError::InvalidVersion),
            ("v1.2.3", ToolError::InvalidVersion),
            ("1..2", ToolError::InvalidVersion),
            (".1", ToolError::InvalidVersion),
            ("1.", ToolError::InvalidVersion),
            ("1.0.0-", ToolError::InvalidVersion),
            ("1.0.0-rc..1", ToolError::InvalidVersion),
            ("1.0.0-rc 1", ToolError::InvalidVersion),
            ("1.0.0+build", ToolError::InvalidVersion),
            ("-1", ToolError::InvalidVersion),
            ("@1.2", ToolError::InvalidVersion),
            ("1.2/../3", ToolError::InvalidVersion),
            ("1.2;rm", ToolError::InvalidVersion),
            ("1.2$HOME", ToolError::InvalidVersion),
        ];
        for (raw, want) in rows {
            assert_eq!(Version::new(raw), Err(want), "{raw:?}");
        }
    }

    #[test]
    fn registry_names_round_trip() {
        for name in ToolName::ALL {
            assert_eq!(ToolName::new(name.as_str()), Ok(name));
            assert_eq!(name.as_str().parse::<ToolName>(), Ok(name));
            let spec = ToolSpec::new(name.as_str(), "1.2.3").unwrap();
            assert_eq!(spec.name(), name);
            let json = serde_json::to_string(&spec).unwrap();
            assert_eq!(serde_json::from_str::<ToolSpec>(&json).unwrap(), spec);
        }
        let mut names: Vec<_> = ToolName::ALL.iter().map(|n| n.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ToolName::ALL.len());
    }

    #[test]
    fn registry_covers_the_operator_list() {
        let names: Vec<_> = ToolName::ALL.iter().map(|n| n.as_str()).collect();
        assert_eq!(names, ["node", "python", "go", "java", "jq", "just", "uv"]);
    }

    #[test]
    fn name_rejects_outside_registry() {
        for raw in [
            "",
            "Node",
            "NODE",
            "node ",
            " node",
            "node\n",
            "rust",
            "cargo:foo",
            "npm:left-pad",
            "github:a/b",
            "nodé",
            "node\0",
            "latest",
        ] {
            assert_eq!(ToolName::new(raw), Err(ToolError::UnknownTool), "{raw:?}");
        }
    }

    #[test]
    fn spec_reports_the_failing_part() {
        assert_eq!(ToolSpec::new("ruby", "1.0"), Err(ToolError::UnknownTool));
        assert_eq!(
            ToolSpec::new("node", "latest"),
            Err(ToolError::InvalidVersion)
        );
        assert_eq!(ToolSpec::new("node", ""), Err(ToolError::EmptyVersion));
    }

    #[test]
    fn spec_deserialises_exact_pin() {
        let spec: ToolSpec =
            serde_json::from_str(r#"{"name":"node","version":"20.11.1"}"#).unwrap();
        assert_eq!(spec.name(), ToolName::Node);
        assert_eq!(spec.version().as_str(), "20.11.1");
    }

    #[test]
    fn spec_deserialise_rejects_unknown_fields() {
        for field in [
            "hook",
            "hooks",
            "task",
            "tasks",
            "env",
            "postinstall",
            "backend",
            "run",
            "depends",
        ] {
            let json = format!(r#"{{"name":"node","version":"20.1","{field}":"x"}}"#);
            let err = serde_json::from_str::<ToolSpec>(&json)
                .unwrap_err()
                .to_string();
            assert!(err.contains("unknown field"), "{field}: {err}");
        }
    }

    #[test]
    fn spec_deserialise_rejects_bad_values_and_missing_fields() {
        for json in [
            r#"{"name":"node","version":"^20"}"#,
            r#"{"name":"node","version":"latest"}"#,
            r#"{"name":"node","version":""}"#,
            r#"{"name":"rust","version":"1.0"}"#,
            r#"{"name":"node"}"#,
            r#"{"version":"1.0"}"#,
            r#"{"name":"node","version":20}"#,
        ] {
            assert!(serde_json::from_str::<ToolSpec>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn errors_carry_no_input_text() {
        let secret = "SECRETVALUE^";
        let err = Version::new(secret).unwrap_err();
        assert!(!err.to_string().contains("SECRET"));
        let err = ToolName::new(secret).unwrap_err();
        assert!(!err.to_string().contains("SECRET"));
    }
}

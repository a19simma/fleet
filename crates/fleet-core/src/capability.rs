//! User capabilities: the closed set of grants a server User can hold.
//!
//! The canonical text of each capability is the only accepted spelling.

use std::fmt;
use std::str::FromStr;

/// A grant a User can hold. Admins grant and revoke capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Capability {
    /// Save a Profile that lists `tools` or selects a `tool` Catalog item, submit a Profile that lists `tools`, or have its blob served to a leased Box.
    ProfileTools,
    /// Store a `github_app` Credential and have its installation token minted for a Job (ADR-0058). Holders can mint write tokens for every repository the installation covers.
    ForgeGithubApp,
    /// Save, pin or run an Environment version that holds a script.
    EnvScripts,
}

/// A string is not the canonical text of any capability.
///
/// Carries no input: callers must not echo a client-supplied value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityError;

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown capability")
    }
}

impl std::error::Error for CapabilityError {}

impl Capability {
    /// Every capability. Adding a variant means adding it here and in [`Capability::as_str`].
    pub const ALL: &'static [Self] = &[Self::ProfileTools, Self::ForgeGithubApp, Self::EnvScripts];

    /// The canonical text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileTools => "profile:tools",
            Self::ForgeGithubApp => "forge:github_app",
            Self::EnvScripts => "env:scripts",
        }
    }

    /// Longest canonical text in bytes, derived from [`Capability::ALL`].
    pub const MAX_LEN: usize = {
        let mut max = 0;
        let mut rest = Self::ALL;
        while let [first, tail @ ..] = rest {
            let len = first.as_str().len();
            if len > max {
                max = len;
            }
            rest = tail;
        }
        max
    };

    /// Parses the canonical text exactly: no trimming, no case folding, no decoration.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError`] for anything but the canonical text of a capability.
    pub fn parse(raw: &str) -> Result<Self, CapabilityError> {
        if raw.len() > Self::MAX_LEN {
            return Err(CapabilityError);
        }
        Self::ALL
            .iter()
            .copied()
            .find(|c| c.as_str() == raw)
            .ok_or(CapabilityError)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = CapabilityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_text_is_profile_tools() {
        assert_eq!(Capability::ProfileTools.as_str(), "profile:tools");
        assert_eq!(Capability::ProfileTools.to_string(), "profile:tools");
    }

    #[test]
    fn canonical_text_is_forge_github_app() {
        assert_eq!(Capability::ForgeGithubApp.as_str(), "forge:github_app");
        assert_eq!(
            Capability::parse("forge:github_app"),
            Ok(Capability::ForgeGithubApp)
        );
        for raw in [
            "forge:github_app ",
            "Forge:github_app",
            "forge:github_app\n",
            "forge:github-app",
            "forge:github_pat",
            "forge:",
        ] {
            assert_eq!(Capability::parse(raw), Err(CapabilityError), "{raw:?}");
        }
    }

    #[test]
    fn canonical_text_is_env_scripts() {
        assert_eq!(Capability::EnvScripts.as_str(), "env:scripts");
        assert_eq!(Capability::EnvScripts.to_string(), "env:scripts");
        assert_eq!(Capability::parse("env:scripts"), Ok(Capability::EnvScripts));
        assert!(Capability::ALL.contains(&Capability::EnvScripts));
        for raw in [
            "ENV:SCRIPTS",
            "env:scripts ",
            " env:scripts",
            "env:scripts\n",
            "env:script",
            "env:scriptss",
            "env:",
        ] {
            assert_eq!(Capability::parse(raw), Err(CapabilityError), "{raw:?}");
        }
    }

    #[test]
    fn every_capability_round_trips() {
        for cap in Capability::ALL {
            assert_eq!(Capability::parse(cap.as_str()), Ok(*cap));
            assert_eq!(cap.to_string().parse::<Capability>(), Ok(*cap));
        }
    }

    #[test]
    fn hostile_inputs_are_refused() {
        let long = "a".repeat(1 << 20);
        let table: &[(&str, &str)] = &[
            ("empty", ""),
            ("space before", " profile:tools"),
            ("space after", "profile:tools "),
            ("tab", "profile:tools\t"),
            ("lf", "profile:tools\n"),
            ("cr", "profile:tools\r"),
            ("crlf", "profile:tools\r\n"),
            ("leading lf", "\nprofile:tools"),
            ("nel", "profile:tools\u{85}"),
            ("line separator", "profile:tools\u{2028}"),
            ("paragraph separator", "profile:tools\u{2029}"),
            ("nbsp", "profile:tools\u{a0}"),
            ("backslash", "profile\\:tools"),
            ("trailing backslash", "profile:tools\\"),
            ("upper first", "Profile:tools"),
            ("upper tools", "profile:Tools"),
            ("all upper", "PROFILE:TOOLS"),
            ("trailing colon", "profile:tools:"),
            ("leading colon", ":profile:tools"),
            ("no colon", "profiletools"),
            ("prefix only", "profile:"),
            ("fullwidth colon", "profile\u{ff1a}tools"),
            ("fullwidth letters", "ｐｒｏｆｉｌｅ:ｔｏｏｌｓ"),
            ("turkish dotless", "profıle:tools"),
            ("kelvin sign", "profile:tools\u{212a}"),
            ("zero width space", "profile:\u{200b}tools"),
            ("nul", "profile:tools\0"),
            ("embedded nul", "profile\0:tools"),
            ("doubled", "profile:toolsprofile:tools"),
            ("comma list", "profile:tools,profile:tools"),
            ("quoted", "\"profile:tools\""),
            ("other scope", "profile:other"),
            ("over long", long.as_str()),
        ];
        for (label, raw) in table {
            assert_eq!(Capability::parse(raw), Err(CapabilityError), "{label}");
        }
    }

    #[test]
    fn max_len_matches_longest_canonical_text() {
        let longest = Capability::ALL
            .iter()
            .map(|c| c.as_str().len())
            .max()
            .unwrap_or(0);
        assert_eq!(Capability::MAX_LEN, longest);
        assert_eq!(Capability::MAX_LEN, "forge:github_app".len());
    }

    #[test]
    fn error_message_carries_no_input() {
        assert_eq!(CapabilityError.to_string(), "unknown capability");
    }
}

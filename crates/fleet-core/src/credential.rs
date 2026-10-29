//! Credential kinds, shapes, validators and fingerprints.
//!
//! Nothing here prints, serialises or compares a secret value. Error messages are fixed
//! strings that carry no input text.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Shortest accepted credential, in bytes.
pub const MIN_CREDENTIAL_LEN: usize = 20;

/// Longest accepted credential, in bytes.
pub const MAX_CREDENTIAL_LEN: usize = 512;

/// Number of hex characters in a fingerprint.
pub const FINGERPRINT_HEX_LEN: usize = 12;

const FINGERPRINT_LABEL: &[u8] = b"fleet.credential.fingerprint.v1\0";

/// What a credential authenticates against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// Anthropic API key.
    AnthropicApiKey,
    /// Claude subscription OAuth token.
    ClaudeSubscriptionToken,
    /// GitHub fine-grained personal access token.
    GithubPat,
    /// Kimi membership key.
    KimiMembershipKey,
    /// Kimi platform key.
    KimiPlatformKey,
    /// Codex API key.
    CodexApiKey,
}

impl CredentialKind {
    /// Every kind, in wire-name order of declaration.
    pub const ALL: [Self; 6] = [
        Self::AnthropicApiKey,
        Self::ClaudeSubscriptionToken,
        Self::GithubPat,
        Self::KimiMembershipKey,
        Self::KimiPlatformKey,
        Self::CodexApiKey,
    ];

    /// Stable wire name.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AnthropicApiKey => "anthropic_api_key",
            Self::ClaudeSubscriptionToken => "claude_subscription_token",
            Self::GithubPat => "github_pat",
            Self::KimiMembershipKey => "kimi_membership_key",
            Self::KimiPlatformKey => "kimi_platform_key",
            Self::CodexApiKey => "codex_api_key",
        }
    }

    /// Parses a wire name.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.wire_name() == name)
    }

    const fn expected_prefix(self) -> Option<&'static str> {
        match self {
            Self::AnthropicApiKey | Self::ClaudeSubscriptionToken => Some("sk-ant-"),
            Self::KimiMembershipKey => Some("sk-kimi-"),
            Self::GithubPat | Self::KimiPlatformKey | Self::CodexApiKey => None,
        }
    }
}

/// How a credential reaches the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialShape {
    /// A fixed secret string.
    StaticSecret,
    /// A file the provider rewrites. Unsupported in v1.
    RefreshingFile,
}

impl CredentialShape {
    /// Stable wire name.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::StaticSecret => "static_secret",
            Self::RefreshingFile => "refreshing_file",
        }
    }
}

/// A secret value. Zeroed on drop, never printed, never serialised.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Takes ownership of the bytes of `value`.
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value.into_bytes()))
    }

    /// The raw bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the secret holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Overwrites the buffer with zeros and empties it.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Why a credential was rejected. Messages are fixed and carry no secret text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// The value is empty.
    Empty,
    /// The value is shorter than [`MIN_CREDENTIAL_LEN`].
    TooShort,
    /// The value is longer than [`MAX_CREDENTIAL_LEN`].
    TooLong,
    /// The value contains whitespace or control characters.
    Whitespace,
    /// The shape is not supported in v1.
    UnsupportedShape,
    /// The GitHub token is not a fine-grained `github_pat_` token.
    GithubNotFineGrained,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "credential is empty",
            Self::TooShort => "credential is too short",
            Self::TooLong => "credential is too long",
            Self::Whitespace => "credential contains whitespace or control characters",
            Self::UnsupportedShape => "credential shape is not supported in v1",
            Self::GithubNotFineGrained => {
                "github credential must be a fine-grained token starting with github_pat_"
            }
        })
    }
}

impl std::error::Error for CredentialError {}

/// A credential that passed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validated {
    /// True when the value lacks the expected, still unverified, provider prefix.
    pub unknown_prefix: bool,
}

/// Checks `value` against the rules of `kind` and `shape`.
///
/// Prefix checks for Anthropic and Kimi keys are lenient because the exact prefixes are
/// unverified: a mismatch sets [`Validated::unknown_prefix`] and still succeeds.
///
/// # Errors
///
/// Returns a [`CredentialError`] for an unsupported shape, an empty, short, long or
/// whitespace-containing value, or a GitHub token that is not fine-grained.
pub fn validate(
    kind: CredentialKind,
    shape: CredentialShape,
    value: &str,
) -> Result<Validated, CredentialError> {
    if shape == CredentialShape::RefreshingFile {
        return Err(CredentialError::UnsupportedShape);
    }
    if value.is_empty() {
        return Err(CredentialError::Empty);
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CredentialError::Whitespace);
    }
    if value.len() < MIN_CREDENTIAL_LEN {
        return Err(CredentialError::TooShort);
    }
    if value.len() > MAX_CREDENTIAL_LEN {
        return Err(CredentialError::TooLong);
    }
    if kind == CredentialKind::GithubPat {
        return if value.starts_with("github_pat_") {
            Ok(Validated {
                unknown_prefix: false,
            })
        } else {
            Err(CredentialError::GithubNotFineGrained)
        };
    }
    let unknown_prefix = kind
        .expected_prefix()
        .is_some_and(|prefix| !value.starts_with(prefix));
    Ok(Validated { unknown_prefix })
}

/// A short, stable identifier of a secret that reveals no part of it.
///
/// It is the first 12 hex characters of SHA-256 over a fixed label and the secret.
pub fn fingerprint(secret: &Secret) -> String {
    use fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_LABEL);
    hasher.update(secret.expose());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(FINGERPRINT_HEX_LEN);
    for byte in digest.iter().take(FINGERPRINT_HEX_LEN / 2) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
    const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
    const STATIC: CredentialShape = CredentialShape::StaticSecret;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn wire_names_round_trip_for_every_kind() {
        let names: Vec<_> = CredentialKind::ALL.iter().map(|k| k.wire_name()).collect();
        assert_eq!(
            names,
            [
                "anthropic_api_key",
                "claude_subscription_token",
                "github_pat",
                "kimi_membership_key",
                "kimi_platform_key",
                "codex_api_key"
            ]
        );
        for kind in CredentialKind::ALL {
            assert_eq!(CredentialKind::from_wire_name(kind.wire_name()), Some(kind));
        }
        assert_eq!(CredentialKind::from_wire_name("nope"), None);
        assert_eq!(
            CredentialShape::RefreshingFile.wire_name(),
            "refreshing_file"
        );
        assert_eq!(STATIC.wire_name(), "static_secret");
    }

    #[test]
    fn github_accepts_only_fine_grained() {
        let ok = validate(CredentialKind::GithubPat, STATIC, PAT);
        assert_eq!(
            ok,
            Ok(Validated {
                unknown_prefix: false
            })
        );
        for bad in [
            "ghp_abcdefghijklmnopqrstuvwxyz0123",
            "gho_abcdefghijklmnopqrstuvwxyz0123",
            "ghs_abcdefghijklmnopqrstuvwxyz0123",
            "ghu_abcdefghijklmnopqrstuvwxyz0123",
        ] {
            let err = validate(CredentialKind::GithubPat, STATIC, bad).unwrap_err();
            assert_eq!(err, CredentialError::GithubNotFineGrained);
            assert!(!err.to_string().contains(bad));
        }
    }

    #[test]
    fn empty_and_whitespace_are_rejected_for_every_kind() {
        for kind in CredentialKind::ALL {
            assert_eq!(validate(kind, STATIC, ""), Err(CredentialError::Empty));
            for bad in [
                " github_pat_abcdefghijklmnopqrstu",
                "github_pat_abcdefghij klmnopqrst",
                "github_pat_abcdefghijklmnopqrstu\n",
            ] {
                assert_eq!(
                    validate(kind, STATIC, bad),
                    Err(CredentialError::Whitespace)
                );
            }
        }
    }

    #[test]
    fn length_bounds_apply() {
        let short = "github_pat_x";
        assert_eq!(
            validate(CredentialKind::GithubPat, STATIC, short),
            Err(CredentialError::TooShort)
        );
        let long = format!("github_pat_{}", "a".repeat(MAX_CREDENTIAL_LEN));
        assert_eq!(
            validate(CredentialKind::GithubPat, STATIC, &long),
            Err(CredentialError::TooLong)
        );
    }

    #[test]
    fn refreshing_file_is_rejected_for_every_kind() {
        for kind in CredentialKind::ALL {
            assert_eq!(
                validate(kind, CredentialShape::RefreshingFile, PAT),
                Err(CredentialError::UnsupportedShape)
            );
        }
    }

    #[test]
    fn anthropic_prefix_is_lenient() {
        for kind in [
            CredentialKind::AnthropicApiKey,
            CredentialKind::ClaudeSubscriptionToken,
        ] {
            assert_eq!(
                validate(kind, STATIC, ANT),
                Ok(Validated {
                    unknown_prefix: false
                })
            );
            assert_eq!(
                validate(kind, STATIC, "zz-unknown-abcdefghijklmnopqrstuv"),
                Ok(Validated {
                    unknown_prefix: true
                })
            );
        }
    }

    #[test]
    fn kimi_membership_expects_its_prefix_leniently() {
        let kind = CredentialKind::KimiMembershipKey;
        assert_eq!(
            validate(kind, STATIC, "sk-kimi-abcdefghijklmnopqrstuv"),
            Ok(Validated {
                unknown_prefix: false
            })
        );
        assert_eq!(
            validate(kind, STATIC, "other-abcdefghijklmnopqrstuvwx"),
            Ok(Validated {
                unknown_prefix: true
            })
        );
    }

    #[test]
    fn kimi_platform_and_codex_accept_any_prefix() {
        for kind in [CredentialKind::KimiPlatformKey, CredentialKind::CodexApiKey] {
            assert_eq!(
                validate(kind, STATIC, "anything-abcdefghijklmnopqrstuvw"),
                Ok(Validated {
                    unknown_prefix: false
                })
            );
        }
    }

    #[test]
    fn fingerprint_is_stable_short_and_hides_the_secret() {
        let a = Secret::new(PAT.to_owned());
        let b = Secret::new(PAT.to_owned());
        let fp = fingerprint(&a);
        assert_eq!(fp, fingerprint(&b));
        assert_eq!(fp.len(), FINGERPRINT_HEX_LEN);
        assert!(
            fp.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert!(!PAT.starts_with(&fp));
        assert!(!PAT.contains(&fp));
        let other = Secret::new(format!("{PAT}x"));
        assert_ne!(fp, fingerprint(&other));
    }

    #[test]
    fn fingerprint_carries_a_label_in_the_hash_input() {
        let secret = Secret::new(PAT.to_owned());
        let bare = Sha256::digest(PAT.as_bytes());
        let mut bare_hex = String::new();
        for byte in bare.iter().take(6) {
            let _ = write!(bare_hex, "{byte:02x}");
        }
        assert_ne!(fingerprint(&secret), bare_hex);
    }

    #[test]
    fn debug_and_display_print_no_value() {
        let secret = Secret::new(PAT.to_owned());
        for text in [
            format!("{secret:?}"),
            format!("{secret}"),
            format!("{secret:#?}"),
        ] {
            assert!(!text.contains(PAT));
            assert!(!text.contains("github_pat_"));
            assert!(text.contains("REDACTED"));
        }
    }

    #[test]
    fn secret_zeroizes_on_drop_and_wipe() {
        assert_zeroize_on_drop::<Secret>();
        let mut secret = Secret::new(PAT.to_owned());
        assert_eq!(secret.len(), PAT.len());
        secret.wipe();
        assert!(secret.is_empty());
    }

    #[test]
    fn error_messages_carry_no_input() {
        let bad = "ghp_abcdefghijklmnopqrstuvwxyz0123";
        let err = validate(CredentialKind::GithubPat, STATIC, bad).unwrap_err();
        assert_eq!(
            err.to_string(),
            "github credential must be a fine-grained token starting with github_pat_"
        );
    }
}

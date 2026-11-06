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

/// Number of hex characters in a fingerprint. It must be even: an odd value would cut off
/// its last half byte without warning.
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
    /// GitHub App installation, minted into short-lived installation tokens.
    GithubApp,
    /// Kimi membership key.
    KimiMembershipKey,
    /// Kimi platform key.
    KimiPlatformKey,
    /// Codex API key.
    CodexApiKey,
}

impl CredentialKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::AnthropicApiKey,
        Self::ClaudeSubscriptionToken,
        Self::GithubPat,
        Self::GithubApp,
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
            Self::GithubApp => "github_app",
            Self::KimiMembershipKey => "kimi_membership_key",
            Self::KimiPlatformKey => "kimi_platform_key",
            Self::CodexApiKey => "codex_api_key",
        }
    }

    /// True for kinds that authenticate against the git forge.
    pub const fn is_forge(self) -> bool {
        matches!(self, Self::GithubPat | Self::GithubApp)
    }

    /// Parses a wire name.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.wire_name() == name)
    }

    const fn expected_prefix(self) -> Option<&'static str> {
        match self {
            Self::AnthropicApiKey | Self::ClaudeSubscriptionToken => Some("sk-ant-"),
            Self::KimiMembershipKey => Some("sk-kimi-"),
            Self::GithubPat | Self::GithubApp | Self::KimiPlatformKey | Self::CodexApiKey => None,
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

/// Longest accepted GitHub App installation id, in digits. It is the width of `u64::MAX`.
pub const MAX_INSTALLATION_ID_LEN: usize = 20;

/// Why an installation id was rejected. Messages are fixed and carry no input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationIdError {
    /// The id is empty, longer than [`MAX_INSTALLATION_ID_LEN`], or holds a non-digit.
    Malformed,
    /// The id starts with a zero, which includes zero itself.
    LeadingZero,
    /// The id does not fit in a `u64`.
    OutOfRange,
}

impl fmt::Display for InstallationIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "installation id must be 1 to 20 ASCII digits",
            Self::LeadingZero => "installation id must not start with zero",
            Self::OutOfRange => "installation id is out of range",
        })
    }
}

impl std::error::Error for InstallationIdError {}

/// Parses a GitHub App installation id.
///
/// The id is 1 to 20 ASCII digits, has no leading zero and fits in a `u64`. Nothing else
/// passes, so the value is safe to place in a URL path.
///
/// # Errors
///
/// Returns an [`InstallationIdError`] for any other input.
pub fn parse_installation_id(value: &str) -> Result<u64, InstallationIdError> {
    if value.is_empty()
        || value.len() > MAX_INSTALLATION_ID_LEN
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(InstallationIdError::Malformed);
    }
    if value.starts_with('0') {
        return Err(InstallationIdError::LeadingZero);
    }
    value.parse().map_err(|_| InstallationIdError::OutOfRange)
}

/// Longest accepted bot name, in bytes.
pub const MAX_BOT_NAME_LEN: usize = 64;

/// Longest accepted bot email, in bytes.
pub const MAX_BOT_EMAIL_LEN: usize = 128;

const BOT_EMAIL_SUFFIX: &str = "[bot]@users.noreply.github.com";

/// Why a git identity was rejected. Messages are fixed and carry no input text. An email over
/// [`MAX_BOT_EMAIL_LEN`] (128 bytes) is rejected as [`BotIdentityError::Email`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotIdentityError {
    /// The name is outside the grammar of ADR-0058 (SEC-006, SEC-012).
    Name,
    /// The email is outside the grammar of ADR-0058 (SEC-006, SEC-012).
    Email,
}

impl fmt::Display for BotIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Name => "bot name is outside the identity grammar",
            Self::Email => "bot email is outside the identity grammar",
        })
    }
}

impl std::error::Error for BotIdentityError {}

/// The git name and email a GitHub App Job commits under (ADR-0058).
///
/// The fields are private, so a value of this type always passed the grammar. `fleetd`
/// re-validates with the same constructor before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotIdentity {
    name: String,
    email: String,
}

impl BotIdentity {
    /// Builds an identity from `name` and `email`.
    ///
    /// The name is 1 to [`MAX_BOT_NAME_LEN`] ASCII bytes, starts with a letter or digit, ends
    /// with a letter, digit or `]`, and holds only letters, digits, space, `.`, `_`, `[`, `]`
    /// and `-`. The email is at most [`MAX_BOT_EMAIL_LEN`] bytes shaped
    /// `<digits>+<slug>[bot]@users.noreply.github.com` with a lowercase slug of letters, digits
    /// and `-`.
    ///
    /// # Errors
    ///
    /// Returns [`BotIdentityError::Name`] or [`BotIdentityError::Email`] for the first field
    /// outside its grammar.
    pub fn new(name: &str, email: &str) -> Result<Self, BotIdentityError> {
        if !valid_bot_name(name) {
            return Err(BotIdentityError::Name);
        }
        if !valid_bot_email(email) {
            return Err(BotIdentityError::Email);
        }
        Ok(Self {
            name: name.to_owned(),
            email: email.to_owned(),
        })
    }

    /// The git author and committer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The git author and committer email.
    pub fn email(&self) -> &str {
        &self.email
    }
}

fn valid_bot_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_BOT_NAME_LEN
        && first.is_ascii_alphanumeric()
        && (last.is_ascii_alphanumeric() || *last == b']')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b" ._[]-".contains(b))
}

fn valid_bot_email(email: &str) -> bool {
    if email.len() > MAX_BOT_EMAIL_LEN {
        return false;
    }
    let Some(local) = email.strip_suffix(BOT_EMAIL_SUFFIX) else {
        return false;
    };
    let Some((id, slug)) = local.split_once('+') else {
        return false;
    };
    !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_digit())
        && !slug.is_empty()
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A secret value. Zeroed on drop, never printed, never serialised.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Takes ownership of the bytes of `value`.
    ///
    /// Only this buffer is zeroed on drop. A copy the caller made of the text is the
    /// caller's to wipe.
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
    /// The `github_app` value is not an installation id.
    GithubAppInstallationId,
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
            Self::GithubAppInstallationId => "github_app value must be an installation id",
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
/// A `github_app` value must satisfy [`parse_installation_id`]. It skips the length bounds,
/// which suit tokens and not ids. Whether a user may store the kind is a capability check
/// the store makes at save.
///
/// # Errors
///
/// Returns a [`CredentialError`] for an unsupported shape, an empty, short, long or
/// whitespace-containing value, a GitHub token that is not fine-grained, or a `github_app`
/// value that is not an installation id. The error text never carries the value.
///
/// The whitespace check uses Unicode whitespace and control characters, so zero-width
/// characters pass. Length bounds count bytes.
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
    if kind == CredentialKind::GithubApp {
        return parse_installation_id(value)
            .map(|_| Validated {
                unknown_prefix: false,
            })
            .map_err(|_| CredentialError::GithubAppInstallationId);
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
///
/// The hash is unsalted and the label is the same everywhere, so a weak secret can be
/// guessed offline from its fingerprint, and one secret has one fingerprint across tenants.
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
    fn github_app_is_listed_and_installation_token_is_not() {
        assert!(CredentialKind::ALL.contains(&CredentialKind::GithubApp));
        assert_eq!(
            CredentialKind::from_wire_name("github_app"),
            Some(CredentialKind::GithubApp)
        );
        assert_eq!(
            CredentialKind::from_wire_name("github_installation_token"),
            None
        );
    }

    const BOT_EMAIL: &str = "12345+fleet-bot[bot]@users.noreply.github.com";

    #[test]
    fn bot_identity_accepts_the_grammar() {
        for name in [
            "a",
            "fleet-bot[bot]",
            "Fleet Bot",
            "x.y_z[1]",
            &format!("a{}b", "c".repeat(62)),
        ] {
            let id = BotIdentity::new(name, BOT_EMAIL).unwrap();
            assert_eq!(id.name(), name);
            assert_eq!(id.email(), BOT_EMAIL);
        }
        for email in [
            "1+a[bot]@users.noreply.github.com",
            "007+a-b-1[bot]@users.noreply.github.com",
        ] {
            assert!(BotIdentity::new("bot", email).is_ok(), "{email}");
        }
    }

    #[test]
    fn bot_name_hostile_input_table() {
        let long = "a".repeat(65);
        let edge = format!("a{}b", "c".repeat(63));
        for name in [
            "",
            " bot",
            "bot ",
            "-bot",
            ".bot",
            "bot-",
            "bot.",
            "bot_",
            "bot\n",
            "bot\r",
            "bot\r\n",
            "bot\0",
            "bot\u{85}",
            "bot\u{2028}",
            "bot\u{2029}",
            "bot<x>",
            "b<ot",
            "bot>",
            "b\"ot",
            "b'ot",
            "b/ot",
            "b\\ot",
            "b:ot",
            "b@ot",
            "b,ot",
            "b\tot",
            "bot\u{e9}",
            "b\u{ff41}",
            "\u{200b}bot",
            long.as_str(),
            edge.as_str(),
        ] {
            assert_eq!(
                BotIdentity::new(name, BOT_EMAIL),
                Err(BotIdentityError::Name),
                "{name:?}"
            );
        }
    }

    #[test]
    fn bot_email_hostile_input_table() {
        let long = format!("1+{}[bot]@users.noreply.github.com", "a".repeat(120));
        for email in [
            "",
            "bot@users.noreply.github.com",
            "+a[bot]@users.noreply.github.com",
            "a+b[bot]@users.noreply.github.com",
            "1+[bot]@users.noreply.github.com",
            "1+A[bot]@users.noreply.github.com",
            "1+a_b[bot]@users.noreply.github.com",
            "1+a[bot]@users.noreply.github.com\n",
            "1+a[bot]@users.noreply.github.com\r\n",
            "1+a[bot]@users.noreply.github.com ",
            " 1+a[bot]@users.noreply.github.com",
            "1+a[bot]@users.noreply.github.com\u{85}",
            "1+a[bot]@users.noreply.github.com\u{2028}",
            "1+a[bot]@Users.noreply.github.com",
            "1+a[bot]@users.noreply.github.com.evil.example",
            "x@evil.example,1+a[bot]@users.noreply.github.com",
            "1+a<b>[bot]@users.noreply.github.com",
            "1+a[bot]\0@users.noreply.github.com",
            "1+\u{e9}[bot]@users.noreply.github.com",
            "\u{0661}+a[bot]@users.noreply.github.com",
            "1+2+a[bot]@users.noreply.github.com",
            "-1+a[bot]@users.noreply.github.com",
            "1+a[bot]@users.noreply.github.com@x",
            "1+a[bot]@users\\.noreply.github.com",
            "1+a[Bot]@users.noreply.github.com",
            long.as_str(),
        ] {
            assert_eq!(
                BotIdentity::new("bot", email),
                Err(BotIdentityError::Email),
                "{email:?}"
            );
        }
    }

    #[test]
    fn bot_identity_errors_carry_no_input() {
        for err in [BotIdentityError::Name, BotIdentityError::Email] {
            assert_ne!(err.to_string(), "");
        }
    }

    #[test]
    fn github_app_validates_as_an_installation_id() {
        for ok in ["1", "12345678", "18446744073709551615"] {
            assert!(
                validate(CredentialKind::GithubApp, STATIC, ok).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "0",
            "012",
            "12a",
            "-1",
            "1/..",
            "18446744073709551616",
            "99999999999999999999",
            "123456789012345678901",
            "github_pat_11ABCDEFG0abcdefghijklmnop",
        ] {
            let err = validate(CredentialKind::GithubApp, STATIC, bad).unwrap_err();
            assert_eq!(err, CredentialError::GithubAppInstallationId, "{bad}");
            assert!(!err.to_string().contains(bad), "{bad}");
        }
        assert_eq!(
            validate(CredentialKind::GithubApp, STATIC, "").unwrap_err(),
            CredentialError::Empty
        );
        assert_eq!(
            validate(CredentialKind::GithubApp, STATIC, "1 2").unwrap_err(),
            CredentialError::Whitespace
        );
    }

    #[test]
    fn only_github_kinds_are_forge() {
        for kind in CredentialKind::ALL {
            let want = matches!(kind, CredentialKind::GithubPat | CredentialKind::GithubApp);
            assert_eq!(kind.is_forge(), want, "{}", kind.wire_name());
        }
    }

    #[test]
    fn installation_id_accepts_valid_values() {
        assert_eq!(parse_installation_id("1"), Ok(1));
        assert_eq!(parse_installation_id("12345678"), Ok(12_345_678));
        assert_eq!(parse_installation_id("18446744073709551615"), Ok(u64::MAX));
    }

    #[test]
    fn installation_id_hostile_input_table() {
        let malformed = [
            "",
            " ",
            " 1",
            "1 ",
            "1 2",
            "\t1",
            "1\n",
            "1\r\n",
            "\u{85}1",
            "1\u{2028}",
            "+1",
            "-1",
            "1.0",
            "1e3",
            "0x10",
            "1_000",
            "\u{0661}",
            "\u{ff11}",
            "1\u{200b}",
            "12a",
            "1/2",
            "1/..",
            "..",
            "../1",
            "1?x",
            "1#x",
            "1%2f",
            "1%2F2",
            "1\\2",
            "123456789012345678901",
            "000000000000000000000",
        ];
        for input in malformed {
            assert_eq!(
                parse_installation_id(input),
                Err(InstallationIdError::Malformed),
                "{input:?}"
            );
        }
        for input in ["0", "00", "01", "007", "01234567890123456789"] {
            assert_eq!(
                parse_installation_id(input),
                Err(InstallationIdError::LeadingZero),
                "{input:?}"
            );
        }
        for input in ["18446744073709551616", "99999999999999999999"] {
            assert_eq!(
                parse_installation_id(input),
                Err(InstallationIdError::OutOfRange),
                "{input:?}"
            );
        }
    }

    #[test]
    fn wire_names_round_trip_for_every_kind() {
        let names: Vec<_> = CredentialKind::ALL.iter().map(|k| k.wire_name()).collect();
        assert_eq!(
            names,
            [
                "anthropic_api_key",
                "claude_subscription_token",
                "github_pat",
                "github_app",
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

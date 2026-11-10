//! Git host names: the normalised [`HostName`], the [`HostKind`] and the [`Host`] row a User or
//! the migration seed can build.
//!
//! This module performs no IO. [`HostName::normalise`] accepts a bare DNS name and refuses
//! everything else with one [`HostError`] variant per row of the ADR-0068 hostile-input table. The
//! IDNA mapping and punycode conversion come from the `idna` crate. A name that passes here can
//! still resolve to a private address: the caller must vet the resolved addresses.

use std::fmt;

use idna::AsciiDenyList;

use crate::repo::{MAX_HOST_BYTES, MAX_LABEL_BYTES};
use crate::text::is_hostile;

/// Longest raw input, in bytes, before any IDNA work.
pub const MAX_RAW_HOST_BYTES: usize = 1024;

const GITHUB_HOST: &str = "github.com";

const RESERVED_SUFFIXES: &[&str] = &[
    "local",
    "localhost",
    "localdomain",
    "internal",
    "intranet",
    "private",
    "corp",
    "home",
    "lan",
    "invalid",
    "onion",
    "arpa",
];

/// Why a host name was refused. The text is fixed and never echoes the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// The input is empty.
    Empty,
    /// The raw input is over [`MAX_RAW_HOST_BYTES`].
    InputTooLong,
    /// A backslash.
    Backslash,
    /// Space, tab, CR, LF, NEL, U+2028, U+2029 or another Unicode whitespace character.
    Whitespace,
    /// A control character such as NUL.
    Control,
    /// An invisible or format character from the shared hostile set.
    Hostile,
    /// A scheme such as `https://`.
    Scheme,
    /// A path, query or fragment, or a leading `//`.
    Path,
    /// Userinfo (`user@host`).
    Userinfo,
    /// A port (`host:443`).
    Port,
    /// An IP literal in dotted, decimal, hex or bracketed form.
    IpLiteral,
    /// A wildcard.
    Wildcard,
    /// IDNA mapping or punycode decoding failed.
    Idna,
    /// A label mixes scripts.
    MixedScript,
    /// An empty label.
    EmptyLabel,
    /// A label starts or ends with a hyphen.
    LabelHyphen,
    /// A label is over 63 bytes.
    LabelTooLong,
    /// The name is over 253 bytes.
    NameTooLong,
    /// The name has no dot.
    SingleLabel,
    /// The name ends in a reserved suffix such as `.local` or `.internal`.
    ReservedSuffix,
    /// `github.com` is seeded by migration and cannot be added by a User.
    GithubReserved,
}

impl HostError {
    /// The fixed text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "host is empty",
            Self::InputTooLong => "host input is too long",
            Self::Backslash => "host contains a backslash",
            Self::Whitespace => "host contains whitespace",
            Self::Control => "host contains a control character",
            Self::Hostile => "host contains an invisible or format character",
            Self::Scheme => "host contains a scheme",
            Self::Path => "host contains a path, query or fragment",
            Self::Userinfo => "host contains userinfo",
            Self::Port => "host contains a port",
            Self::IpLiteral => "host is an IP address",
            Self::Wildcard => "host contains a wildcard",
            Self::Idna => "host is not a valid internationalised name",
            Self::MixedScript => "host label mixes scripts",
            Self::EmptyLabel => "host has an empty label",
            Self::LabelHyphen => "host label starts or ends with a hyphen",
            Self::LabelTooLong => "host label is over 63 bytes",
            Self::NameTooLong => "host is over 253 bytes",
            Self::SingleLabel => "host has no dot",
            Self::ReservedSuffix => "host ends in a reserved suffix",
            Self::GithubReserved => "github.com is reserved",
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for HostError {}

/// A normalised host name: lowercase ASCII, punycode, no trailing dot, at least two labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

impl HostName {
    /// Normalises and validates a host name typed by a User.
    ///
    /// # Errors
    ///
    /// Returns the [`HostError`] of the first hostile-input row the input matches.
    pub fn normalise(input: &str) -> Result<Self, HostError> {
        screen(input)?;
        let trimmed = input.strip_suffix('.').unwrap_or(input);
        let ascii = idna::domain_to_ascii_cow(trimmed.as_bytes(), AsciiDenyList::STD3)
            .map_err(|_| HostError::Idna)?
            .into_owned();
        check_ascii(&ascii)?;
        check_scripts(&ascii)?;
        Ok(Self(ascii))
    }

    /// The normalised name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn screen(input: &str) -> Result<(), HostError> {
    if input.is_empty() {
        return Err(HostError::Empty);
    }
    if input.len() > MAX_RAW_HOST_BYTES {
        return Err(HostError::InputTooLong);
    }
    for c in input.chars() {
        if c == '\\' {
            return Err(HostError::Backslash);
        }
        if c.is_whitespace() {
            return Err(HostError::Whitespace);
        }
        if c.is_control() {
            return Err(HostError::Control);
        }
        if is_hostile(c) {
            return Err(HostError::Hostile);
        }
    }
    if input.contains("://") {
        return Err(HostError::Scheme);
    }
    if input.contains(['/', '?', '#']) {
        return Err(HostError::Path);
    }
    if input.contains('@') {
        return Err(HostError::Userinfo);
    }
    if input.contains(['[', ']']) {
        return Err(HostError::IpLiteral);
    }
    if input.contains(':') {
        return Err(HostError::Port);
    }
    if input.contains('*') {
        return Err(HostError::Wildcard);
    }
    Ok(())
}

fn check_ascii(ascii: &str) -> Result<(), HostError> {
    if ascii.len() > MAX_HOST_BYTES {
        return Err(HostError::NameTooLong);
    }
    for label in ascii.split('.') {
        if label.is_empty() {
            return Err(HostError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_BYTES {
            return Err(HostError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(HostError::LabelHyphen);
        }
    }
    let last = ascii.rsplit('.').next().unwrap_or_default();
    if is_numeric_label(last) {
        return Err(HostError::IpLiteral);
    }
    if !ascii.contains('.') {
        return Err(HostError::SingleLabel);
    }
    if RESERVED_SUFFIXES.contains(&last) {
        return Err(HostError::ReservedSuffix);
    }
    Ok(())
}

fn is_numeric_label(label: &str) -> bool {
    let digits = label.strip_prefix("0x").unwrap_or(label);
    let hex = digits.len() != label.len();
    if hex && digits.is_empty() {
        return true;
    }
    !digits.is_empty()
        && digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (hex && b.is_ascii_hexdigit()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
    Other,
}

fn script_of(c: char) -> Option<Script> {
    if c.is_ascii_alphabetic() {
        return Some(Script::Latin);
    }
    if c.is_ascii() || !c.is_alphabetic() {
        return None;
    }
    Some(match u32::from(c) {
        0xC0..=0x2AF | 0x1E00..=0x1EFF => Script::Latin,
        0x370..=0x3FF | 0x1F00..=0x1FFF => Script::Greek,
        0x400..=0x52F => Script::Cyrillic,
        _ => Script::Other,
    })
}

fn check_scripts(ascii: &str) -> Result<(), HostError> {
    let (unicode, _) = idna::domain_to_unicode(ascii);
    for label in unicode.split('.') {
        let mut seen: Option<Script> = None;
        for script in label.chars().filter_map(script_of) {
            match seen {
                Some(first) if first != script => return Err(HostError::MixedScript),
                _ => seen = Some(script),
            }
        }
    }
    Ok(())
}

/// The kind of git host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostKind {
    /// `github.com`, seeded by migration only.
    Github,
    /// A Forgejo or Gitea host, the only kind a User can add.
    Forgejo,
}

impl HostKind {
    /// The stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Forgejo => "forgejo",
        }
    }

    /// Reads the stored text of a trusted row. Returns `None` for any other text.
    #[must_use]
    pub fn from_stored(text: &str) -> Option<Self> {
        match text {
            "github" => Some(Self::Github),
            "forgejo" => Some(Self::Forgejo),
            _ => None,
        }
    }
}

/// A host row: a normalised name and its kind.
///
/// The only constructors are [`Host::user_added`], which always yields [`HostKind::Forgejo`],
/// [`Host::seed_github`], and [`Host::from_row`] for a stored row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    name: HostName,
    kind: HostKind,
}

impl Host {
    /// A host a User added. The kind is always [`HostKind::Forgejo`], so a hostile host cannot
    /// claim to be GitHub, and `github.com` itself is refused.
    ///
    /// # Errors
    ///
    /// Returns the [`HostError`] of [`HostName::normalise`], or [`HostError::GithubReserved`].
    pub fn user_added(input: &str) -> Result<Self, HostError> {
        let name = HostName::normalise(input)?;
        if name.as_str() == GITHUB_HOST {
            return Err(HostError::GithubReserved);
        }
        Ok(Self {
            name,
            kind: HostKind::Forgejo,
        })
    }

    /// The `github.com` row the migration seeds.
    #[must_use]
    pub fn seed_github() -> Self {
        Self {
            name: HostName(GITHUB_HOST.to_owned()),
            kind: HostKind::Github,
        }
    }

    /// A host read back from a stored row.
    #[must_use]
    pub const fn from_row(name: HostName, kind: HostKind) -> Self {
        Self { name, kind }
    }

    /// The normalised name.
    #[must_use]
    pub const fn name(&self) -> &HostName {
        &self.name
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> HostKind {
        self.kind
    }
}

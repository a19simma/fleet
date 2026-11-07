//! Repository identity across forges: the parsed [`RepoRef`], the [`ForgeKind`] grammar choice, and
//! the [`RepoVerdict`] a forge check returns.
//!
//! This module performs no IO. [`RepoRef::parse`] reads `https://host/owner/name[.git]` or the bare
//! `host/owner/name` and refuses everything else. The GitHub grammar and its length caps match the
//! server App policy (`cred/app_policy.rs`). The Forgejo grammar exists only in core. Core also
//! refuses a name that still ends in `.git` after one suffix strip, and requires a host.
//!
//! A lexical parser cannot see what a name resolves to. A host that passes here can still resolve
//! to a loopback, private or link-local address. The fetcher must resolve the host once, vet every
//! returned address, and dial the vetted address.

use std::fmt::{self, Write as _};

/// Longest accepted input, in bytes.
pub const MAX_INPUT_BYTES: usize = 1024;

/// Longest GitHub account login, in bytes.
pub const MAX_GITHUB_OWNER_BYTES: usize = 39;

/// Longest GitHub repository name, in bytes.
pub const MAX_GITHUB_NAME_BYTES: usize = 100;

/// Longest Forgejo account name, in bytes.
pub const MAX_FORGEJO_OWNER_BYTES: usize = 40;

/// Longest Forgejo repository name, in bytes.
pub const MAX_FORGEJO_NAME_BYTES: usize = 100;

/// Longest host, in bytes.
pub const MAX_HOST_BYTES: usize = 253;

/// Longest host label, in bytes.
pub const MAX_LABEL_BYTES: usize = 63;

const GITHUB_HOST: &str = "github.com";
const HTTPS_PREFIX: &str = "https://";
const GIT_SUFFIX: &str = ".git";
const FORGEJO_RESERVED_SUFFIXES: &[&str] = &[".git", ".wiki", ".rss", ".atom"];
const FORGEJO_RESERVED_OWNERS: &[&str] = &[
    "admin",
    "api",
    "user",
    "explore",
    "login",
    "assets",
    "issues",
    "pulls",
    "notifications",
    "org",
    "repo",
    "attachments",
    "avatars",
    "favicon.ico",
    "robots.txt",
];
const FORGEJO_RESERVED_OWNER_SUFFIXES: &[&str] = &[".keys", ".gpg"];

/// The forge family that decides the segment grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeKind {
    /// GitHub: owner up to 39 and name up to 100 bytes.
    Github,
    /// Forgejo: owner up to 40 and name up to 100 bytes, with reserved owner names and suffixes
    /// and reserved repository names.
    Forgejo,
}

/// Why a repository reference was refused. The text is fixed and never echoes the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoError {
    /// The input is empty.
    Empty,
    /// The input is over the length cap.
    TooLong,
    /// A byte is outside printable ASCII, or a backslash.
    Charset,
    /// A percent escape.
    Percent,
    /// Userinfo, or the scp form `user@host:path`.
    Userinfo,
    /// A port.
    Port,
    /// A query or a fragment.
    QueryOrFragment,
    /// A scheme other than https.
    Scheme,
    /// The host is not an ASCII DNS name.
    Host,
    /// The host is an IP literal in any form.
    IpHost,
    /// The path is not exactly owner and name, or holds an empty, `.` or `..` segment.
    Segments,
    /// The owner is outside the grammar.
    Owner,
    /// The name is outside the grammar or reserved.
    Name,
}

impl fmt::Display for RepoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "repository is empty",
            Self::TooLong => "repository is too long",
            Self::Charset => "repository holds a character outside printable ASCII",
            Self::Percent => "repository holds a percent escape",
            Self::Userinfo => "repository holds userinfo",
            Self::Port => "repository holds a port",
            Self::QueryOrFragment => "repository holds a query or fragment",
            Self::Scheme => "repository scheme must be https",
            Self::Host => "repository host is not a valid DNS name",
            Self::IpHost => "repository host is an IP address",
            Self::Segments => "repository path must be exactly owner and name",
            Self::Owner => "repository owner is invalid",
            Self::Name => "repository name is invalid",
        })
    }
}

impl std::error::Error for RepoError {}

/// A repository: lowercase host, lowercase `owner/name`, and the path as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    host: String,
    path: String,
    display_path: String,
}

/// What a forge check reported for one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoVerdict {
    /// The lowercase `owner/name` the forge resolved.
    pub canonical_path: String,
    /// Whether the credential can read the repository.
    pub read: bool,
    /// Whether it can push, or `None` when unknown.
    pub push: Option<bool>,
    /// The login the credential acts as, when known.
    pub login: Option<String>,
}

impl RepoRef {
    /// Parses with the grammar picked by host: `github.com` is GitHub, any other host Forgejo.
    ///
    /// GitHub Enterprise hosts therefore get the Forgejo grammar here. A caller with an
    /// operator-configured host must use [`RepoRef::parse_as`] with the configured kind.
    ///
    /// # Errors
    ///
    /// Returns a [`RepoError`] naming the first rule the input breaks.
    pub fn parse(input: &str) -> Result<Self, RepoError> {
        let kind = match authority_of(input) {
            Some(host) if host.eq_ignore_ascii_case(GITHUB_HOST) => ForgeKind::Github,
            _ => ForgeKind::Forgejo,
        };
        Self::parse_as(input, kind)
    }

    /// Parses with an explicit forge grammar.
    ///
    /// # Errors
    ///
    /// Returns a [`RepoError`] naming the first rule the input breaks.
    pub fn parse_as(input: &str, kind: ForgeKind) -> Result<Self, RepoError> {
        let (host, owner, name) = split(input)?;
        if !valid_owner(owner, kind) {
            return Err(RepoError::Owner);
        }
        if !valid_name(name, kind) {
            return Err(RepoError::Name);
        }
        let display_path = format!("{owner}/{name}");
        Ok(Self {
            host,
            path: display_path.to_ascii_lowercase(),
            display_path,
        })
    }

    /// Splits a reference into its lowercase host and lowercase `owner/name` without applying
    /// any forge grammar.
    ///
    /// It applies every structural rule of [`RepoRef::parse_as`] (charset, scheme, host, exactly
    /// two segments, one `.git` strip) and the segment byte set, but not the owner and name
    /// rules of a forge. A caller that looks up a stored row uses it: the row was stored under
    /// the grammar of the kind the server holds for its host, which the caller cannot know.
    ///
    /// # Errors
    ///
    /// Returns a [`RepoError`] naming the first structural rule the input breaks.
    pub fn locate(input: &str) -> Result<(String, String), RepoError> {
        let (host, owner, name) = split(input)?;
        if !segment_bytes_ok(owner) || !segment_bytes_ok(name) {
            return Err(RepoError::Name);
        }
        Ok((host, format!("{owner}/{name}").to_ascii_lowercase()))
    }

    /// The lowercase host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The lowercase `owner/name`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The `owner/name` as written, without `.git`.
    #[must_use]
    pub fn display_path(&self) -> &str {
        &self.display_path
    }
}

/// Shows `text` in printable ASCII only: every other character becomes `\u{hex}`.
///
/// A stored host is punycode (`xn--` labels), because [`RepoRef::parse`] refuses non-ASCII input.
/// For a valid row this returns the text unchanged. A value that reached storage by another route
/// is shown with its code points visible, so a lookalike letter or a bidirectional mark can never
/// pass for the plain host.
#[must_use]
pub fn ascii_form(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii_graphic() {
            out.push(c);
        } else {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
    }
    out
}

fn split(input: &str) -> Result<(String, &str, &str), RepoError> {
    screen(input)?;
    let rest = match input.strip_prefix(HTTPS_PREFIX) {
        Some(rest) => rest,
        None if input.contains("://") => return Err(RepoError::Scheme),
        None => input,
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host_of(authority)?;
    let mut segments = path.split('/');
    let (Some(owner), Some(name), None) = (segments.next(), segments.next(), segments.next())
    else {
        return Err(RepoError::Segments);
    };
    if [owner, name].iter().any(|s| matches!(*s, "" | "." | "..")) {
        return Err(RepoError::Segments);
    }
    Ok((host, owner, strip_git_suffix(name)))
}

fn strip_git_suffix(name: &str) -> &str {
    let Some(cut) = name.len().checked_sub(GIT_SUFFIX.len()) else {
        return name;
    };
    match name.get(cut..) {
        Some(tail) if tail.eq_ignore_ascii_case(GIT_SUFFIX) => &name[..cut],
        _ => name,
    }
}

fn ends_with_ignore_case(value: &str, suffix: &str) -> bool {
    value
        .len()
        .checked_sub(suffix.len())
        .and_then(|cut| value.get(cut..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn authority_of(input: &str) -> Option<&str> {
    let rest = input.strip_prefix(HTTPS_PREFIX).unwrap_or(input);
    rest.split_once('/').map(|(authority, _)| authority)
}

fn screen(input: &str) -> Result<(), RepoError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(RepoError::TooLong);
    }
    if input.is_empty() {
        return Err(RepoError::Empty);
    }
    if input.bytes().any(|b| !b.is_ascii_graphic() || b == b'\\') {
        return Err(RepoError::Charset);
    }
    for (byte, error) in [
        (b'%', RepoError::Percent),
        (b'@', RepoError::Userinfo),
        (b'?', RepoError::QueryOrFragment),
        (b'#', RepoError::QueryOrFragment),
    ] {
        if input.bytes().any(|b| b == byte) {
            return Err(error);
        }
    }
    Ok(())
}

fn host_of(authority: &str) -> Result<String, RepoError> {
    if authority.starts_with('[') {
        return Err(RepoError::IpHost);
    }
    if authority.contains(':') {
        return Err(RepoError::Port);
    }
    let host = authority.to_ascii_lowercase();
    if host.len() > MAX_HOST_BYTES {
        return Err(RepoError::Host);
    }
    let last = host.rsplit('.').next().unwrap_or_default();
    if is_numeric_label(last) {
        return Err(RepoError::IpHost);
    }
    if !host.contains('.') || !host.split('.').all(valid_label) {
        return Err(RepoError::Host);
    }
    Ok(host)
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

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_BYTES
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label != "xn--"
        && (label.starts_with("xn--") || label.get(2..4) != Some("--"))
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn segment_bytes_ok(segment: &str) -> bool {
    segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_owner(owner: &str, kind: ForgeKind) -> bool {
    match kind {
        ForgeKind::Github => {
            !owner.is_empty()
                && owner.len() <= MAX_GITHUB_OWNER_BYTES
                && !owner.starts_with('-')
                && !owner.ends_with('-')
                && owner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }
        ForgeKind::Forgejo => {
            owner.len() <= MAX_FORGEJO_OWNER_BYTES
                && owner.starts_with(|c: char| c.is_ascii_alphanumeric())
                && segment_bytes_ok(owner)
                && !FORGEJO_RESERVED_OWNERS
                    .iter()
                    .any(|reserved| owner.eq_ignore_ascii_case(reserved))
                && !FORGEJO_RESERVED_OWNER_SUFFIXES
                    .iter()
                    .any(|suffix| ends_with_ignore_case(owner, suffix))
        }
    }
}

fn valid_name(name: &str, kind: ForgeKind) -> bool {
    if name.is_empty() || name == "." || name == ".." || !segment_bytes_ok(name) {
        return false;
    }
    match kind {
        ForgeKind::Github => {
            name.len() <= MAX_GITHUB_NAME_BYTES && !ends_with_ignore_case(name, GIT_SUFFIX)
        }
        ForgeKind::Forgejo => {
            name.len() <= MAX_FORGEJO_NAME_BYTES
                && name != "-"
                && !FORGEJO_RESERVED_SUFFIXES
                    .iter()
                    .any(|suffix| ends_with_ignore_case(name, suffix))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_form_keeps_printable_ascii_and_spells_out_everything_else() {
        assert_eq!(
            ascii_form("xn--bcher-kva.example/o_r-1"),
            "xn--bcher-kva.example/o_r-1"
        );
        let cases = [
            ("b\u{fc}cher.example", "b\\u{fc}cher.example"),
            ("\u{430}pple.example", "\\u{430}pple.example"),
            ("a\u{202e}b", "a\\u{202e}b"),
            ("a\u{200f}b", "a\\u{200f}b"),
            ("a\r\nb", "a\\u{d}\\u{a}b"),
            ("a\u{85}b\u{2028}", "a\\u{85}b\\u{2028}"),
            ("a b", "a\\u{20}b"),
            ("a\0b", "a\\u{0}b"),
            ("\u{1f600}", "\\u{1f600}"),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(ascii_form(input), want, "{input:?}");
        }
    }

    #[test]
    fn locate_skips_the_forge_grammar_but_keeps_every_structural_rule() {
        assert_eq!(
            RepoRef::locate("https://GHE.example.com/Admin/Hello.git").ok(),
            Some(("ghe.example.com".to_owned(), "admin/hello".to_owned()))
        );
        assert!(RepoRef::parse("ghe.example.com/admin/hello").is_err());
        for bad in [
            "",
            "github.com/octo",
            "github.com/a/b/c",
            "http://github.com/a/b",
            "github.com/a/%41",
            "github.com/a b/c",
            "github.com/a/b;c",
            "github.com/a;b/c",
            "github.com/./b",
            "[::1]/a/b",
            "example.com:80/a/b",
        ] {
            assert!(RepoRef::locate(bad).is_err(), "{bad:?}");
        }
    }

    fn long(n: usize, c: char) -> String {
        std::iter::repeat_n(c, n).collect()
    }

    fn check(rows: &[(String, RepoError)]) {
        for (input, want) in rows {
            assert_eq!(RepoRef::parse(input), Err(*want), "{input:?}");
        }
    }

    #[test]
    fn hostile_input_table_paths() {
        let rows: Vec<(String, RepoError)> = vec![
            (String::new(), RepoError::Empty),
            ("https://example.com/o/".into(), RepoError::Segments),
            ("https://example.com//r".into(), RepoError::Segments),
            ("example.com/o/".into(), RepoError::Segments),
            ("example.com/o/r/x".into(), RepoError::Segments),
            ("a/b/c".into(), RepoError::Host),
            ("a/b".into(), RepoError::Host),
            ("/o/r".into(), RepoError::Host),
            ("https://example.com/o/r/".into(), RepoError::Segments),
            ("https://example.com/".into(), RepoError::Segments),
            ("https://example.com".into(), RepoError::Segments),
            ("//".into(), RepoError::Host),
            ("https://example.com/o//r".into(), RepoError::Segments),
            ("https://example.com/../r".into(), RepoError::Segments),
            ("https://example.com/o/..".into(), RepoError::Segments),
            ("https://example.com/./r".into(), RepoError::Segments),
            ("https://example.com/o/.".into(), RepoError::Segments),
            ("..".into(), RepoError::Host),
            (".".into(), RepoError::Host),
            ("https://example.com/%2e%2e/r".into(), RepoError::Percent),
            ("https://example.com/o%2fx/r".into(), RepoError::Percent),
            ("https://example.com/o/r%00".into(), RepoError::Percent),
            ("https://example.com/o/r%0d%0a".into(), RepoError::Percent),
            ("https://example.com/o/r\r".into(), RepoError::Charset),
            ("https://example.com/o/r\n".into(), RepoError::Charset),
            ("https://example.com/o/r\r\n".into(), RepoError::Charset),
            ("https://example.com/o/r\u{85}".into(), RepoError::Charset),
            ("https://example.com/o/r\u{2028}".into(), RepoError::Charset),
            ("https://example.com/o/r\u{2029}".into(), RepoError::Charset),
            ("https://example.com/o/r\0".into(), RepoError::Charset),
            ("https://example.com/o/r\t".into(), RepoError::Charset),
            ("https://example.com/o/r ".into(), RepoError::Charset),
            ("https://example.com/o\\r".into(), RepoError::Charset),
            ("https://example.com\\o/r".into(), RepoError::Charset),
        ];
        check(&rows);
    }

    #[test]
    fn hostile_input_table_syntax_and_host() {
        let l64 = long(64, 'a');
        let host254 = format!("{0}.{0}.{0}.{1}.com", long(63, 'a'), long(58, 'b'));
        let over_total = format!("example.com/o/{}", long(1100, 'a'));
        let rows: Vec<(String, RepoError)> = vec![
            ("https://example.com/o/r@x".into(), RepoError::Userinfo),
            ("https://u@example.com/o/r".into(), RepoError::Userinfo),
            ("https://u:p@example.com/o/r".into(), RepoError::Userinfo),
            ("git@example.com:o/r".into(), RepoError::Userinfo),
            (
                "https://example.com/o/r?x=1".into(),
                RepoError::QueryOrFragment,
            ),
            (
                "https://example.com/o/r#x".into(),
                RepoError::QueryOrFragment,
            ),
            ("https://example.com/o/r:x".into(), RepoError::Name),
            ("http://example.com/o/r".into(), RepoError::Scheme),
            ("ssh://example.com/o/r".into(), RepoError::Scheme),
            ("ftp://example.com/o/r".into(), RepoError::Scheme),
            ("HTTP://example.com/o/r".into(), RepoError::Scheme),
            ("https://example.com:443/o/r".into(), RepoError::Port),
            ("https://example.com:8443/o/r".into(), RepoError::Port),
            ("example.com:22/o/r".into(), RepoError::Port),
            ("https://example.com:/o/r".into(), RepoError::Port),
            ("https://[::1]/o/r".into(), RepoError::IpHost),
            ("https://[2001:db8::1]/o/r".into(), RepoError::IpHost),
            ("https://127.0.0.1/o/r".into(), RepoError::IpHost),
            ("https://2130706433/o/r".into(), RepoError::IpHost),
            ("https://0x7f.1/o/r".into(), RepoError::IpHost),
            ("https://0x7f000001/o/r".into(), RepoError::IpHost),
            ("https://169.254.169.254/o/r".into(), RepoError::IpHost),
            ("127.0.0.1/o/r".into(), RepoError::IpHost),
            ("https://127.1/o/r".into(), RepoError::IpHost),
            ("https://example.1/o/r".into(), RepoError::IpHost),
            ("https://GITHUB.COM/o_x/r".into(), RepoError::Owner),
            (
                format!("example.com/o/{}", long(1011, 'a')),
                RepoError::TooLong,
            ),
            ("https://exämple.com/o/r".into(), RepoError::Charset),
            ("https://example.com/ö/r".into(), RepoError::Charset),
            ("https://example.com/\u{202e}o/r".into(), RepoError::Charset),
            ("https://example.com\u{ff0f}o/r".into(), RepoError::Charset),
            (format!("https://{l64}.com/o/r"), RepoError::Host),
            (format!("https://{host254}/o/r"), RepoError::Host),
            ("https://example.com./o/r".into(), RepoError::Host),
            ("https://-a.example.com/o/r".into(), RepoError::Host),
            ("https://a-.example.com/o/r".into(), RepoError::Host),
            ("https://a..example.com/o/r".into(), RepoError::Host),
            ("https://ab--c.example.com/o/r".into(), RepoError::Host),
            (
                "https://under_score.example.com/o/r".into(),
                RepoError::Host,
            ),
            ("https://localhost/o/r".into(), RepoError::Host),
            (over_total, RepoError::TooLong),
            ("https://example.com/-o/r".into(), RepoError::Owner),
            ("https://example.com/.o/r".into(), RepoError::Owner),
            ("https://example.com/o/-".into(), RepoError::Name),
            ("https://example.com/o/r.git.git".into(), RepoError::Name),
            ("https://example.com/o/.git".into(), RepoError::Name),
            ("https://example.com/o/r.wiki".into(), RepoError::Name),
            ("https://example.com/o/r.RSS".into(), RepoError::Name),
            ("https://example.com/o/r.atom".into(), RepoError::Name),
            ("https://github.com/o_x/r".into(), RepoError::Owner),
            ("https://github.com/o./r".into(), RepoError::Owner),
            ("https://github.com/o-/r".into(), RepoError::Owner),
            ("https://github.com/-o/r".into(), RepoError::Owner),
            (
                format!("https://github.com/{}/r", long(40, 'a')),
                RepoError::Owner,
            ),
            (
                format!("https://github.com/o/{}", long(101, 'a')),
                RepoError::Name,
            ),
            ("https://github.com/o/r.git.git".into(), RepoError::Name),
            ("https://github.com/o/r\u{ff0f}x".into(), RepoError::Charset),
        ];
        check(&rows);
    }

    #[test]
    fn host_and_scheme_edge_rows() {
        let rows: Vec<(String, RepoError)> = vec![
            ("https://1.1.1.0x/o/r".into(), RepoError::IpHost),
            ("https://a.0x/o/r".into(), RepoError::IpHost),
            ("https://a.0X/o/r".into(), RepoError::IpHost),
            ("https://0X7F.1/o/r".into(), RepoError::IpHost),
            ("https://127.0.0.0x/o/r".into(), RepoError::IpHost),
            ("https://0.0x/o/r".into(), RepoError::IpHost),
            ("https://0x.0x/o/r".into(), RepoError::IpHost),
            ("https://xn--/o/r".into(), RepoError::Host),
            ("https://a.xn--/o/r".into(), RepoError::Host),
            ("https://xn--.example/o/r".into(), RepoError::Host),
            ("HTTPS://example.com/o/r".into(), RepoError::Scheme),
            ("https://example.com/o/r.git/".into(), RepoError::Segments),
            ("github.com./o/r".into(), RepoError::Host),
            ("GITHUB.COM:443/o/r".into(), RepoError::Port),
            ("example.com/o.keys/r".into(), RepoError::Owner),
            ("example.com/admin/r".into(), RepoError::Owner),
            ("https://github.com/o/r.GIT.git".into(), RepoError::Name),
            ("https://example.com/o/r.GIT.git".into(), RepoError::Name),
            ("https://example.com/o/r.git.GIT".into(), RepoError::Name),
        ];
        check(&rows);
    }

    #[test]
    fn forgejo_owner_rules() {
        let mut rows: Vec<(String, RepoError)> = Vec::new();
        for owner in [
            "admin",
            "api",
            "user",
            "explore",
            "login",
            "assets",
            "issues",
            "pulls",
            "notifications",
            "org",
            "repo",
            "attachments",
            "avatars",
            "favicon.ico",
            "robots.txt",
            "ADMIN",
            "Favicon.ICO",
            "o.keys",
            "o.KEYS",
            "o.gpg",
            "o.GPG",
            ".keys",
            "_o",
            "-o",
            ".o",
        ] {
            rows.push((format!("https://git.example/{owner}/r"), RepoError::Owner));
        }
        rows.push((
            format!("https://git.example/{}/r", long(41, 'a')),
            RepoError::Owner,
        ));
        rows.push((
            format!("https://git.example/o/{}", long(101, 'a')),
            RepoError::Name,
        ));
        check(&rows);
        for input in [
            format!("https://git.example/{}/{}", long(40, 'a'), long(100, 'b')),
            "https://git.example/administrator/r".to_owned(),
            "https://git.example/o.keyring/r".to_owned(),
            "https://git.example/9o/r".to_owned(),
        ] {
            assert!(RepoRef::parse(&input).is_ok(), "{input:?}");
        }
    }

    #[test]
    fn git_suffix_strips_case_insensitively_once() -> Result<(), RepoError> {
        for input in [
            "example.com/o/r.GIT",
            "github.com/o/r.GIT",
            "github.com/o/r.Git",
        ] {
            let r = RepoRef::parse(input)?;
            assert_eq!(r.path(), "o/r", "{input:?}");
            assert_eq!(r.display_path(), "o/r", "{input:?}");
        }
        for kind in [ForgeKind::Github, ForgeKind::Forgejo] {
            assert_eq!(
                RepoRef::parse_as("https://git.example/o/r.GIT.git", kind),
                Err(RepoError::Name)
            );
            assert_eq!(
                RepoRef::parse_as("https://git.example/o/.GIT", kind),
                Err(RepoError::Name)
            );
        }
        Ok(())
    }

    #[test]
    fn accepted_shapes() {
        let l63 = long(63, 'a');
        let max_host = format!("{0}.{0}.{0}.{1}.com", l63, long(57, 'b'));
        assert_eq!(max_host.len(), 253);
        for input in [
            "https://example.com/o/r",
            "https://example.com/o/r.git",
            "https://1.example.com/o/r",
            "https://a1.example.com/o/r",
            "example.com/o/r",
            "example.com/o/r.git",
            "https://EXAMPLE.com/O/R",
            "https://xn--bcher-kva.example/o/r",
            "https://example.com/o.x/r_y-z.v1",
            "https://github.com/o/r.wiki",
            "https://github.com/o/-",
            &format!("https://github.com/{}/{}", long(39, 'a'), long(100, 'b')),
            &format!("https://{l63}.com/o/r"),
            &format!("example.com/o/{}", long(100, 'a')),
            &format!("https://{max_host}/o/r"),
        ] {
            assert!(RepoRef::parse(input).is_ok(), "{input:?}");
        }
    }

    #[test]
    fn case_variants_share_identity_and_git_strips_once() -> Result<(), RepoError> {
        let a = RepoRef::parse("https://Example.COM/Octo/Repo.git")?;
        let b = RepoRef::parse("example.com/octo/repo")?;
        assert_eq!(a.host(), b.host());
        assert_eq!(a.path(), b.path());
        assert_eq!(a.host(), "example.com");
        assert_eq!(a.path(), "octo/repo");
        assert_eq!(a.display_path(), "Octo/Repo");
        assert_eq!(b.display_path(), "octo/repo");
        let c = RepoRef::parse("example.com/o/r.git")?;
        assert_eq!(c.path(), "o/r");
        let d = RepoRef::parse("example.com/o/r.git.x")?;
        assert_eq!(d.path(), "o/r.git.x");
        Ok(())
    }

    #[test]
    fn grammar_follows_the_kind() -> Result<(), RepoError> {
        assert_eq!(
            RepoRef::parse("https://github.com/o_x/r"),
            Err(RepoError::Owner)
        );
        RepoRef::parse("https://git.example/o_x/r")?;
        assert_eq!(
            RepoRef::parse_as("https://git.example/o_x/r", ForgeKind::Github),
            Err(RepoError::Owner)
        );
        RepoRef::parse_as("https://github.com/o_x/r", ForgeKind::Forgejo)?;
        assert_eq!(
            RepoRef::parse_as("https://git.example/o/r.wiki", ForgeKind::Forgejo),
            Err(RepoError::Name)
        );
        RepoRef::parse_as("https://git.example/o/r.wiki", ForgeKind::Github)?;
        Ok(())
    }

    #[test]
    fn errors_never_echo_the_input() {
        let secret = "https://user:hunter2@example.com/o/r";
        let Err(err) = RepoRef::parse(secret) else {
            return;
        };
        assert!(!err.to_string().contains("hunter2"));
        assert!(!format!("{err:?}").contains("hunter2"));
    }

    #[test]
    fn verdict_holds_its_fields() {
        let v = RepoVerdict {
            canonical_path: "o/r".into(),
            read: true,
            push: None,
            login: Some("bot".into()),
        };
        assert_eq!(v.clone(), v);
        assert_eq!(v.push, None);
    }
}

//! Fetch policy: which hosts a Job's fetch may reach, and the caps on one fetch.
//!
//! No network I/O lives here. The policy and caps are data that the fetch core reads.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::netguard::is_public_address;

/// Longest URL fetch accepts, in bytes (ADR-0038).
pub const MAX_URL_BYTES: usize = 1024;

const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

/// Why a host pattern was refused. The message holds no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPatternError {
    /// The pattern is empty or longer than a DNS name.
    Length,
    /// A label is empty, too long, or has a character outside letters, digits and hyphen.
    Label,
    /// The pattern is an IP address, which is never a host name.
    IpLiteral,
    /// The wildcard is not a single leading `*.` over at least two further labels.
    Wildcard,
}

impl fmt::Display for HostPatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "host pattern length is out of range",
            Self::Label => "host pattern has an invalid label",
            Self::IpLiteral => "host pattern is an IP address",
            Self::Wildcard => "host pattern wildcard is invalid",
        })
    }
}

impl std::error::Error for HostPatternError {}

/// A host name or a `*.` wildcard over a domain, matched case-insensitively.
///
/// A wildcard matches subdomains at any depth and never the bare domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Exactly this host.
    Exact(String),
    /// Any subdomain of this domain.
    Subdomain(String),
}

fn valid_labels(name: &str) -> Result<(), HostPatternError> {
    if name.is_empty() || name.len() > MAX_HOST_BYTES {
        return Err(HostPatternError::Length);
    }
    for label in name.split('.') {
        let bytes = label.as_bytes();
        let edge_ok = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric);
        if bytes.len() > MAX_LABEL_BYTES
            || !edge_ok
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(HostPatternError::Label);
        }
    }
    Ok(())
}

impl HostPattern {
    /// Parse `host.example` or `*.example`.
    ///
    /// # Errors
    ///
    /// Returns [`HostPatternError`] for an empty or oversized pattern, a label that is not
    /// ASCII letters, digits and hyphen, an IP literal, or a misplaced wildcard.
    pub fn parse(raw: &str) -> Result<Self, HostPatternError> {
        let lower = raw.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("*.") {
            if rest.contains('*') || !rest.contains('.') {
                return Err(HostPatternError::Wildcard);
            }
            valid_labels(rest)?;
            return Ok(Self::Subdomain(rest.to_owned()));
        }
        if lower.contains('*') {
            return Err(HostPatternError::Wildcard);
        }
        if lower.parse::<IpAddr>().is_ok() {
            return Err(HostPatternError::IpLiteral);
        }
        valid_labels(&lower)?;
        Ok(Self::Exact(lower))
    }

    /// Whether a host name matches. The host is compared case-insensitively.
    ///
    /// A wildcard match also requires every label before the domain to pass the same rules as
    /// [`HostPattern::parse`], so a head with an empty label, a space, non-ASCII or a URL
    /// delimiter never matches. `host` must be the host the URL parser produced, in ASCII
    /// (punycode for internationalised names), never a raw string cut from the URL text.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        match self {
            Self::Exact(name) => host == *name,
            Self::Subdomain(domain) => host
                .strip_suffix(domain.as_str())
                .and_then(|head| head.strip_suffix('.'))
                .is_some_and(|head| valid_labels(head).is_ok()),
        }
    }
}

/// Limits on one fetch and on the fetches of one Job. The values are the build-task choices
/// that ADR-0038 left open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchCaps {
    /// Largest response body on the wire, in bytes.
    pub max_body_bytes: u64,
    /// Largest body after content decoding, in bytes.
    pub max_decoded_bytes: u64,
    /// Longest time to open the connection.
    pub connect_timeout: Duration,
    /// Longest time for the whole fetch, redirects included.
    pub total_timeout: Duration,
    /// Most redirect hops followed.
    pub max_redirects: u8,
    /// Longest URL, in bytes.
    pub max_url_bytes: usize,
    /// Most fetches one Job may make.
    pub max_fetches_per_job: u32,
}

impl Default for FetchCaps {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            max_decoded_bytes: 4 * 1024 * 1024,
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_redirects: 5,
            max_url_bytes: MAX_URL_BYTES,
            max_fetches_per_job: 50,
        }
    }
}

impl FetchCaps {
    /// Whether a URL is within the length cap.
    #[must_use]
    pub const fn url_within_cap(&self, url: &str) -> bool {
        url.len() <= self.max_url_bytes
    }
}

/// Which hosts fetch may reach. The default is [`FetchPolicy::AllowAllPublicHosts`].
///
/// The policy is only a decision function. The fetch core must check the host with
/// [`FetchPolicy::permits_host`] and the connected socket address with
/// [`FetchPolicy::permits_address`] on every hop, including each redirect, and must not use
/// an HTTP proxy. See those methods for the exact contract.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FetchPolicy {
    /// Any public host. This is an exfiltration path.
    ///
    /// An agent can put repo files, the prompt or any other Job data into a URL path or query
    /// string and send it to any public host, and a host that logs requests receives it.
    /// Redaction covers exact secret values only, so it does not stop this. The user chose
    /// this default knowingly (ADR-0038). Addresses that are not public are still refused.
    #[default]
    AllowAllPublicHosts,
    /// Only hosts that match one of these patterns. Addresses that are not public are still
    /// refused.
    Allowlist(Vec<HostPattern>),
}

impl FetchPolicy {
    /// Whether a host name may be fetched. An empty allowlist permits nothing.
    ///
    /// `host` must be the post-parse ASCII (punycode) host from the URL parser. Callers must
    /// call this again on every redirect hop, must not route the fetch through an HTTP proxy
    /// (the proxy would resolve and dial the host, bypassing the address check), and must pair
    /// it with [`FetchPolicy::permits_address`] on the connected socket address.
    #[must_use]
    pub fn permits_host(&self, host: &str) -> bool {
        match self {
            Self::AllowAllPublicHosts => true,
            Self::Allowlist(patterns) => patterns.iter().any(|p| p.matches(host)),
        }
    }

    /// Whether a resolved address may be dialled. Every policy refuses non-public addresses.
    ///
    /// Callers must apply this to the address of the socket actually connected, through a
    /// custom connector or a resolver filter, and never to the result of a separate earlier
    /// lookup: a second lookup can return a different address (DNS rebinding). Apply it again
    /// on every redirect hop, together with [`FetchPolicy::permits_host`], and do not route
    /// the fetch through an HTTP proxy, which would dial an address this check never sees.
    #[must_use]
    pub fn permits_address(&self, ip: IpAddr) -> bool {
        is_public_address(ip)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn pat(s: &str) -> Option<HostPattern> {
        HostPattern::parse(s).ok()
    }

    #[test]
    fn default_policy_is_allow_all_public_hosts() {
        assert_eq!(FetchPolicy::default(), FetchPolicy::AllowAllPublicHosts);
    }

    #[test]
    fn allow_all_permits_any_host_name() {
        assert!(FetchPolicy::AllowAllPublicHosts.permits_host("docs.rs"));
    }

    #[test]
    fn allow_all_still_refuses_non_public_addresses() {
        let policy = FetchPolicy::default();
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            let ip = s.parse::<IpAddr>().ok();
            assert!(ip.is_some_and(|ip| !policy.permits_address(ip)), "{s}");
        }
        assert!(!policy.permits_address(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        let public = "8.8.8.8".parse::<IpAddr>().ok();
        assert!(public.is_some_and(|ip| policy.permits_address(ip)));
    }

    #[test]
    fn allowlist_refuses_non_public_addresses_too() {
        let policy = FetchPolicy::Allowlist(vec![HostPattern::Exact("docs.rs".into())]);
        let ip = "192.168.0.1".parse::<IpAddr>().ok();
        assert!(ip.is_some_and(|ip| !policy.permits_address(ip)));
    }

    #[test]
    fn allowlist_matches_only_listed_hosts() {
        let policy = FetchPolicy::Allowlist(vec![
            HostPattern::Exact("docs.rs".into()),
            HostPattern::Subdomain("github.com".into()),
        ]);
        assert!(policy.permits_host("docs.rs"));
        assert!(policy.permits_host("raw.github.com"));
        assert!(!policy.permits_host("example.com"));
        assert!(!FetchPolicy::Allowlist(Vec::new()).permits_host("docs.rs"));
    }

    #[test]
    fn exact_pattern_is_case_insensitive() {
        assert_eq!(pat("Docs.RS"), Some(HostPattern::Exact("docs.rs".into())));
        assert!(pat("docs.rs").is_some_and(|p| p.matches("DOCS.rs")));
    }

    #[test]
    fn wildcard_matches_subdomains_never_the_bare_domain() {
        let p = pat("*.example.com");
        assert!(p.as_ref().is_some_and(|p| p.matches("a.example.com")));
        assert!(p.as_ref().is_some_and(|p| p.matches("a.b.example.com")));
        assert!(p.as_ref().is_some_and(|p| !p.matches("example.com")));
        assert!(p.as_ref().is_some_and(|p| !p.matches("notexample.com")));
        assert!(
            p.as_ref()
                .is_some_and(|p| !p.matches("example.com.evil.net"))
        );
        assert!(p.is_some_and(|p| !p.matches(".example.com")));
    }

    #[test]
    fn wildcard_refuses_heads_that_are_not_valid_labels() {
        let p = pat("*.example.com");
        for host in [
            "a..example.com",
            "a b.example.com",
            "\u{e9}.example.com",
            "a/b.example.com",
            "a@b.example.com",
            "a#b.example.com",
            "a\\b.example.com",
            "a?b.example.com",
            "-a.example.com",
            "a-.example.com",
            ".a.example.com",
        ] {
            assert!(p.as_ref().is_some_and(|p| !p.matches(host)), "{host:?}");
        }
        assert!(p.is_some_and(|p| p.matches("a-b.c1.example.com")));
    }

    #[test]
    fn bad_patterns_are_refused_with_the_right_error() {
        let cases = [
            ("", HostPatternError::Length),
            ("a..b", HostPatternError::Label),
            ("-a.com", HostPatternError::Label),
            ("a-.com", HostPatternError::Label),
            ("a.com.", HostPatternError::Label),
            ("a.com:443", HostPatternError::Label),
            ("https://a.com", HostPatternError::Label),
            ("user@a.com", HostPatternError::Label),
            ("a/b.com", HostPatternError::Label),
            ("bücher.de", HostPatternError::Label),
            ("127.0.0.1", HostPatternError::IpLiteral),
            ("::1", HostPatternError::IpLiteral),
            ("*", HostPatternError::Wildcard),
            ("*.com", HostPatternError::Wildcard),
            ("*.*.com", HostPatternError::Wildcard),
            ("a.*.com", HostPatternError::Wildcard),
            ("*a.com", HostPatternError::Wildcard),
        ];
        for (raw, want) in cases {
            assert_eq!(HostPattern::parse(raw), Err(want), "{raw:?}");
        }
    }

    #[test]
    fn label_and_host_length_caps() {
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(
            HostPattern::parse(&long_label),
            Err(HostPatternError::Label)
        );
        let ok_label = format!("{}.com", "a".repeat(63));
        assert!(HostPattern::parse(&ok_label).is_ok());
        let long_host = vec!["a".repeat(60); 5].join(".");
        assert_eq!(
            HostPattern::parse(&long_host),
            Err(HostPatternError::Length)
        );
    }

    #[test]
    fn pattern_error_text_holds_no_input() {
        let msg = HostPattern::parse("secret-value@x").map_err(|e| e.to_string());
        assert!(msg.is_err_and(|m| !m.contains("secret")));
    }

    #[test]
    fn default_caps_hold_the_adr_url_cap_and_are_nonzero() {
        let caps = FetchCaps::default();
        assert_eq!(caps.max_url_bytes, 1024);
        assert!(caps.max_body_bytes > 0);
        assert!(caps.max_decoded_bytes >= caps.max_body_bytes);
        assert!(caps.connect_timeout > Duration::ZERO);
        assert!(caps.total_timeout > caps.connect_timeout);
        assert!(caps.max_redirects > 0);
        assert!(caps.max_fetches_per_job > 0);
    }

    #[test]
    fn url_cap_is_inclusive() {
        let caps = FetchCaps::default();
        assert!(caps.url_within_cap(&"a".repeat(1024)));
        assert!(!caps.url_within_cap(&"a".repeat(1025)));
    }
}

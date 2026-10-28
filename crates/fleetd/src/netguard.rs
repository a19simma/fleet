//! Address checks for fetch: which IP addresses a fetch may dial.
//!
//! The tables list the IANA special-purpose address registries (IPv4 and IPv6) where the
//! registry marks a block as not globally reachable, plus blocks that ADR-0038 names. Where a
//! block holds a few global entries (`192.0.0.0/24`, `2001::/23`), the whole block is refused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 block as a base address and a prefix length.
pub type V4Block = (Ipv4Addr, u8);

/// An IPv6 block as a base address and a prefix length.
pub type V6Block = (Ipv6Addr, u8);

/// IPv4 blocks that are not public, from the IANA IPv4 special-purpose registry.
pub const NON_PUBLIC_V4: &[V4Block] = &[
    (Ipv4Addr::UNSPECIFIED, 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// The only IPv6 range treated as public unicast: `2000::/3`.
pub const GLOBAL_UNICAST_V6: V6Block = (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);

/// IPv6 blocks inside [`GLOBAL_UNICAST_V6`] that are not public, from the IANA IPv6
/// special-purpose registry.
pub const NON_PUBLIC_V6: &[V6Block] = &[
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
];

fn in_v4(block: V4Block, ip: Ipv4Addr) -> bool {
    let (net, len) = block;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from(net) & mask == u32::from(ip) & mask
}

fn in_v6(block: V6Block, ip: Ipv6Addr) -> bool {
    let (net, len) = block;
    let mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    u128::from(net) & mask == u128::from(ip) & mask
}

fn public_v4(ip: Ipv4Addr) -> bool {
    !NON_PUBLIC_V4.iter().any(|block| in_v4(*block, ip))
}

fn public_v6(ip: Ipv6Addr) -> bool {
    in_v6(GLOBAL_UNICAST_V6, ip) && !NON_PUBLIC_V6.iter().any(|block| in_v6(*block, ip))
}

/// Whether a fetch may dial this address.
///
/// IPv4-mapped IPv6 addresses are unwrapped and checked as IPv4. Every other IPv6 address
/// outside `2000::/3` is refused, which covers loopback, unspecified, unique local, link-local,
/// multicast, IPv4-compatible, NAT64 and discard ranges.
#[must_use]
pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(|| public_v6(v6), public_v4),
    }
}

/// Longest URL a fetch accepts, in bytes (ADR-0038).
pub const MAX_URL_BYTES: usize = 1024;

/// Why [`precheck_url`] refused a URL. Display text is fixed and holds no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRefusal {
    /// The URL is longer than [`MAX_URL_BYTES`].
    TooLong,
    /// The URL holds a byte outside printable ASCII, or a backslash.
    InvalidCharacter,
    /// The scheme is not `https`.
    NotHttps,
    /// The URL holds a `#`.
    Fragment,
    /// The authority holds an `@`.
    Userinfo,
    /// The port is not exactly `443`.
    BadPort,
    /// The host is empty.
    EmptyHost,
    /// The host is not a valid ASCII DNS name or IPv6 literal.
    InvalidHost,
    /// The host ends in a dot.
    TrailingDot,
    /// The host is an IP literal that fails [`is_public_address`].
    NonPublicAddress,
}

impl std::fmt::Display for UrlRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "url too long",
            Self::InvalidCharacter => "url holds a disallowed character",
            Self::NotHttps => "url scheme must be https",
            Self::Fragment => "url fragment refused",
            Self::Userinfo => "url userinfo refused",
            Self::BadPort => "url port must be 443",
            Self::EmptyHost => "url host empty",
            Self::InvalidHost => "url host invalid",
            Self::TrailingDot => "url host trailing dot refused",
            Self::NonPublicAddress => "url host address not public",
        })
    }
}

impl std::error::Error for UrlRefusal {}

/// A URL that passed [`precheck_url`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarget {
    /// Lowercase ASCII host; an IPv6 literal has no brackets.
    pub host: String,
    /// Always 443.
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

const HTTPS_PREFIX: &str = "https://";
const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;
const HTTPS_PORT: u16 = 443;

fn parse_port(text: &str) -> Result<u16, UrlRefusal> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UrlRefusal::BadPort);
    }
    match text.parse::<u16>() {
        Ok(HTTPS_PORT) if text == "443" => Ok(HTTPS_PORT),
        _ => Err(UrlRefusal::BadPort),
    }
}

fn check_dns_host(host: &str) -> Result<(), UrlRefusal> {
    if host.is_empty() {
        return Err(UrlRefusal::EmptyHost);
    }
    if host.ends_with('.') {
        return Err(UrlRefusal::TrailingDot);
    }
    if host.len() > MAX_HOST_BYTES {
        return Err(UrlRefusal::InvalidHost);
    }
    for label in host.split('.') {
        let bytes = label.as_bytes();
        let edge_ok = bytes.first() != Some(&b'-') && bytes.last() != Some(&b'-');
        let chars_ok = bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-');
        if bytes.is_empty() || bytes.len() > MAX_LABEL_BYTES || !edge_ok || !chars_ok {
            return Err(UrlRefusal::InvalidHost);
        }
    }
    let tld_starts_with_letter = host
        .rsplit('.')
        .next()
        .and_then(|tld| tld.bytes().next())
        .is_some_and(|b| b.is_ascii_alphabetic());
    if !tld_starts_with_letter || !host.contains('.') {
        return Err(UrlRefusal::InvalidHost);
    }
    Ok(())
}

fn parse_host(authority_host: &str) -> Result<String, UrlRefusal> {
    if let Some(inner) = authority_host.strip_prefix('[') {
        let literal = inner.strip_suffix(']').ok_or(UrlRefusal::InvalidHost)?;
        let ip = literal
            .parse::<Ipv6Addr>()
            .map_err(|_| UrlRefusal::InvalidHost)?;
        return if is_public_address(IpAddr::V6(ip)) {
            Ok(ip.to_string())
        } else {
            Err(UrlRefusal::NonPublicAddress)
        };
    }
    let host = authority_host.to_ascii_lowercase();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return if is_public_address(IpAddr::V4(ip)) {
            Ok(host)
        } else {
            Err(UrlRefusal::NonPublicAddress)
        };
    }
    check_dns_host(&host)?;
    Ok(host)
}

/// Checks a URL without touching the network and returns its host, port and path.
///
/// Accepts only `https` on port 443, written as `443` or left out. Refuses, with a fixed
/// [`UrlRefusal`] that holds no part of the input: a length over [`MAX_URL_BYTES`], any byte
/// outside printable ASCII (whitespace, controls and non-ASCII, so an internationalised host
/// must arrive as punycode), a backslash, a fragment, userinfo, an empty host, a percent sign in
/// the host, a trailing-dot host (refused, never stripped, so one host has one spelling), a
/// single-label host, a host whose last label does not start with a letter (which refuses the
/// numeric and hex forms resolvers read as IPv4), and an IP literal that fails
/// [`is_public_address`]. The returned host is lowercase ASCII; an IPv6 literal comes back
/// without brackets. The path keeps its query and is `/` when the URL has none.
///
/// This is the pre-check only. The resolved address is checked again at dial time.
///
/// # Errors
/// Returns the [`UrlRefusal`] for the first rule the URL breaks.
pub fn precheck_url(input: &str) -> Result<ParsedTarget, UrlRefusal> {
    if input.len() > MAX_URL_BYTES {
        return Err(UrlRefusal::TooLong);
    }
    if !input.bytes().all(|b| b.is_ascii_graphic()) || input.contains('\\') {
        return Err(UrlRefusal::InvalidCharacter);
    }
    let rest = input
        .get(..HTTPS_PREFIX.len())
        .filter(|head| head.eq_ignore_ascii_case(HTTPS_PREFIX))
        .and_then(|_| input.get(HTTPS_PREFIX.len()..))
        .ok_or(UrlRefusal::NotHttps)?;
    if rest.contains('#') {
        return Err(UrlRefusal::Fragment);
    }
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    if authority.contains('@') {
        return Err(UrlRefusal::Userinfo);
    }
    let (host_text, port) = match authority.rfind(':') {
        Some(at) if !authority.starts_with('[') || authority[..at].ends_with(']') => {
            (&authority[..at], parse_port(&authority[at + 1..])?)
        }
        _ => (authority, HTTPS_PORT),
    };
    if host_text.contains('%') {
        return Err(UrlRefusal::InvalidHost);
    }
    let host = parse_host(host_text)?;
    let path = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    Ok(ParsedTarget { host, port, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(s: &str) -> Option<UrlRefusal> {
        precheck_url(s).err()
    }

    fn target(host: &str, path: &str) -> ParsedTarget {
        ParsedTarget {
            host: host.to_owned(),
            port: 443,
            path: path.to_owned(),
        }
    }

    #[test]
    fn named_range_edges_are_refused_and_neighbours_allowed() {
        let refused = [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.0",
            "10.255.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.0.0",
            "169.254.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.0.0",
            "192.168.255.255",
            "192.0.2.0",
            "198.51.100.255",
            "203.0.113.0",
            "224.0.0.0",
            "239.255.255.255",
            "255.255.255.255",
        ];
        for s in refused {
            assert!(!is_public_address(ip4(s)), "{s}");
        }
        for ip in [
            Ipv4Addr::new(100, 64, 0, 0),
            Ipv4Addr::new(100, 127, 255, 255),
        ] {
            assert!(!is_public_address(IpAddr::V4(ip)), "{ip}");
        }
        for s in [
            "1.0.0.0",
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
        ] {
            assert!(is_public_address(ip4(s)), "{s}");
        }
        for s in [
            "fe80::",
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fc00::",
            "fdff::1",
        ] {
            assert!(!is_public_address(ip6(s)), "{s}");
        }
        for s in [
            "2002:7f00:1::1",
            "2002:0a00:1::1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public_address(ip6(s)), "{s}");
        }
    }

    #[test]
    fn precheck_accepts_plain_https_and_normalises() {
        assert_eq!(
            precheck_url("https://example.com"),
            Ok(target("example.com", "/"))
        );
        assert_eq!(
            precheck_url("HTTPS://Example.COM/a/b"),
            Ok(target("example.com", "/a/b"))
        );
        assert_eq!(
            precheck_url("https://example.com:443/x?q=1"),
            Ok(target("example.com", "/x?q=1"))
        );
        assert_eq!(
            precheck_url("https://example.com?q=1"),
            Ok(target("example.com", "/?q=1"))
        );
        assert_eq!(
            precheck_url("https://xn--bcher-kva.example/"),
            Ok(target("xn--bcher-kva.example", "/"))
        );
        assert_eq!(
            precheck_url("https://example.com/a@b"),
            Ok(target("example.com", "/a@b"))
        );
        assert_eq!(
            precheck_url("https://example.com/%41"),
            Ok(target("example.com", "/%41"))
        );
        assert_eq!(precheck_url("https://8.8.8.8/"), Ok(target("8.8.8.8", "/")));
        assert_eq!(
            precheck_url("https://[2606:4700:4700::1111]:443/"),
            Ok(target("2606:4700:4700::1111", "/"))
        );
    }

    #[test]
    fn precheck_refuses_scheme_and_userinfo() {
        assert_eq!(refusal("http://example.com/"), Some(UrlRefusal::NotHttps));
        assert_eq!(refusal("ftp://example.com/"), Some(UrlRefusal::NotHttps));
        assert_eq!(refusal("example.com/"), Some(UrlRefusal::NotHttps));
        assert_eq!(refusal("https:/example.com"), Some(UrlRefusal::NotHttps));
        assert_eq!(
            refusal("https://u@example.com/"),
            Some(UrlRefusal::Userinfo)
        );
        assert_eq!(
            refusal("https://u:p@example.com/"),
            Some(UrlRefusal::Userinfo)
        );
        assert_eq!(refusal("https://@example.com/"), Some(UrlRefusal::Userinfo));
        assert_eq!(
            refusal("https://good.example@evil.example/"),
            Some(UrlRefusal::Userinfo)
        );
    }

    #[test]
    fn precheck_refuses_ports_other_than_443() {
        for s in [
            "https://example.com:0/",
            "https://example.com:80/",
            "https://example.com:8443/",
            "https://example.com:00443/",
            "https://example.com:65536/",
            "https://example.com:+443/",
            "https://example.com:/",
            "https://example.com:44a/",
            "https://[2606:4700:4700::1111]:80/",
        ] {
            assert_eq!(refusal(s), Some(UrlRefusal::BadPort), "{s}");
        }
    }

    #[test]
    fn precheck_refuses_length_over_cap_and_accepts_at_cap() {
        let head = "https://example.com/";
        let at = format!("{head}{}", "a".repeat(MAX_URL_BYTES - head.len()));
        assert_eq!(at.len(), MAX_URL_BYTES);
        assert!(precheck_url(&at).is_ok());
        let over = format!("{at}a");
        assert_eq!(refusal(&over), Some(UrlRefusal::TooLong));
    }

    #[test]
    fn precheck_refuses_hostile_characters() {
        for s in [
            "https://example.com\\@evil.example/",
            "https://example.com/a\\b",
            "https://example.com/a b",
            " https://example.com/",
            "https://example.com/\t",
            "https://example.com/\n",
            "https://exa\tmple.com/",
            "https://exa\u{0}mple.com/",
            "https://b\u{fc}cher.example/",
            "https://example.com/\u{e9}",
        ] {
            assert_eq!(refusal(s), Some(UrlRefusal::InvalidCharacter), "{s}");
        }
    }

    #[test]
    fn precheck_refuses_fragments() {
        for s in [
            "https://example.com/#a",
            "https://example.com#a",
            "https://example.com/a?b#c",
        ] {
            assert_eq!(refusal(s), Some(UrlRefusal::Fragment), "{s}");
        }
    }

    #[test]
    fn precheck_refuses_bad_hosts() {
        assert_eq!(refusal("https:///path"), Some(UrlRefusal::EmptyHost));
        assert_eq!(refusal("https://"), Some(UrlRefusal::EmptyHost));
        assert_eq!(refusal("https://:443/"), Some(UrlRefusal::EmptyHost));
        assert_eq!(refusal("https://?q=1"), Some(UrlRefusal::EmptyHost));
        for s in [
            "https://example.com./",
            "https://example.com.:443/",
            "https://./",
        ] {
            assert_eq!(refusal(s), Some(UrlRefusal::TrailingDot), "{s}");
        }
        for s in [
            "https://exa%6dple.com/",
            "https://%65xample.com/",
            "https://a..example/",
            "https://.example.com/",
            "https://-a.example/",
            "https://a-.example/",
            "https://a_b.example/",
            "https://*.example.com/",
            "https://example.com:443:443/",
            "https://[::1/",
            "https://[::1]x/",
            "https://[nope]/",
            "https://localhost/",
            "https://intranet/",
            "https://0x7f000001/",
            "https://0x7f.0.0.1/",
            "https://127.1/",
            "https://2130706433/",
            "https://017700000001/",
            "https://1.2.3/",
        ] {
            assert_eq!(refusal(s), Some(UrlRefusal::InvalidHost), "{s}");
        }
        let long_label = format!("https://{}.example/", "a".repeat(64));
        assert_eq!(refusal(&long_label), Some(UrlRefusal::InvalidHost));
        let ok_label = format!("https://{}.example/", "a".repeat(63));
        assert!(precheck_url(&ok_label).is_ok());
        let long_host = format!("https://{}/", vec!["a".repeat(60); 5].join(".") + ".com");
        assert_eq!(refusal(&long_host), Some(UrlRefusal::InvalidHost));
    }

    #[test]
    fn precheck_refuses_non_public_ip_literals() {
        for s in [
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://192.168.1.1/",
            "https://0.0.0.0/",
            "https://255.255.255.255/",
            "https://[::1]/",
            "https://[::]/",
            "https://[fe80::1]/",
            "https://[fd00::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:7f00:1]/",
            "https://[64:ff9b::7f00:1]/",
            "https://[2002:7f00:1::1]/",
            "https://[ff02::1]/",
        ] {
            assert_eq!(refusal(s), Some(UrlRefusal::NonPublicAddress), "{s}");
        }
        let cgnat = format!("https://{}/", Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(refusal(&cgnat), Some(UrlRefusal::NonPublicAddress));
    }

    fn v4_span(block: V4Block) -> (Ipv4Addr, Ipv4Addr) {
        let (net, len) = block;
        let host_bits = if len == 0 { u32::MAX } else { u32::MAX >> len };
        (net, Ipv4Addr::from(u32::from(net) | host_bits))
    }

    fn v6_span(block: V6Block) -> (Ipv6Addr, Ipv6Addr) {
        let (net, len) = block;
        let host_bits = if len == 0 {
            u128::MAX
        } else {
            u128::MAX >> len
        };
        (net, Ipv6Addr::from(u128::from(net) | host_bits))
    }

    fn ip4(s: &str) -> IpAddr {
        s.parse::<Ipv4Addr>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4)
    }

    fn ip6(s: &str) -> IpAddr {
        s.parse::<Ipv6Addr>()
            .map_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpAddr::V6)
    }

    #[test]
    fn every_v4_block_is_refused_at_both_ends_and_middle() {
        for block in NON_PUBLIC_V4 {
            let (first, last) = v4_span(*block);
            let mid = Ipv4Addr::from((u32::from(first) / 2) + (u32::from(last) / 2));
            for ip in [first, last, mid] {
                assert!(!is_public_address(IpAddr::V4(ip)), "{ip} in {block:?}");
            }
        }
    }

    #[test]
    fn every_v6_block_is_refused_at_both_ends_and_middle() {
        for block in NON_PUBLIC_V6 {
            let (first, last) = v6_span(*block);
            let mid = Ipv6Addr::from((u128::from(first) / 2) + (u128::from(last) / 2));
            for ip in [first, last, mid] {
                assert!(!is_public_address(IpAddr::V6(ip)), "{ip} in {block:?}");
            }
        }
    }

    #[test]
    fn every_v4_block_unwraps_when_mapped_into_v6() {
        for block in NON_PUBLIC_V4 {
            let (first, last) = v4_span(*block);
            let refused = |ip: Ipv4Addr| {
                assert!(
                    !is_public_address(IpAddr::V6(ip.to_ipv6_mapped())),
                    "mapped {ip} in {block:?}"
                );
            };
            refused(first);
            refused(last);
        }
    }

    #[test]
    fn mapped_public_v4_is_public() {
        assert!(is_public_address(IpAddr::V6(
            Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped()
        )));
    }

    #[test]
    fn v6_outside_global_unicast_is_refused() {
        let refused = [
            "::",
            "::1",
            "::8.8.8.8",
            "64:ff9b::808:808",
            "64:ff9b:1::1",
            "100::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "ff0e::1",
            "5f00::1",
            "1fff:ffff::1",
            "4000::1",
        ];
        for s in refused {
            assert!(!is_public_address(ip6(s)), "{s}");
        }
    }

    #[test]
    fn known_public_addresses_are_allowed() {
        let v4 = [
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
            "9.255.255.255",
            "11.0.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.0",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ];
        for s in v4 {
            assert!(is_public_address(ip4(s)), "{s}");
        }
        for ip in [
            Ipv4Addr::new(100, 63, 255, 255),
            Ipv4Addr::new(100, 128, 0, 0),
        ] {
            assert!(is_public_address(IpAddr::V4(ip)), "{ip}");
        }
        let v6 = [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450:4001::1",
            "2001:200::1",
            "2001:db9::1",
            "2003::1",
            "3ffe::1",
            "3fff:1000::1",
        ];
        for s in v6 {
            assert!(is_public_address(ip6(s)), "{s}");
        }
    }

    #[test]
    fn agrees_with_std_predicates_over_a_v4_sweep() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let ip = Ipv4Addr::new(a, b, 1, 1);
                let std_non_public = ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_documentation();
                if std_non_public {
                    assert!(!is_public_address(IpAddr::V4(ip)), "{ip}");
                }
            }
        }
    }

    #[test]
    fn agrees_with_std_predicates_over_a_v6_sweep() {
        for hi in (0..=0xffffu32).step_by(0x101) {
            let hi = u16::try_from(hi).unwrap_or(0);
            for second in [0u16, 1, 0xdb8, 0xffff] {
                let ip = Ipv6Addr::new(hi, second, 0, 0, 0, 0, 0, 1);
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                {
                    assert!(!is_public_address(IpAddr::V6(ip)), "{ip}");
                }
            }
        }
    }
}

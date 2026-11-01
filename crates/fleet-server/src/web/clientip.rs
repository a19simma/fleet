//! The client address for rate limiting, taken from the peer and `X-Forwarded-For`.
//!
//! Cilium's Envoy appends the peer address as the rightmost entry and keeps whatever the
//! client sent on the left, so only entries counted from the right are trustworthy.
//! `hops` is how many trusted proxies sit in front of the server: the Nth entry from the
//! right is the client. Zero ignores the header. Anything that does not parse falls back
//! to the peer address.

use std::net::{IpAddr, Ipv4Addr};

/// The longest `X-Forwarded-For` value read, in bytes. A longer header is ignored.
pub const MAX_FORWARDED_BYTES: usize = 1024;

/// The most hops `FLEET_TRUSTED_PROXY_HOPS` accepts.
pub const MAX_TRUSTED_HOPS: usize = 8;

/// The key used when the peer address is unknown.
pub const UNKNOWN: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Picks the client address.
///
/// `forwarded` holds each `X-Forwarded-For` header value in arrival order. The Nth entry
/// from the right must parse as a bare IP address, and so must every entry right of it.
/// With `hops` of zero, too few entries, an over-long header or a bad entry the peer
/// address wins, or [`UNKNOWN`] when there is no peer.
#[must_use]
pub fn client_ip(peer: Option<IpAddr>, forwarded: &[&str], hops: usize) -> IpAddr {
    let fallback = peer.map_or(UNKNOWN, |ip| ip.to_canonical());
    if hops == 0 || forwarded.iter().map(|v| v.len()).sum::<usize>() > MAX_FORWARDED_BYTES {
        return fallback;
    }
    let entries: Vec<&str> = forwarded
        .iter()
        .flat_map(|value| value.split(','))
        .collect();
    if entries.len() < hops {
        return fallback;
    }
    let mut parsed = Vec::with_capacity(hops);
    for entry in entries.iter().rev().take(hops) {
        let text = entry.trim_matches([' ', '\t']);
        match text.parse::<IpAddr>() {
            Ok(ip) if !text.is_empty() => parsed.push(ip),
            _ => return fallback,
        }
    }
    parsed.last().map_or(fallback, IpAddr::to_canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn zero_hops_ignores_the_header() {
        assert_eq!(client_ip(Some(PEER), &["203.0.113.5"], 0), PEER);
    }

    #[test]
    fn one_hop_takes_the_rightmost_entry() {
        assert_eq!(
            client_ip(Some(PEER), &["198.51.100.9, 203.0.113.5"], 1),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn a_client_supplied_left_entry_cannot_choose_the_key() {
        assert_eq!(
            client_ip(Some(PEER), &["1.1.1.1, 2.2.2.2, 203.0.113.5"], 1),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn two_hops_take_the_second_from_the_right() {
        assert_eq!(
            client_ip(Some(PEER), &["9.9.9.9, 203.0.113.5, 10.1.1.1"], 2),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn several_header_lines_read_as_one_list() {
        assert_eq!(
            client_ip(Some(PEER), &["9.9.9.9", "203.0.113.5"], 1),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn too_few_entries_fail_closed_to_the_peer() {
        assert_eq!(client_ip(Some(PEER), &["203.0.113.5"], 2), PEER);
        assert_eq!(client_ip(Some(PEER), &[], 1), PEER);
    }

    #[test]
    fn a_missing_peer_falls_back_to_the_unknown_key() {
        assert_eq!(client_ip(None, &[], 0), UNKNOWN);
        assert_eq!(client_ip(None, &["garbage"], 1), UNKNOWN);
    }

    #[test]
    fn hostile_entries_fail_closed_to_the_peer() {
        let long = format!("203.0.113.5,{}", "1".repeat(MAX_FORWARDED_BYTES));
        let table = [
            "",
            ",",
            "203.0.113.5,",
            "203.0.113.5, ",
            "203.0.113.5:443",
            "[2001:db8::1]:443",
            "[2001:db8::1]",
            "203.0.113.5 1.1.1.1",
            "unknown",
            "garbage",
            "203.0.113.5\r\n",
            "203.0.113.5\0",
            "203.0.113.\u{661}",
            "203.0.113.5%eth0",
            "2001:db8::1::2",
            "1.2.3",
            long.as_str(),
        ];
        for bad in table {
            assert_eq!(client_ip(Some(PEER), &[bad], 1), PEER, "{bad:?}");
        }
    }

    #[test]
    fn whitespace_around_a_good_entry_is_trimmed() {
        assert_eq!(
            client_ip(Some(PEER), &["1.1.1.1 ,\t203.0.113.5 "], 1),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn ipv6_and_mapped_addresses_are_canonical() {
        assert_eq!(
            client_ip(Some(PEER), &["2001:db8::1"], 1),
            ip("2001:db8::1")
        );
        assert_eq!(
            client_ip(Some(PEER), &["::ffff:203.0.113.5"], 1),
            ip("203.0.113.5")
        );
        assert_eq!(
            client_ip(Some(ip("::ffff:10.0.0.7")), &[], 0),
            ip("10.0.0.7")
        );
    }
}

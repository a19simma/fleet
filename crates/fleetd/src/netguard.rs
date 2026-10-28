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

#[cfg(test)]
mod tests {
    use super::*;

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

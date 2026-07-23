//! DNS answer classification for the host-mediated resolver.

use std::net::IpAddr;

/// Return whether an address is unsafe to expose through a DNS answer unless
/// that exact address was explicitly pinned by policy.
///
/// This is intentionally stricter than the TCP-connect mandatory-deny ranges:
/// private IPv4 networks and IPv6 unique-local addresses are included to stop
/// an admitted public hostname from rebinding to an internal service.
#[must_use]
pub fn dns_answer_forbidden(ip: IpAddr) -> bool {
    // An IPv4-mapped IPv6 answer (`::ffff:a.b.c.d`) reaches the embedded IPv4
    // destination on a dual-stack connect, so classify it as that IPv4 address
    // rather than letting it slip past the IPv4 rules as an opaque IPv6 one.
    match crate::policy::network_policy::unmap_v4_mapped(ip) {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || is_shared_address_space(address)
        }
        IpAddr::V6(address) => {
            let first_segment = address.segments()[0];
            address.is_loopback()
                || address.is_unspecified()
                || first_segment & 0xffc0 == 0xfe80
                || first_segment & 0xfe00 == 0xfc00
        }
    }
}

/// RFC 6598 carrier-grade-NAT shared address space (`100.64.0.0/10`).
///
/// `Ipv4Addr::is_private` does not cover this range, but it is reachable
/// internal space in some deployments and is already in the connect-time
/// mandatory-deny set — so the stricter DNS-answer guard must reject it too.
const fn is_shared_address_space(address: std::net::Ipv4Addr) -> bool {
    matches!(address.octets(), [100, 64..=127, _, _])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn public_addresses_are_allowed() {
        for value in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:2800:220:1:248:1893:25c8:1946",
            "2001:4860:4860::8888",
            // A mapped *public* address stays allowed after normalization.
            "::ffff:93.184.216.34",
        ] {
            assert!(
                !dns_answer_forbidden(ip(value)),
                "{value} should be allowed"
            );
        }
    }

    #[test]
    fn private_link_local_loopback_ula_metadata_are_forbidden() {
        for value in [
            "0.0.0.0",
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.10.1",
            "127.0.0.1",
            "127.42.99.7",
            "::",
            "::1",
            "fe80::1",
            "febf:ffff::1",
            "fc00::1",
            "fd12:3456::1",
        ] {
            assert!(
                dns_answer_forbidden(ip(value)),
                "{value} should be forbidden"
            );
        }
    }

    #[test]
    fn ipv4_mapped_and_cgnat_forms_are_forbidden() {
        for value in [
            // IPv4-mapped IPv6 must not bypass the IPv4 rebinding rules — the
            // kernel reaches the embedded IPv4 destination on a dual-stack connect.
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.1.1",
            // Carrier-grade-NAT shared space (RFC 6598), plain and mapped.
            "100.64.0.1",
            "100.127.255.255",
            "::ffff:100.64.0.1",
        ] {
            assert!(
                dns_answer_forbidden(ip(value)),
                "{value} should be forbidden"
            );
        }
    }

    #[test]
    fn addresses_adjacent_to_explicit_ranges_are_allowed() {
        for value in [
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "fbff:ffff::1",
            "fe00::1",
            "fe7f:ffff::1",
            "fec0::1",
        ] {
            assert!(
                !dns_answer_forbidden(ip(value)),
                "{value} should be allowed"
            );
        }
    }
}

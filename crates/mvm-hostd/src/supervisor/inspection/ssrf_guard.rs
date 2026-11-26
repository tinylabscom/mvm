//! `SsrfGuard` — block outbound traffic to private/internal IPs.
//!
//! Classifies a destination by **IP address**. [`SsrfGuard::classify`]
//! names the range when the address falls into any of:
//!
//! - RFC1918 private ranges (10/8, 172.16/12, 192.168/16)
//! - Loopback (127/8, ::1)
//! - Link-local (169.254/16, fe80::/10)
//! - Carrier-grade NAT (100.64.0.0/10) — frequently used as private
//!   transit by cloud providers
//! - Multicast / broadcast / unspecified / documentation
//! - IPv6 unique-local (fc00::/7)
//! - **Cloud metadata services** (169.254.169.254 — AWS / Azure /
//!   GCP / Oracle; 100.100.100.200 — Alibaba). These are link-local
//!   and CGNAT respectively, but they earn their own deny reasons
//!   because the audit signal "your workload tried to reach IMDS"
//!   is much louder than "your workload tried to reach a link-local
//!   address."
//!
//! Threat shape addressed:
//! - LLM agent fetches `http://169.254.169.254/latest/meta-data/iam/
//!   security-credentials/...` and ships the cloud's instance
//!   credentials to a remote service.
//! - Workload tricked into hitting `http://localhost:8080/admin`
//!   inside a co-tenant.
//! - DNS rebinding: a name that first resolves to a public IP and on a
//!   second lookup to `127.0.0.1`. Callers classify the address they are
//!   about to connect to, not the name.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Classifier for private / internal / metadata IP ranges. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct SsrfGuard;

impl SsrfGuard {
    /// If `ip` is in a disallowed range, return a stable human-readable
    /// reason (used directly in deny strings). `None` means the IP is
    /// publicly routable.
    pub fn classify(ip: IpAddr) -> Option<&'static str> {
        match ip {
            IpAddr::V4(v4) => classify_v4(v4),
            IpAddr::V6(v6) => classify_v6(v6),
        }
        // Anything the shared egress classifier restricts is restricted here
        // too — the IPv4 addresses inside NAT64, 6to4, Teredo and
        // IPv4-compatible forms, and AWS's IPv6 metadata endpoint — so the host
        // tools never reach what a workload's egress may not.
        .or_else(|| {
            mvm_contract::policy::restricted_address::classify(ip)
                .map(mvm_contract::policy::restricted_address::RestrictedClass::describe)
        })
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<&'static str> {
    // Cloud-metadata IPs first so their (more informative) reason
    // wins over the generic link-local / CGNAT classifications they
    // would otherwise fall under.
    let oct = ip.octets();
    if oct == [169, 254, 169, 254] {
        return Some("cloud metadata service (169.254.169.254 — AWS/Azure/GCP IMDS)");
    }
    if oct == [100, 100, 100, 200] {
        return Some("cloud metadata service (100.100.100.200 — Alibaba IMDS)");
    }

    if ip.is_loopback() {
        return Some("IPv4 loopback (127.0.0.0/8)");
    }
    if ip.is_unspecified() {
        return Some("IPv4 unspecified (0.0.0.0)");
    }
    if ip.is_private() {
        return Some("IPv4 RFC1918 private (10/8, 172.16/12, or 192.168/16)");
    }
    if ip.is_link_local() {
        return Some("IPv4 link-local (169.254.0.0/16)");
    }
    if ip.is_broadcast() {
        return Some("IPv4 broadcast (255.255.255.255)");
    }
    if ip.is_multicast() {
        return Some("IPv4 multicast (224.0.0.0/4)");
    }
    if ip.is_documentation() {
        return Some("IPv4 documentation range (RFC5737)");
    }
    // RFC6598 carrier-grade NAT (100.64.0.0/10).
    if oct[0] == 100 && (oct[1] & 0b1100_0000) == 0b0100_0000 {
        return Some("IPv4 carrier-grade NAT (100.64.0.0/10)");
    }
    // RFC2544 benchmarking (198.18.0.0/15).
    if oct[0] == 198 && (oct[1] & 0xfe) == 18 {
        return Some("IPv4 RFC2544 benchmarking (198.18.0.0/15)");
    }
    None
}

fn classify_v6(ip: Ipv6Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("IPv6 loopback (::1)");
    }
    if ip.is_unspecified() {
        return Some("IPv6 unspecified (::)");
    }
    if ip.is_multicast() {
        return Some("IPv6 multicast (ff00::/8)");
    }
    let segs = ip.segments();
    // IPv4-mapped (::ffff:0:0/96) — reuse the IPv4 classification on
    // the embedded address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    // Unique-local fc00::/7
    if (segs[0] & 0xfe00) == 0xfc00 {
        return Some("IPv6 unique-local (fc00::/7)");
    }
    // Link-local fe80::/10
    if (segs[0] & 0xffc0) == 0xfe80 {
        return Some("IPv6 link-local (fe80::/10)");
    }
    // Documentation 2001:db8::/32
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return Some("IPv6 documentation range (2001:db8::/32)");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(ip: &str) -> Option<&'static str> {
        SsrfGuard::classify(ip.parse().expect("test address is an IP literal"))
    }

    #[test]
    fn the_shared_classifier_s_embedded_and_metadata_forms_are_blocked_too() {
        for addr in [
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::1",
            "fd00:ec2::254",
            "::10.0.0.1",
        ] {
            assert!(reason(addr).is_some(), "{addr}");
        }
    }

    // ---- IPv4 disallowed ranges ----

    #[test]
    fn v4_loopback_is_classified() {
        assert!(reason("127.0.0.1").expect("loopback").contains("loopback"));
    }

    #[test]
    fn v4_private_ranges_are_classified() {
        assert!(reason("10.0.0.1").is_some());
        assert!(reason("192.168.1.1").is_some());
        for octet in 16..=31 {
            let host = format!("172.{octet}.5.5");
            assert!(reason(&host).is_some(), "expected a class for {host}");
        }
        // 172.15 and 172.32 are publicly routable.
        assert!(reason("172.15.5.5").is_none());
        assert!(reason("172.32.5.5").is_none());
    }

    #[test]
    fn v4_link_local_is_classified() {
        assert!(
            reason("169.254.10.20")
                .expect("link-local")
                .contains("link-local")
        );
    }

    #[test]
    fn v4_aws_imds_gets_the_metadata_reason() {
        // 169.254.169.254 is link-local but the metadata-service
        // reason is much more informative for audit, so it must
        // win over the generic link-local label.
        let r = reason("169.254.169.254").expect("metadata");
        assert!(
            r.contains("metadata"),
            "reason should mention metadata service: {r}"
        );
    }

    #[test]
    fn v4_alibaba_imds_is_named() {
        assert!(
            reason("100.100.100.200")
                .expect("alibaba")
                .contains("Alibaba")
        );
    }

    #[test]
    fn v4_cgnat_is_classified() {
        // 100.64.0.0/10 — first octet 100, second between 64 and 127.
        assert!(reason("100.64.5.5").is_some());
        // 100.63 and 100.128 are NOT CGNAT.
        assert!(reason("100.63.5.5").is_none());
        assert!(reason("100.128.5.5").is_none());
    }

    #[test]
    fn v4_unspecified_and_multicast_are_classified() {
        assert!(reason("0.0.0.0").is_some());
        assert!(reason("224.0.0.1").is_some());
    }

    #[test]
    fn v4_public_addresses_are_not_classified() {
        for host in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.5.5",
            "192.169.1.1",
            "104.18.32.10",
        ] {
            assert_eq!(reason(host), None, "expected no class for {host}");
        }
    }

    // ---- IPv6 ----

    #[test]
    fn v6_internal_ranges_are_classified() {
        for host in [
            "::1",
            "fe80::1",
            "fd12:3456:789a::1",
            "::",
            "::ffff:127.0.0.1",
        ] {
            assert!(reason(host).is_some(), "expected a class for {host}");
        }
        assert!(SsrfGuard::classify(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_some());
    }

    #[test]
    fn v6_public_address_is_not_classified() {
        // Google's public DNS over IPv6.
        assert_eq!(reason("2001:4860:4860::8888"), None);
        assert!(SsrfGuard::classify(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_none());
    }
}

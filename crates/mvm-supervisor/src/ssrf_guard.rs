//! `SsrfGuard` — block outbound traffic to private/internal IPs.
//!
//! Plan 37 §15 third-line defence (Wave 2.3). Where Wave 2.1's
//! `DestinationPolicy` filters by **(host, port) string** and Wave
//! 2.2's `SecretsScanner` filters by body content, this inspector
//! filters by **resolved IP**. It refuses requests whose destination
//! IP falls into any of:
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
//! - DNS rebinding: attacker registers `evil.com` whose A record
//!   first returns a public IP (passes DestinationPolicy at policy-
//!   evaluation time) and on a second lookup returns `127.0.0.1`.
//!   The proxy's job is to resolve **once** and pin the IP into
//!   `RequestCtx::resolved_ip`; this guard verifies the pinned IP
//!   isn't internal.
//!
//! Match logic:
//! 1. Try parsing `ctx.host` as an `IpAddr`. If it parses, that's
//!    the IP we'd connect to (no DNS step). Check it.
//! 2. Else if `ctx.resolved_ip` is set, check that.
//! 3. Else, the proxy hasn't resolved DNS yet — Allow (this guard
//!    is re-run after resolution; running it before is a no-op).
//!
//! The guard is **agnostic to whether DestinationPolicy passed**.
//! Both checks must pass — DestinationPolicy alone is bypassable
//! because hostnames don't tell you which IP a packet actually goes
//! to. SsrfGuard must run after DNS has been resolved by the proxy;
//! the recommended chain order is `DestinationPolicy → SsrfGuard →
//! SecretsScanner → ...`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;

use crate::inspector::{Inspector, InspectorVerdict, RequestCtx};

/// Inspector that refuses requests targeting private / internal /
/// metadata IP ranges. Stateless — the same instance is shared
/// across the chain.
#[derive(Debug, Default, Clone, Copy)]
pub struct SsrfGuard;

impl SsrfGuard {
    pub const fn new() -> Self {
        Self
    }

    /// If `ip` is in a disallowed range, return a stable human-readable
    /// reason (used directly in deny strings). `None` means the IP is
    /// publicly routable.
    pub fn classify(ip: IpAddr) -> Option<&'static str> {
        match ip {
            IpAddr::V4(v4) => classify_v4(v4),
            IpAddr::V6(v6) => classify_v6(v6),
        }
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

#[async_trait]
impl Inspector for SsrfGuard {
    fn name(&self) -> &'static str {
        "ssrf_guard"
    }

    async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
        // Two routes to a checkable IP:
        //   - host parses as IP literal (no DNS step)
        //   - proxy already resolved DNS into resolved_ip
        // If neither holds, the proxy hasn't done its job yet and
        // the guard runs as a no-op (the chain re-runs post-DNS).
        let candidate = match ctx.host.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => ctx.resolved_ip,
        };
        let Some(ip) = candidate else {
            return InspectorVerdict::Allow;
        };
        match Self::classify(ip) {
            Some(reason) => InspectorVerdict::Deny {
                reason: format!("destination IP {ip} blocked by SSRF guard: {reason}"),
            },
            None => InspectorVerdict::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ctx_with_host(host: &str) -> RequestCtx {
        RequestCtx::new(host, 443, "/")
    }

    fn ctx_resolved(host: &str, ip: IpAddr) -> RequestCtx {
        RequestCtx::new(host, 443, "/").with_resolved_ip(ip)
    }

    // ---- IPv4 disallowed ranges ----

    #[tokio::test]
    async fn v4_loopback_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("127.0.0.1"))
            .await;
        assert!(v.is_deny());
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("loopback"));
            assert!(reason.contains("127.0.0.1"));
        }
    }

    #[tokio::test]
    async fn v4_private_10_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("10.0.0.1"))
            .await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn v4_private_192_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("192.168.1.1"))
            .await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn v4_private_172_denies() {
        for octet in 16..=31 {
            let host = format!("172.{octet}.5.5");
            let v = SsrfGuard::new().inspect(&mut ctx_with_host(&host)).await;
            assert!(v.is_deny(), "expected deny for {host}");
        }
        // 172.15 and 172.32 are publicly routable.
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("172.15.5.5"))
            .await;
        assert!(v.is_allow());
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("172.32.5.5"))
            .await;
        assert!(v.is_allow());
    }

    #[tokio::test]
    async fn v4_link_local_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("169.254.10.20"))
            .await;
        assert!(v.is_deny());
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("link-local"));
        }
    }

    #[tokio::test]
    async fn v4_aws_imds_denies_with_specific_reason() {
        // 169.254.169.254 is link-local but the metadata-service
        // reason is much more informative for audit, so it must
        // win over the generic link-local label.
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("169.254.169.254"))
            .await;
        assert!(v.is_deny());
        if let InspectorVerdict::Deny { reason } = v {
            assert!(
                reason.contains("metadata"),
                "reason should mention metadata service: {reason}"
            );
            assert!(reason.contains("169.254.169.254"));
        }
    }

    #[tokio::test]
    async fn v4_alibaba_imds_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("100.100.100.200"))
            .await;
        assert!(v.is_deny());
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("Alibaba"));
        }
    }

    #[tokio::test]
    async fn v4_cgnat_denies() {
        // 100.64.0.0/10 — first octet 100, second between 64 and 127.
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("100.64.5.5"))
            .await;
        assert!(v.is_deny());
        // 100.63 and 100.128 are NOT CGNAT.
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("100.63.5.5"))
            .await;
        assert!(v.is_allow());
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("100.128.5.5"))
            .await;
        assert!(v.is_allow());
    }

    #[tokio::test]
    async fn v4_unspecified_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("0.0.0.0"))
            .await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn v4_multicast_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("224.0.0.1"))
            .await;
        assert!(v.is_deny());
    }

    // ---- IPv4 publicly routable allowed ----

    #[tokio::test]
    async fn v4_public_allows() {
        for host in ["8.8.8.8", "1.1.1.1", "172.15.5.5", "192.169.1.1"] {
            let v = SsrfGuard::new().inspect(&mut ctx_with_host(host)).await;
            assert!(v.is_allow(), "expected allow for {host}, got {v:?}");
        }
    }

    // ---- IPv6 disallowed ranges ----

    #[tokio::test]
    async fn v6_loopback_denies() {
        let v = SsrfGuard::new().inspect(&mut ctx_with_host("::1")).await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn v6_link_local_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("fe80::1"))
            .await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn v6_unique_local_denies() {
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("fd12:3456:789a::1"))
            .await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn v6_unspecified_denies() {
        let v = SsrfGuard::new().inspect(&mut ctx_with_host("::")).await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn v6_v4mapped_loopback_denies() {
        // ::ffff:127.0.0.1 — should be classified by the embedded v4.
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("::ffff:127.0.0.1"))
            .await;
        assert!(v.is_deny(), "expected deny, got {v:?}");
    }

    #[tokio::test]
    async fn v6_public_allows() {
        // Google's public DNS over IPv6.
        let v = SsrfGuard::new()
            .inspect(&mut ctx_with_host("2001:4860:4860::8888"))
            .await;
        assert!(v.is_allow());
    }

    // ---- DNS-resolved path (host is a name, IP is pinned) ----

    #[tokio::test]
    async fn hostname_with_resolved_internal_ip_denies() {
        // The proxy resolved `evil.com` to a private IP — this is
        // exactly the DNS-rebinding vector this guard exists for.
        let mut c = ctx_resolved("evil.com", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let v = SsrfGuard::new().inspect(&mut c).await;
        assert!(v.is_deny(), "expected deny, got {v:?}");
    }

    #[tokio::test]
    async fn hostname_with_resolved_imds_denies() {
        let mut c = ctx_resolved(
            "metadata.google.internal",
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        );
        let v = SsrfGuard::new().inspect(&mut c).await;
        assert!(v.is_deny());
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("metadata"));
        }
    }

    #[tokio::test]
    async fn hostname_with_resolved_public_ip_allows() {
        let mut c = ctx_resolved("api.openai.com", IpAddr::V4(Ipv4Addr::new(104, 18, 32, 10)));
        let v = SsrfGuard::new().inspect(&mut c).await;
        assert!(v.is_allow());
    }

    #[tokio::test]
    async fn hostname_without_resolved_ip_allows() {
        // No IP literal, no resolved_ip — the guard is a no-op and
        // the chain proceeds. The proxy is responsible for re-running
        // the chain after DNS resolution.
        let mut c = ctx_with_host("api.openai.com");
        let v = SsrfGuard::new().inspect(&mut c).await;
        assert!(v.is_allow());
    }

    // ---- direct classify() coverage ----

    #[test]
    fn classify_returns_none_for_public_v4() {
        assert!(SsrfGuard::classify(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_none());
    }

    #[test]
    fn classify_returns_some_for_private_v4() {
        assert!(SsrfGuard::classify(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_some());
    }

    #[test]
    fn classify_returns_some_for_v6_loopback() {
        assert!(SsrfGuard::classify(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_some());
    }
}

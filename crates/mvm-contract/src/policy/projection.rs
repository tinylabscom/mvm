//! Egress policy projection seam.
//!
//! A launch's [`NetworkPolicy`] projects to the canonical CIDR-keyed grant
//! set the per-VM endpoint's egress gate consumes. Hostnames are pinned to
//! IPs at projection time (via the admission-time `DnsPinRegistry`), so live
//! DNS never widens reach. [`CanonicalEgress::permits`] is the one decision
//! function, and it denies the mandatory-deny ranges whatever the rules say.
//!
//! This module is decision logic only — no enforcement, no I/O,
//! no resolver.
//!
//! [`NetworkPolicy`]: crate::policy::network_policy::NetworkPolicy

use core::net::IpAddr;

use alloc::string::String;
use alloc::vec::Vec;

use ipnet::IpNet;
use thiserror::Error;

use crate::policy::dns_pin::DnsPinRegistry;
use crate::policy::network_policy::{is_banned_ssh_port, is_mandatory_deny};

/// L4 protocol of a canonical rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

/// One canonical egress rule over the pinned address space.
/// `port_lo..=port_hi` is inclusive; the any-port wildcard is
/// normalized to `(0, 65535)` before a rule is constructed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalRule {
    pub proto: Proto,
    pub net: IpNet,
    pub port_lo: u16,
    pub port_hi: u16,
}

impl CanonicalRule {
    /// Pure membership decision: does this rule admit the probe?
    pub fn permits(&self, proto: &Proto, ip: IpAddr, port: u16) -> bool {
        debug_assert!(self.port_lo <= self.port_hi, "inverted port range");
        self.proto == *proto
            && self.net.contains(&ip)
            && self.port_lo <= port
            && port <= self.port_hi
    }
}

/// The canonical projection of a resolved policy's egress grants.
/// `Unrestricted` is the `egress.mode = "open"` kill-switch made
/// explicit; mandatory-deny still applies to it.
///
/// Translators that lower `Rules` into an enforcement backend must
/// keep installing mandatory-deny independently and first — the
/// unconditional check in [`Self::permits`] is this module's backstop,
/// not a substitute for the enforcement layer's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalEgress {
    Unrestricted,
    Rules(Vec<CanonicalRule>),
}

impl CanonicalEgress {
    /// The single decision function both enforcement layers must
    /// agree with. Mandatory-deny is checked first and is
    /// unconditional — no grant shape can override it.
    ///
    /// A private-range address (RFC1918, IPv6 unique-local, multicast,
    /// reserved) is admitted only by a rule that names it specifically: a
    /// literal address or a CIDR inside that private range, which is also
    /// what a pinned allow-list host lowers to. An unrestricted grant, or a
    /// rule for a supernet such as `0.0.0.0/0`, names no private address and
    /// so admits none. See [`crate::policy::restricted_address`].
    pub fn permits(&self, proto: &Proto, ip: IpAddr, port: u16) -> bool {
        use crate::policy::restricted_address::{classify, grant_readmits};
        if is_mandatory_deny(ip) {
            return false;
        }
        if is_banned_ssh_flow(proto, port) {
            return false;
        }
        match self {
            Self::Unrestricted => classify(ip).is_none(),
            Self::Rules(rules) => rules
                .iter()
                .any(|r| r.permits(proto, ip, port) && grant_readmits(&r.net, ip)),
        }
    }
}

fn is_banned_ssh_flow(proto: &Proto, port: u16) -> bool {
    *proto == Proto::Tcp && is_banned_ssh_port(port)
}

/// Projection-time refusals. Every variant is fail-closed: a grant that
/// cannot be projected admits nothing.
#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("no admission-time DNS pin for allow-list host {host:?}")]
    MissingPin { host: String },
    #[error("DNS pin for {host:?} expired at {expires_at}")]
    ExpiredPin { host: String, expires_at: String },
    #[error("DNS pin for {host:?} has an empty IP set")]
    EmptyPin { host: String },
}

/// Normalize the wire-format any-port wildcard `(0, 0)` to the
/// explicit full range. Any other pair passes through verbatim.
fn normalize_ports(lo: u16, hi: u16) -> (u16, u16) {
    if lo == 0 && hi == 0 {
        (0, 65535)
    } else {
        (lo, hi)
    }
}

/// Lower a bare [`crate::policy::network_policy::NetworkPolicy`] (the
/// no-signed-bundle transient/dev path) + admission-time DNS pins into the
/// canonical egress grant set. The endpoint's egress gate is built from this, so
/// a bare allow-list gates `host:port` on the pinned addresses and a direct dial
/// to an unlisted address is refused, not just an unlisted name.
///
/// - unrestricted ⇒ [`CanonicalEgress::Unrestricted`] (mandatory-deny still applies).
/// - deny-all (empty rule set) ⇒ `Rules([])`: admits nothing.
/// - allow-list / preset ⇒ one TCP rule per (pinned IP, port), and nothing
///   else. It admits no UDP at all, port 53 included: a guest resolves names
///   through the gate's DNS verdict over the pin registry, never by sending
///   raw datagrams to a resolver of its choosing.
///
/// Fail-closed: a host with no live, non-empty pin returns an error and the
/// caller drops to deny-all. Lenient on mandatory-deny overlap —
/// [`CanonicalEgress::permits`] denies those ranges at decision time.
pub fn canonicalize_network_policy(
    policy: &crate::policy::network_policy::NetworkPolicy,
    pins: &DnsPinRegistry,
    now: &str,
) -> Result<CanonicalEgress, ProjectionError> {
    let rules = match policy.resolve_rules() {
        // `None` ⇒ unrestricted kill-switch.
        None => return Ok(CanonicalEgress::Unrestricted),
        Some(rules) => rules,
    };
    let mut canon = Vec::new();
    for hp in &rules {
        let pin = pins
            .lookup(&hp.host)
            .ok_or_else(|| ProjectionError::MissingPin {
                host: hp.host.clone(),
            })?;
        if !pin.is_valid_at(now) {
            return Err(ProjectionError::ExpiredPin {
                host: hp.host.clone(),
                expires_at: pin.expires_at.clone(),
            });
        }
        if pin.ips.is_empty() {
            return Err(ProjectionError::EmptyPin {
                host: hp.host.clone(),
            });
        }
        let (port_lo, port_hi) = normalize_ports(hp.port, hp.port);
        for pinned in &pin.ips {
            canon.push(CanonicalRule {
                proto: Proto::Tcp,
                net: host_net(*pinned),
                port_lo,
                port_hi,
            });
        }
    }
    canon.sort();
    canon.dedup();
    Ok(CanonicalEgress::Rules(canon))
}

/// A pinned IP as a host-length net (`/32` or `/128`), explicit
/// so there is no doubt about prefix length.
fn host_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).expect("/32 is always valid")),
        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).expect("/128 is always valid")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use crate::policy::network_policy::BANNED_SSH_PORT;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }

    const NOW: &str = "2026-06-11T00:00:00Z";

    // ── canonicalize_network_policy: the bare (no-bundle) transient lowering ──
    // (reuses the `pin` / `registry` helpers defined lower in this module)

    #[test]
    fn bare_unrestricted_is_unrestricted() {
        let eg = canonicalize_network_policy(
            &crate::policy::network_policy::NetworkPolicy::unrestricted(),
            &DnsPinRegistry::new(),
            NOW,
        )
        .unwrap();
        assert_eq!(eg, CanonicalEgress::Unrestricted);
    }

    #[test]
    fn bare_deny_all_admits_nothing() {
        let eg = canonicalize_network_policy(
            &crate::policy::network_policy::NetworkPolicy::deny_all(),
            &DnsPinRegistry::new(),
            NOW,
        )
        .unwrap();
        assert_eq!(eg, CanonicalEgress::Rules(vec![]));
        // Deny-all admits no datagram, DNS port included.
        assert!(!eg.permits(&Proto::Udp, ip("1.1.1.1"), 53));
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn bare_allow_list_pins_host_port_and_admits_no_udp() {
        let np = crate::policy::network_policy::NetworkPolicy::allow_list(vec![
            crate::policy::network_policy::HostPort::new("example.com", 443),
        ]);
        let eg = canonicalize_network_policy(
            &np,
            &registry(vec![pin("example.com", &["93.184.216.34"])]),
            NOW,
        )
        .unwrap();
        // The pinned host:port is admitted…
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        // …but a different port on the same IP is not (port gating — the fix).
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 8080));
        // …and a direct dial to an unlisted IP is denied (the bypass closed).
        assert!(!eg.permits(&Proto::Tcp, ip("8.8.8.8"), 443));
        // No UDP is admitted, port 53 included, to a public or a private
        // resolver: names resolve through the gate's DNS verdict, not raw UDP.
        assert!(!eg.permits(&Proto::Udp, ip("1.1.1.1"), 53));
        assert!(!eg.permits(&Proto::Udp, ip("192.168.1.1"), 53));
        assert!(!eg.permits(&Proto::Udp, ip("93.184.216.34"), 443));
        // TCP/53 to an unlisted resolver is refused as well.
        assert!(!eg.permits(&Proto::Tcp, ip("1.1.1.1"), 53));
        // Mandatory-deny still refuses UDP/53 to the metadata address.
        assert!(!eg.permits(&Proto::Udp, ip("169.254.169.254"), 53));
    }

    #[test]
    fn bare_allow_list_pins_every_resolved_ip() {
        let np = crate::policy::network_policy::NetworkPolicy::allow_list(vec![
            crate::policy::network_policy::HostPort::new("multi.example", 443),
        ]);
        let eg = canonicalize_network_policy(
            &np,
            &registry(vec![pin("multi.example", &["203.0.113.7", "198.51.100.9"])]),
            NOW,
        )
        .unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("203.0.113.7"), 443));
        assert!(eg.permits(&Proto::Tcp, ip("198.51.100.9"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("203.0.113.8"), 443));
    }

    #[test]
    fn bare_allow_list_fails_closed_on_missing_pin() {
        let np = crate::policy::network_policy::NetworkPolicy::allow_list(vec![
            crate::policy::network_policy::HostPort::new("unresolved.example", 443),
        ]);
        let err = canonicalize_network_policy(&np, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::MissingPin { .. }));
    }

    #[test]
    fn bare_allow_list_fails_closed_on_empty_pin() {
        let np = crate::policy::network_policy::NetworkPolicy::allow_list(vec![
            crate::policy::network_policy::HostPort::new("empty.example", 443),
        ]);
        let err = canonicalize_network_policy(&np, &registry(vec![pin("empty.example", &[])]), NOW)
            .unwrap_err();
        assert!(matches!(err, ProjectionError::EmptyPin { .. }));
    }

    #[test]
    fn bare_allow_list_fails_closed_on_expired_pin() {
        let np = crate::policy::network_policy::NetworkPolicy::allow_list(vec![
            crate::policy::network_policy::HostPort::new("stale.example", 443),
        ]);
        let stale = DnsPin::at(
            "stale.example",
            vec![ip("93.184.216.34")],
            "2020-01-01T00:00:00Z",
            "2020-01-01T01:00:00Z",
        );
        let err = canonicalize_network_policy(&np, &registry(vec![stale]), NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::ExpiredPin { .. }));
    }

    #[test]
    fn canonical_rule_permits_inside_net_and_port_range() {
        let rule = CanonicalRule {
            proto: Proto::Tcp,
            net: net("10.0.0.0/24"),
            port_lo: 443,
            port_hi: 443,
        };
        assert!(rule.permits(&Proto::Tcp, ip("10.0.0.7"), 443));
    }

    #[test]
    fn canonical_rule_denies_wrong_proto_ip_or_port() {
        let rule = CanonicalRule {
            proto: Proto::Tcp,
            net: net("10.0.0.0/24"),
            port_lo: 443,
            port_hi: 443,
        };
        assert!(
            !rule.permits(&Proto::Udp, ip("10.0.0.7"), 443),
            "proto mismatch"
        );
        assert!(
            !rule.permits(&Proto::Tcp, ip("10.0.1.7"), 443),
            "ip outside net"
        );
        assert!(
            !rule.permits(&Proto::Tcp, ip("10.0.0.7"), 80),
            "port outside range"
        );
    }

    #[test]
    fn canonical_rule_supports_ipv6() {
        let rule = CanonicalRule {
            proto: Proto::Udp,
            net: net("2001:db8::/32"),
            port_lo: 0,
            port_hi: 65535,
        };
        assert!(rule.permits(&Proto::Udp, ip("2001:db8::1"), 53));
        assert!(!rule.permits(&Proto::Udp, ip("2001:db9::1"), 53));
    }

    #[test]
    fn canonical_rule_port_range_is_inclusive_at_both_ends() {
        let rule = CanonicalRule {
            proto: Proto::Tcp,
            net: net("10.0.0.0/24"),
            port_lo: 80,
            port_hi: 443,
        };
        assert!(rule.permits(&Proto::Tcp, ip("10.0.0.7"), 80));
        assert!(rule.permits(&Proto::Tcp, ip("10.0.0.7"), 443));
        assert!(!rule.permits(&Proto::Tcp, ip("10.0.0.7"), 79));
        assert!(!rule.permits(&Proto::Tcp, ip("10.0.0.7"), 444));
    }

    #[test]
    fn canonical_rule_port_zero_only_rule_is_not_a_wildcard() {
        // (0, 0) is normalized to (0, 65535) by the lowering before
        // a rule is built; a literal (0, 0) rule permits only port 0.
        let rule = CanonicalRule {
            proto: Proto::Tcp,
            net: net("10.0.0.0/24"),
            port_lo: 0,
            port_hi: 0,
        };
        assert!(rule.permits(&Proto::Tcp, ip("10.0.0.7"), 0));
        assert!(!rule.permits(&Proto::Tcp, ip("10.0.0.7"), 1));
    }

    #[test]
    fn canonical_egress_rules_permit_only_matching_probe() {
        let eg = CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Tcp,
            net: net("93.184.216.0/24"),
            port_lo: 443,
            port_hi: 443,
        }]);
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.217.34"), 443));
    }

    #[test]
    fn canonical_egress_empty_rules_is_deny_all() {
        let eg = CanonicalEgress::Rules(vec![]);
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn canonical_egress_unrestricted_permits_ordinary_destinations() {
        let eg = CanonicalEgress::Unrestricted;
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(eg.permits(&Proto::Udp, ip("8.8.8.8"), 53));
    }

    #[test]
    fn ssh_port_is_denied_even_under_unrestricted() {
        let eg = CanonicalEgress::Unrestricted;
        assert!(
            !eg.permits(&Proto::Tcp, ip("93.184.216.34"), BANNED_SSH_PORT),
            "TCP/22 is banned even under open egress"
        );
        assert!(
            eg.permits(&Proto::Udp, ip("93.184.216.34"), BANNED_SSH_PORT),
            "the SSH ban is TCP/22-specific, not an unrelated UDP port block"
        );
    }

    #[test]
    fn mandatory_deny_wins_even_under_unrestricted() {
        // The `open` kill-switch never reaches metadata/loopback: even an
        // open policy keeps every destination gated by mandatory-deny.
        let eg = CanonicalEgress::Unrestricted;
        for denied in ["169.254.169.254", "127.0.0.1", "100.64.0.1", "::1"] {
            assert!(
                !eg.permits(&Proto::Tcp, ip(denied), 443),
                "{denied} must be denied under unrestricted"
            );
        }
    }

    #[test]
    fn mandatory_deny_wins_even_when_a_rule_matches() {
        // A rule that (somehow) covers a denied address still
        // denies at decision time — belt to the projection-time
        // refusal's suspenders.
        let eg = CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Tcp,
            net: net("0.0.0.0/0"),
            port_lo: 0,
            port_hi: 65535,
        }]);
        assert!(!eg.permits(&Proto::Tcp, ip("169.254.169.254"), 80));
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 80));
    }

    fn pin(dest: &str, ips: &[&str]) -> DnsPin {
        DnsPin::at(
            dest,
            ips.iter().map(|s| ip(s)).collect(),
            "2026-06-10T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )
    }

    fn registry(pins: Vec<DnsPin>) -> DnsPinRegistry {
        let mut reg = DnsPinRegistry::new();
        for p in pins {
            reg.add(p);
        }
        reg
    }
}

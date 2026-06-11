//! Egress policy projection seam.
//!
//! One resolved [`EffectivePolicy`] projects to two enforcement
//! shapes: the canonical CIDR-keyed grant set the kernel layer
//! (nftables / `LiveL4Gate` / `PlanFlowPolicy`) consumes, and the
//! hostname-keyed outbound grant set the WASI context builder
//! consumes. Hostnames are pinned to IPs at projection time (via
//! the admission-time [`DnsPinRegistry`]) so both projections are
//! compared and enforced over the same pinned address space —
//! live DNS never widens reach. Mandatory-deny ranges refuse at
//! projection time, unconditionally: a grant that resolves into a
//! denied range is an error, not a pin.
//!
//! This module is decision logic only — no enforcement, no I/O,
//! no resolver. The cross-projection consistency property test is
//! the anti-drift witness: both projections must decide
//! identically for every probe.
//!
//! [`EffectivePolicy`]: crate::policy::resolver::EffectivePolicy
//! [`DnsPinRegistry`]: crate::policy::dns_pin::DnsPinRegistry

use std::net::IpAddr;

use ipnet::IpNet;
use thiserror::Error;

use crate::policy::network_policy::is_mandatory_deny;

/// L4 protocol of a canonical rule. The string forms `"tcp"` /
/// `"udp"` are the `L4RuleSpec.proto` wire values; anything else
/// refuses at projection time (loud failure at admission, not a
/// silent drop at runtime — same posture as `LiveL4Gate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl std::str::FromStr for Proto {
    type Err = ProjectionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(ProjectionError::UnknownProto {
                proto: other.to_string(),
            }),
        }
    }
}

impl Proto {
    /// Named alias for [`FromStr`] used by the lowering code.
    pub fn parse(s: &str) -> Result<Self, ProjectionError> {
        s.parse()
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalEgress {
    Unrestricted,
    Rules(Vec<CanonicalRule>),
}

impl CanonicalEgress {
    /// The single decision function both enforcement layers must
    /// agree with. Mandatory-deny is checked first and is
    /// unconditional — no grant shape can override it.
    pub fn permits(&self, proto: &Proto, ip: IpAddr, port: u16) -> bool {
        if is_mandatory_deny(ip) {
            return false;
        }
        match self {
            Self::Unrestricted => true,
            Self::Rules(rules) => rules.iter().any(|r| r.permits(proto, ip, port)),
        }
    }
}

/// Projection-time refusals. Every variant is a fail-closed
/// admission error: the plan does not admit with a grant the
/// projections could not agree on.
#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("unknown proto {proto:?} (expected \"tcp\" or \"udp\")")]
    UnknownProto { proto: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
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
    fn proto_parses_tcp_udp_and_refuses_unknown() {
        assert_eq!(Proto::parse("tcp").unwrap(), Proto::Tcp);
        assert_eq!(Proto::parse("udp").unwrap(), Proto::Udp);
        assert!(matches!(
            Proto::parse("icmp"),
            Err(ProjectionError::UnknownProto { .. })
        ));
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
    fn proto_fromstr_roundtrip() {
        assert_eq!("tcp".parse::<Proto>().unwrap(), Proto::Tcp);
        assert_eq!("udp".parse::<Proto>().unwrap(), Proto::Udp);
        assert!("TCP".parse::<Proto>().is_err());
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
    fn mandatory_deny_wins_even_under_unrestricted() {
        // The `open` kill-switch never reaches metadata/loopback —
        // mirrors the gateway-bridge invariant that even an open
        // policy keeps every packet gated by mandatory-deny.
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
}

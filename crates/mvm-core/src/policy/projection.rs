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

use crate::policy::dns_pin::DnsPinRegistry;
use crate::policy::network_policy::{is_mandatory_deny, mandatory_deny_ranges};
use crate::policy::resolver::EffectivePolicy;

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
    #[error("unparseable dst_cidr {cidr:?}: {source}")]
    BadCidr {
        cidr: String,
        source: ipnet::AddrParseError,
    },
    #[error("no admission-time DNS pin for allow-list host {host:?}")]
    MissingPin { host: String },
    #[error("DNS pin for {host:?} expired at {expires_at}")]
    ExpiredPin { host: String, expires_at: String },
    #[error("DNS pin for {host:?} has an empty IP set")]
    EmptyPin { host: String },
    #[error("grant for {dest:?} overlaps mandatory-deny range {range}")]
    MandatoryDenyOverlap { dest: String, range: IpNet },
}

/// True when two CIDRs share any address. For valid CIDRs, two
/// nets overlap iff one contains the other's network address.
fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Refuse any grant net that intersects a mandatory-deny range.
/// Projection-time belt; `CanonicalEgress::permits` keeps the
/// decision-time suspenders.
fn refuse_mandatory_overlap(dest: &str, net: &IpNet) -> Result<(), ProjectionError> {
    for deny in mandatory_deny_ranges() {
        if nets_overlap(&deny, net) {
            return Err(ProjectionError::MandatoryDenyOverlap {
                dest: dest.to_string(),
                range: deny,
            });
        }
    }
    Ok(())
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

/// Lower a resolved policy + admission-time pin registry into the
/// canonical egress grant set. Pure; fail-closed on every
/// malformed or unpinnable input. `now` is an RFC 3339 UTC
/// timestamp (the caller's clock — tests pass a fixed string),
/// used to refuse expired pins.
pub fn canonicalize_effective(
    eff: &EffectivePolicy,
    pins: &DnsPinRegistry,
    now: &str,
) -> Result<CanonicalEgress, ProjectionError> {
    if eff.egress.mode.as_deref() == Some("open") {
        return Ok(CanonicalEgress::Unrestricted);
    }
    let mut rules = Vec::new();
    for spec in &eff.network.l4 {
        let net: IpNet = spec
            .dst_cidr
            .parse()
            .map_err(|source| ProjectionError::BadCidr {
                cidr: spec.dst_cidr.clone(),
                source,
            })?;
        refuse_mandatory_overlap(&spec.dst_cidr, &net)?;
        let (port_lo, port_hi) = normalize_ports(spec.port_lo, spec.port_hi);
        rules.push(CanonicalRule {
            proto: Proto::parse(&spec.proto)?,
            net,
            port_lo,
            port_hi,
        });
    }
    rules.extend(pinned_allow_list_rules(eff, pins, now)?);
    rules.sort();
    rules.dedup();
    Ok(CanonicalEgress::Rules(rules))
}

/// A pinned IP as a host-length net (`/32` or `/128`), explicit
/// so there is no doubt about prefix length.
fn host_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).expect("/32 is always valid")),
        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).expect("/128 is always valid")),
    }
}

/// Lower `egress.allow_list` (hostname, port) entries through the
/// pin registry. Allow-list destinations are L7/TCP (they feed the
/// CONNECT-shaped egress proxy), so the canonical rules are TCP.
/// Fail-closed: a host without a live pin refuses the whole
/// projection rather than silently dropping the entry.
fn pinned_allow_list_rules(
    eff: &EffectivePolicy,
    pins: &DnsPinRegistry,
    now: &str,
) -> Result<Vec<CanonicalRule>, ProjectionError> {
    let mut rules = Vec::new();
    for (host, port) in &eff.egress.allow_list {
        let pin = pins
            .lookup(host)
            .ok_or_else(|| ProjectionError::MissingPin { host: host.clone() })?;
        if !pin.is_valid_at(now) {
            return Err(ProjectionError::ExpiredPin {
                host: host.clone(),
                expires_at: pin.expires_at.clone(),
            });
        }
        if pin.ips.is_empty() {
            return Err(ProjectionError::EmptyPin { host: host.clone() });
        }
        let (port_lo, port_hi) = normalize_ports(*port, *port);
        for pinned in &pin.ips {
            let net = host_net(*pinned);
            refuse_mandatory_overlap(host, &net)?;
            rules.push(CanonicalRule {
                proto: Proto::Tcp,
                net,
                port_lo,
                port_hi,
            });
        }
    }
    Ok(rules)
}

/// One outbound target in the WASI-facing (hostname-keyed) shape.
/// `PinnedHost` is what a `WasiCtx` outbound-host grant becomes
/// once pinned; `Net` carries an L4 CIDR rule that has no
/// hostname. The wasmtime runner maps this shape onto the actual
/// `WasiCtxBuilder`; nothing here depends on wasmtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasiTarget {
    PinnedHost { host: String, ips: Vec<IpAddr> },
    Net(IpNet),
}

/// One outbound grant in the WASI-facing shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiOutboundGrant {
    pub target: WasiTarget,
    pub proto: Proto,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// The WASI-facing projection of a resolved policy's egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasiEgress {
    Unrestricted,
    Grants(Vec<WasiOutboundGrant>),
}

/// Project the resolved policy into the WASI-facing shape. A
/// deliberately separate walk from [`canonicalize_effective`] —
/// the cross-projection witness compares the two paths' decisions
/// and exists to catch drift between them. The refusal ladder
/// (bad CIDR, unknown proto, missing/expired/empty pin,
/// mandatory-deny overlap) is intentionally identical.
pub fn to_wasi_grants(
    eff: &EffectivePolicy,
    pins: &DnsPinRegistry,
    now: &str,
) -> Result<WasiEgress, ProjectionError> {
    if eff.egress.mode.as_deref() == Some("open") {
        return Ok(WasiEgress::Unrestricted);
    }
    let mut grants = Vec::new();
    for spec in &eff.network.l4 {
        let net: IpNet = spec
            .dst_cidr
            .parse()
            .map_err(|source| ProjectionError::BadCidr {
                cidr: spec.dst_cidr.clone(),
                source,
            })?;
        refuse_mandatory_overlap(&spec.dst_cidr, &net)?;
        let (port_lo, port_hi) = normalize_ports(spec.port_lo, spec.port_hi);
        grants.push(WasiOutboundGrant {
            target: WasiTarget::Net(net),
            proto: Proto::parse(&spec.proto)?,
            port_lo,
            port_hi,
        });
    }
    for (host, port) in &eff.egress.allow_list {
        let pin = pins
            .lookup(host)
            .ok_or_else(|| ProjectionError::MissingPin { host: host.clone() })?;
        if !pin.is_valid_at(now) {
            return Err(ProjectionError::ExpiredPin {
                host: host.clone(),
                expires_at: pin.expires_at.clone(),
            });
        }
        if pin.ips.is_empty() {
            return Err(ProjectionError::EmptyPin { host: host.clone() });
        }
        for pinned in &pin.ips {
            refuse_mandatory_overlap(host, &host_net(*pinned))?;
        }
        let (port_lo, port_hi) = normalize_ports(*port, *port);
        grants.push(WasiOutboundGrant {
            target: WasiTarget::PinnedHost {
                host: host.clone(),
                ips: pin.ips.clone(),
            },
            proto: Proto::Tcp,
            port_lo,
            port_hi,
        });
    }
    Ok(WasiEgress::Grants(grants))
}

/// True when `covering` admits every probe `covered` admits:
/// same proto, supernet-or-equal, port-range superset.
fn covers(covering: &CanonicalRule, covered: &CanonicalRule) -> bool {
    covering.proto == covered.proto
        && covering.net.contains(&covered.net)
        && covering.port_lo <= covered.port_lo
        && covered.port_hi <= covering.port_hi
}

/// Intersection-only merge of a *requested* grant set against the
/// *resolved* (authoritative) one. The request can attenuate,
/// never widen: a requested rule survives only when some resolved
/// rule fully covers it; partial overlaps drop whole (fail-closed,
/// no rule splitting). `Unrestricted` on the request side grants
/// exactly the resolved set.
pub fn clamp(requested: &CanonicalEgress, resolved: &CanonicalEgress) -> CanonicalEgress {
    match (requested, resolved) {
        (CanonicalEgress::Unrestricted, _) => resolved.clone(),
        (CanonicalEgress::Rules(_), CanonicalEgress::Unrestricted) => requested.clone(),
        (CanonicalEgress::Rules(req), CanonicalEgress::Rules(res)) => CanonicalEgress::Rules(
            req.iter()
                .filter(|r| res.iter().any(|s| covers(s, r)))
                .cloned()
                .collect(),
        ),
    }
}

/// The WASI-side decision function. Must agree with
/// [`CanonicalEgress::permits`] for every probe — that agreement
/// is the cross-projection witness.
pub fn wasi_allows(egress: &WasiEgress, proto: &Proto, ip_addr: IpAddr, port: u16) -> bool {
    if is_mandatory_deny(ip_addr) {
        return false;
    }
    match egress {
        WasiEgress::Unrestricted => true,
        WasiEgress::Grants(grants) => grants.iter().any(|g| {
            g.proto == *proto
                && g.port_lo <= port
                && port <= g.port_hi
                && match &g.target {
                    WasiTarget::PinnedHost { ips, .. } => ips.contains(&ip_addr),
                    WasiTarget::Net(net) => net.contains(&ip_addr),
                }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use crate::policy::policies::L4RuleSpec;
    use crate::policy::resolver::EffectivePolicy;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }

    const NOW: &str = "2026-06-11T00:00:00Z";

    fn l4(proto: &str, cidr: &str, lo: u16, hi: u16) -> L4RuleSpec {
        L4RuleSpec {
            proto: proto.to_string(),
            dst_cidr: cidr.to_string(),
            port_lo: lo,
            port_hi: hi,
        }
    }

    fn eff_with_l4(rules: Vec<L4RuleSpec>) -> EffectivePolicy {
        let mut eff = EffectivePolicy::default();
        eff.network.l4 = rules;
        eff
    }

    #[test]
    fn canonicalize_default_policy_is_deny_all() {
        let eff = EffectivePolicy::default();
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert_eq!(eg, CanonicalEgress::Rules(vec![]));
    }

    #[test]
    fn canonicalize_open_mode_is_unrestricted() {
        let mut eff = EffectivePolicy::default();
        eff.egress.mode = Some("open".to_string());
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert_eq!(eg, CanonicalEgress::Unrestricted);
    }

    #[test]
    fn canonicalize_lowers_l4_rules_verbatim() {
        let eff = eff_with_l4(vec![l4("tcp", "93.184.216.0/24", 443, 443)]);
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 80));
    }

    #[test]
    fn canonicalize_normalizes_any_port_wildcard() {
        // (0, 0) is the wire-format any-port wildcard.
        let eff = eff_with_l4(vec![l4("udp", "8.8.8.8/32", 0, 0)]);
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(eg.permits(&Proto::Udp, ip("8.8.8.8"), 53));
        assert!(eg.permits(&Proto::Udp, ip("8.8.8.8"), 65535));
    }

    #[test]
    fn canonicalize_refuses_unparseable_cidr() {
        let eff = eff_with_l4(vec![l4("tcp", "not-a-cidr", 443, 443)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::BadCidr { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn canonicalize_refuses_unknown_proto() {
        let eff = eff_with_l4(vec![l4("icmp", "8.8.8.8/32", 0, 0)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::UnknownProto { .. }),
            "got {err:?}"
        );
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

    // ─────────────────────────────────────────────────
    // allow-list via DNS pin registry
    // ─────────────────────────────────────────────────

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

    fn eff_with_allow(list: Vec<(&str, u16)>) -> EffectivePolicy {
        let mut eff = EffectivePolicy::default();
        eff.egress.allow_list = list.into_iter().map(|(h, p)| (h.to_string(), p)).collect();
        eff
    }

    #[test]
    fn allow_list_host_lowers_to_pinned_host_nets() {
        let eff = eff_with_allow(vec![("api.example.com", 443)]);
        let pins = registry(vec![pin(
            "api.example.com",
            &["93.184.216.34", "93.184.216.35"],
        )]);
        let eg = canonicalize_effective(&eff, &pins, NOW).unwrap();
        // Both pinned addresses admitted, TCP, exactly port 443.
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.35"), 443));
        // An unpinned address of the "same host" is NOT admitted —
        // the projection enforces pins, not live DNS.
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.36"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 80));
        assert!(!eg.permits(&Proto::Udp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn allow_list_port_zero_is_any_port() {
        let eff = eff_with_allow(vec![("api.example.com", 0)]);
        let pins = registry(vec![pin("api.example.com", &["93.184.216.34"])]);
        let eg = canonicalize_effective(&eff, &pins, NOW).unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 8080));
    }

    #[test]
    fn allow_list_ipv6_pin_lowers_to_slash128() {
        let eff = eff_with_allow(vec![("v6.example.com", 443)]);
        let pins = registry(vec![pin("v6.example.com", &["2001:db8::42"])]);
        let eg = canonicalize_effective(&eff, &pins, NOW).unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("2001:db8::42"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("2001:db8::43"), 443));
    }

    #[test]
    fn allow_list_host_without_pin_refuses() {
        let eff = eff_with_allow(vec![("unpinned.example.com", 443)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::MissingPin { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn allow_list_expired_pin_refuses() {
        let eff = eff_with_allow(vec![("stale.example.com", 443)]);
        let stale = DnsPin::at(
            "stale.example.com",
            vec![ip("93.184.216.34")],
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z", // expired before NOW
        );
        let err = canonicalize_effective(&eff, &registry(vec![stale]), NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::ExpiredPin { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn allow_list_empty_pin_set_refuses() {
        let eff = eff_with_allow(vec![("empty.example.com", 443)]);
        let pins = registry(vec![pin("empty.example.com", &[])]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::EmptyPin { .. }),
            "got {err:?}"
        );
    }

    // ─────────────────────────────────────────────────
    // mandatory-deny overlap refusals
    // ─────────────────────────────────────────────────

    #[test]
    fn l4_rule_overlapping_mandatory_deny_refuses() {
        for cidr in [
            "169.254.0.0/16",
            "169.254.169.254/32",
            "127.0.0.0/8",
            "100.64.0.0/10",
        ] {
            let eff = eff_with_l4(vec![l4("tcp", cidr, 0, 0)]);
            let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
            assert!(
                matches!(err, ProjectionError::MandatoryDenyOverlap { .. }),
                "{cidr}: got {err:?}"
            );
        }
    }

    #[test]
    fn l4_supernet_of_mandatory_deny_refuses() {
        // A /0 covers every deny range — refuse, don't carve.
        let eff = eff_with_l4(vec![l4("tcp", "0.0.0.0/0", 443, 443)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::MandatoryDenyOverlap { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rebinding_pin_into_metadata_range_refuses() {
        // A policy-permitted host whose admission-time resolution
        // lands in the cloud metadata range is a refusal, not a pin.
        let eff = eff_with_allow(vec![("rebind.example.com", 443)]);
        let pins = registry(vec![pin("rebind.example.com", &["169.254.169.254"])]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::MandatoryDenyOverlap { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rebinding_pin_into_loopback_v6_refuses() {
        let eff = eff_with_allow(vec![("rebind6.example.com", 443)]);
        let pins = registry(vec![pin("rebind6.example.com", &["::1"])]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::MandatoryDenyOverlap { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn mixed_pin_one_bad_ip_refuses_whole_projection() {
        // One good IP + one metadata IP: fail-closed on the whole
        // projection, no partial admit.
        let eff = eff_with_allow(vec![("mixed.example.com", 443)]);
        let pins = registry(vec![pin(
            "mixed.example.com",
            &["93.184.216.34", "169.254.169.254"],
        )]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(
            matches!(err, ProjectionError::MandatoryDenyOverlap { .. }),
            "got {err:?}"
        );
    }

    // ─────────────────────────────────────────────────
    // WASI-facing projection
    // ─────────────────────────────────────────────────

    #[test]
    fn wasi_projection_default_policy_denies_everything() {
        let eff = EffectivePolicy::default();
        let w = to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn wasi_projection_pinned_host_allows_only_pinned_ips() {
        let eff = eff_with_allow(vec![("api.example.com", 443)]);
        let pins = registry(vec![pin("api.example.com", &["93.184.216.34"])]);
        let w = to_wasi_grants(&eff, &pins, NOW).unwrap();
        assert!(wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("93.184.216.35"), 443));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 80));
    }

    #[test]
    fn wasi_projection_l4_net_target() {
        let eff = eff_with_l4(vec![l4("udp", "8.8.8.0/24", 53, 53)]);
        let w = to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(wasi_allows(&w, &Proto::Udp, ip("8.8.8.8"), 53));
        assert!(!wasi_allows(&w, &Proto::Udp, ip("8.8.9.8"), 53));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("8.8.8.8"), 53));
    }

    #[test]
    fn wasi_projection_mandatory_deny_unconditional() {
        let mut eff = EffectivePolicy::default();
        eff.egress.mode = Some("open".to_string());
        let w = to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(matches!(w, WasiEgress::Unrestricted));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("169.254.169.254"), 443));
        assert!(wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn wasi_projection_refuses_same_inputs_canonical_refuses() {
        // Shared refusal ladder: missing pin and rebinding pin
        // refuse here exactly as in the canonical walk.
        let eff = eff_with_allow(vec![("unpinned.example.com", 443)]);
        assert!(matches!(
            to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap_err(),
            ProjectionError::MissingPin { .. }
        ));
        let eff = eff_with_allow(vec![("rebind.example.com", 443)]);
        let pins = registry(vec![pin("rebind.example.com", &["169.254.169.254"])]);
        assert!(matches!(
            to_wasi_grants(&eff, &pins, NOW).unwrap_err(),
            ProjectionError::MandatoryDenyOverlap { .. }
        ));
    }

    // ─────────────────────────────────────────────────
    // clamp — intersection-only merge
    // ─────────────────────────────────────────────────

    fn rule(proto: Proto, cidr: &str, lo: u16, hi: u16) -> CanonicalRule {
        CanonicalRule {
            proto,
            net: net(cidr),
            port_lo: lo,
            port_hi: hi,
        }
    }

    #[test]
    fn clamp_request_wider_than_resolved_yields_intersection() {
        // A requested grant can attenuate the resolved one, never
        // widen it.
        let requested = CanonicalEgress::Rules(vec![
            rule(Proto::Tcp, "93.184.216.34/32", 443, 443), // covered → kept
            rule(Proto::Tcp, "203.0.113.0/24", 0, 65535),   // not granted → dropped
        ]);
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.0/24", 443, 443)]);
        let granted = clamp(&requested, &resolved);
        assert!(granted.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!granted.permits(&Proto::Tcp, ip("203.0.113.7"), 443));
    }

    #[test]
    fn clamp_unrestricted_request_cannot_widen() {
        let requested = CanonicalEgress::Unrestricted;
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 443, 443)]);
        let granted = clamp(&requested, &resolved);
        assert_eq!(granted, resolved);
    }

    #[test]
    fn clamp_request_can_attenuate_unrestricted() {
        let requested =
            CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 443, 443)]);
        let resolved = CanonicalEgress::Unrestricted;
        let granted = clamp(&requested, &resolved);
        assert_eq!(granted, requested);
    }

    #[test]
    fn clamp_partial_port_overlap_drops_fail_closed() {
        // Conservative intersection: a requested rule only
        // partially covered by the resolved grant is dropped
        // whole, not split.
        let requested =
            CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 80, 8080)]);
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 443, 443)]);
        let granted = clamp(&requested, &resolved);
        assert_eq!(granted, CanonicalEgress::Rules(vec![]));
    }

    #[test]
    fn clamp_is_never_wider_than_resolved_pointwise() {
        let requested = CanonicalEgress::Rules(vec![
            rule(Proto::Tcp, "10.0.0.0/8", 0, 65535),
            rule(Proto::Udp, "8.8.8.8/32", 53, 53),
        ]);
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Udp, "8.8.8.0/24", 53, 53)]);
        let granted = clamp(&requested, &resolved);
        for (proto, addr, port) in [
            (Proto::Tcp, "10.1.2.3", 443u16),
            (Proto::Udp, "8.8.8.8", 53),
            (Proto::Udp, "8.8.8.9", 53),
        ] {
            if granted.permits(&proto, ip(addr), port) {
                assert!(
                    resolved.permits(&proto, ip(addr), port),
                    "clamp widened: {proto:?} {addr}:{port}"
                );
            }
        }
        // And the covered request survives.
        assert!(granted.permits(&Proto::Udp, ip("8.8.8.8"), 53));
    }
}

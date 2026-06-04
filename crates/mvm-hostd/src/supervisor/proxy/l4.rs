//! Plan 60 Phase 3 Slice B — L4 egress policy substrate.
//!
//! `(proto, dst_cidr, dst_port_range)` allow-list evaluated against
//! `(proto, dst_ip, dst_port)` at flow-establishment time. Default-
//! deny — an empty rule set refuses every outbound flow. Each
//! evaluation produces an [`L4Decision`] that the eventual TUN /
//! smoltcp consumer feeds into its `accept` / `drop + audit`
//! branches.
//!
//! ## Scope of this module
//!
//! - **Policy only.** Pure evaluation; no networking I/O.
//! - **Both IPv4 and IPv6** supported via `ipnet::IpNet`.
//! - **TCP and UDP** supported via [`Protocol`]; ICMP and others
//!   land when a workload needs them (`Other(u8)` is reserved on
//!   the wire).
//! - **Hot-path** — the consumer will call `evaluate` once per
//!   flow attempt, so the implementation uses an O(rules) scan
//!   sorted by specificity-leaning order. For typical workload
//!   allow-lists (<50 entries) this is faster than a trie.
//!
//! ## What this module does NOT do
//!
//! - **No TUN device management.** The Linux TUN + smoltcp
//!   integration that turns an `L4Policy::evaluate` decision into
//!   accept/drop on a per-VM TAP lives in the per-tenant
//!   network-namespace work (Phase 3 Slice C / mvm-hostd lift).
//! - **No audit emission.** The consumer wires
//!   `EgressAuditSink::record` with the flow tuple + decision.
//!   This module returns the decision; the *what to do with it*
//!   is the consumer's concern.
//! - **No firewall rules.** Linux nftables / macOS pf / Windows
//!   WFP rules are Slice C — the firewall is additive enforcement
//!   beneath the proxy, not the proxy itself.

use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// L4 protocols the egress policy understands today.
///
/// `Other(u8)` is the wire-format escape hatch for IP protocols the
/// policy doesn't yet have a named variant for (ICMP = 1, IGMP = 2,
/// etc.). The `evaluate` path never matches `Other` — adding a new
/// named protocol is the supported way to extend coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Tcp,
    Udp,
    /// Reserved wire-format escape. Never matched by `evaluate`.
    Other(u8),
}

/// The verdict for a single `(proto, dst_ip, dst_port)` lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Decision {
    /// Some rule matched and permits the flow.
    Allow,
    /// No rule matched; default-deny fired. The `reason` carries a
    /// human-readable explanation suitable for the audit sink and
    /// for the operator's `mvmctl audit tail` output.
    Deny { reason: String },
}

/// One row of the allow-list. Matches when ALL three components
/// match: proto equals, dst_ip is within `dst_cidr`, and port falls
/// in the inclusive `[port_lo, port_hi]` range.
///
/// `port_lo = 0 && port_hi = 0` is the "any port" wildcard for the
/// protocol+cidr pair (matches both well-known and ephemeral
/// ports). Otherwise `port_lo <= port <= port_hi` is the standard
/// range check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4Rule {
    pub proto: Protocol,
    pub dst_cidr: IpNet,
    /// Inclusive low bound of the destination port range.
    pub port_lo: u16,
    /// Inclusive high bound. `port_lo == 0 && port_hi == 0` means
    /// "any port for this (proto, cidr)".
    pub port_hi: u16,
}

impl L4Rule {
    /// Build a single-port rule. The most common shape; convenience
    /// over the `port_lo`/`port_hi` field literals.
    pub fn single_port(proto: Protocol, dst_cidr: IpNet, port: u16) -> Self {
        Self {
            proto,
            dst_cidr,
            port_lo: port,
            port_hi: port,
        }
    }

    /// Build an any-port rule. Useful for DNS over UDP where the
    /// destination is a specific resolver but the source port is
    /// ephemeral on both sides.
    pub fn any_port(proto: Protocol, dst_cidr: IpNet) -> Self {
        Self {
            proto,
            dst_cidr,
            port_lo: 0,
            port_hi: 0,
        }
    }

    /// Check whether this rule matches a `(proto, ip, port)` flow.
    pub fn matches(&self, proto: Protocol, ip: IpAddr, port: u16) -> bool {
        if self.proto != proto {
            return false;
        }
        if !self.dst_cidr.contains(&ip) {
            return false;
        }
        if self.port_lo == 0 && self.port_hi == 0 {
            return true;
        }
        self.port_lo <= port && port <= self.port_hi
    }
}

/// Ordered allow-list. Default-deny when empty or when no rule
/// matches the queried flow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4Policy {
    pub rules: Vec<L4Rule>,
}

impl L4Policy {
    pub fn new(rules: impl IntoIterator<Item = L4Rule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
        }
    }

    /// Default-deny sentinel. Useful as the resolver's fall-back
    /// when no policy bundle is provisioned (matches the "fail
    /// closed" framing in ADR-002).
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Evaluate `(proto, ip, port)` against the rule list. The
    /// first matching rule wins (rules earlier in the list take
    /// precedence; callers concerned about determinism should
    /// pre-sort).
    pub fn evaluate(&self, proto: Protocol, ip: IpAddr, port: u16) -> L4Decision {
        if self.rules.iter().any(|r| r.matches(proto, ip, port)) {
            return L4Decision::Allow;
        }
        L4Decision::Deny {
            reason: format!(
                "no L4 rule matched {proto:?} {ip}:{port} (default deny — \
                 add a rule to the policy bundle's [network] section)"
            ),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// L4Gate — supervisor slot consumed by the W5 policy resolver.
//
// Symmetric with `EgressProxy` (L7) / `ToolGate` / `KeystoreReleaser` /
// `ArtifactCollector`: a `Box<dyn L4Gate>` slot the supervisor consults
// at admission. Slice B wires `LiveL4Gate { policy: L4Policy }` from
// a parsed bundle's `[[network.l4]]` rows; the smoltcp / TUN consumer
// that turns an `Allow` into accept-the-connection ships with Slice C.
// ──────────────────────────────────────────────────────────────────────

/// Errors `L4Gate::evaluate` can return. `NotWired` is the
/// fail-closed default emitted by `NoopL4Gate`; the live impl returns
/// the wrapped decision via `Ok`, including `Deny` for default-deny
/// hits.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum L4Error {
    /// Supervisor slot is the Noop — admission ran without a policy
    /// bundle behind it. Surface to the operator with the same message
    /// shape as `EgressError::NotWired`.
    #[error("L4 gate not wired (Noop slot)")]
    NotWired,
}

/// Trait object the supervisor's `with_l4_gate` builder consumes.
/// Async-shaped for symmetry with the other gates; today's impls
/// never .await, but future extensions (e.g., per-tenant DNS-derived
/// allow-lists) plausibly will.
#[async_trait]
pub trait L4Gate: Send + Sync {
    async fn evaluate(&self, proto: Protocol, ip: IpAddr, port: u16)
    -> Result<L4Decision, L4Error>;
}

/// Fail-closed default. A supervisor wired with `NoopL4Gate` errors
/// `NotWired` on every flow attempt. Identical posture to
/// `NoopEgressProxy` — a misconfigured deployment fails loud on first
/// consult instead of silently passing traffic.
#[derive(Debug, Default)]
pub struct NoopL4Gate;

#[async_trait]
impl L4Gate for NoopL4Gate {
    async fn evaluate(
        &self,
        _proto: Protocol,
        _ip: IpAddr,
        _port: u16,
    ) -> Result<L4Decision, L4Error> {
        Err(L4Error::NotWired)
    }
}

/// Live impl backed by a concrete `L4Policy`. Plan 60 Phase 3 Slice B
/// constructs this from a parsed policy bundle's `[[network.l4]]`
/// rows via [`LiveL4Gate::from_specs`].
#[derive(Debug, Default)]
pub struct LiveL4Gate {
    pub policy: L4Policy,
}

impl LiveL4Gate {
    pub fn new(policy: L4Policy) -> Self {
        Self { policy }
    }

    /// Translate a slice of `mvm_core::policy::L4RuleSpec` rows into a
    /// `LiveL4Gate`. Refuses unparseable CIDRs and unknown protocols
    /// at *translate* time — the operator sees a loud admission
    /// failure rather than a silent default-deny at runtime.
    pub fn from_specs(specs: &[mvm_core::policy::L4RuleSpec]) -> Result<Self, L4SpecError> {
        let mut rules = Vec::with_capacity(specs.len());
        for (i, spec) in specs.iter().enumerate() {
            let proto = match spec.proto.as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                other => {
                    return Err(L4SpecError::UnknownProtocol {
                        index: i,
                        value: other.to_string(),
                    });
                }
            };
            let dst_cidr: IpNet =
                spec.dst_cidr
                    .parse()
                    .map_err(|e: ipnet::AddrParseError| L4SpecError::BadCidr {
                        index: i,
                        value: spec.dst_cidr.clone(),
                        detail: e.to_string(),
                    })?;
            if spec.port_lo > spec.port_hi
                // 0-0 is the explicit any-port wildcard; any other
                // `lo > hi` row is operator error.
                && !(spec.port_lo == 0 && spec.port_hi == 0)
            {
                return Err(L4SpecError::InvertedPortRange {
                    index: i,
                    port_lo: spec.port_lo,
                    port_hi: spec.port_hi,
                });
            }
            rules.push(L4Rule {
                proto,
                dst_cidr,
                port_lo: spec.port_lo,
                port_hi: spec.port_hi,
            });
        }
        Ok(Self::new(L4Policy::new(rules)))
    }
}

#[async_trait]
impl L4Gate for LiveL4Gate {
    async fn evaluate(
        &self,
        proto: Protocol,
        ip: IpAddr,
        port: u16,
    ) -> Result<L4Decision, L4Error> {
        Ok(self.policy.evaluate(proto, ip, port))
    }
}

/// Translation errors from [`LiveL4Gate::from_specs`]. Each variant
/// names the bundle row index so operators can fix the offending
/// `[[network.l4]]` entry by `index = N` (zero-based).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum L4SpecError {
    #[error("L4 rule #{index}: unknown proto {value:?} (expected \"tcp\" or \"udp\")")]
    UnknownProtocol { index: usize, value: String },

    #[error("L4 rule #{index}: dst_cidr {value:?} doesn't parse as a CIDR: {detail}")]
    BadCidr {
        index: usize,
        value: String,
        detail: String,
    },

    #[error(
        "L4 rule #{index}: inverted port range port_lo={port_lo} > port_hi={port_hi} \
         (use port_lo == 0 && port_hi == 0 for an any-port wildcard)"
    )]
    InvertedPortRange {
        index: usize,
        port_lo: u16,
        port_hi: u16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(cidr: &str) -> IpNet {
        cidr.parse().unwrap()
    }

    fn v6(cidr: &str) -> IpNet {
        cidr.parse().unwrap()
    }

    fn ip4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn ip6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    // ──────────────────────────────────────────────────────────────
    // Default-deny invariants
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn empty_policy_denies_every_flow() {
        let p = L4Policy::deny_all();
        let deny = p.evaluate(Protocol::Tcp, ip4("8.8.8.8"), 443);
        assert!(
            matches!(deny, L4Decision::Deny { .. }),
            "empty policy must deny, got {deny:?}"
        );
    }

    #[test]
    fn default_deny_reason_names_proto_ip_port() {
        let p = L4Policy::deny_all();
        let deny = p.evaluate(Protocol::Udp, ip4("1.1.1.1"), 53);
        match deny {
            L4Decision::Deny { reason } => {
                assert!(reason.contains("Udp"), "reason missing proto: {reason}");
                assert!(reason.contains("1.1.1.1"), "reason missing ip: {reason}");
                assert!(reason.contains("53"), "reason missing port: {reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Allow paths
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn single_port_rule_matches_exact_flow() {
        let p = L4Policy::new([L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443)]);
        assert_eq!(
            p.evaluate(Protocol::Tcp, ip4("10.0.0.5"), 443),
            L4Decision::Allow
        );
    }

    #[test]
    fn single_port_rule_denies_off_cidr() {
        let p = L4Policy::new([L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443)]);
        let deny = p.evaluate(Protocol::Tcp, ip4("10.0.1.5"), 443);
        assert!(matches!(deny, L4Decision::Deny { .. }));
    }

    #[test]
    fn single_port_rule_denies_wrong_port() {
        let p = L4Policy::new([L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443)]);
        let deny = p.evaluate(Protocol::Tcp, ip4("10.0.0.5"), 22);
        assert!(matches!(deny, L4Decision::Deny { .. }));
    }

    #[test]
    fn single_port_rule_denies_wrong_proto() {
        let p = L4Policy::new([L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443)]);
        let deny = p.evaluate(Protocol::Udp, ip4("10.0.0.5"), 443);
        assert!(matches!(deny, L4Decision::Deny { .. }));
    }

    #[test]
    fn any_port_rule_matches_every_port() {
        let p = L4Policy::new([L4Rule::any_port(Protocol::Udp, v4("8.8.8.8/32"))]);
        assert_eq!(
            p.evaluate(Protocol::Udp, ip4("8.8.8.8"), 53),
            L4Decision::Allow
        );
        assert_eq!(
            p.evaluate(Protocol::Udp, ip4("8.8.8.8"), 12345),
            L4Decision::Allow
        );
        // Wrong proto still denies.
        assert!(matches!(
            p.evaluate(Protocol::Tcp, ip4("8.8.8.8"), 53),
            L4Decision::Deny { .. }
        ));
    }

    #[test]
    fn port_range_rule_includes_endpoints() {
        let p = L4Policy::new([L4Rule {
            proto: Protocol::Tcp,
            dst_cidr: v4("0.0.0.0/0"),
            port_lo: 8000,
            port_hi: 8010,
        }]);
        assert_eq!(
            p.evaluate(Protocol::Tcp, ip4("1.2.3.4"), 8000),
            L4Decision::Allow
        );
        assert_eq!(
            p.evaluate(Protocol::Tcp, ip4("1.2.3.4"), 8005),
            L4Decision::Allow
        );
        assert_eq!(
            p.evaluate(Protocol::Tcp, ip4("1.2.3.4"), 8010),
            L4Decision::Allow
        );
        assert!(matches!(
            p.evaluate(Protocol::Tcp, ip4("1.2.3.4"), 7999),
            L4Decision::Deny { .. }
        ));
        assert!(matches!(
            p.evaluate(Protocol::Tcp, ip4("1.2.3.4"), 8011),
            L4Decision::Deny { .. }
        ));
    }

    #[test]
    fn first_match_wins() {
        // Two rules covering the same flow — the earlier one should
        // produce Allow even if a later one would have matched
        // differently. We can't observe ordering through Allow vs
        // Deny here, but we can confirm Allow is reached.
        let p = L4Policy::new([
            L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/8"), 443),
            L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443),
        ]);
        assert_eq!(
            p.evaluate(Protocol::Tcp, ip4("10.0.0.5"), 443),
            L4Decision::Allow
        );
    }

    #[test]
    fn ipv6_cidr_matches() {
        let p = L4Policy::new([L4Rule::single_port(
            Protocol::Tcp,
            v6("2606:4700::/32"),
            443,
        )]);
        assert_eq!(
            p.evaluate(Protocol::Tcp, ip6("2606:4700:4700::1111"), 443),
            L4Decision::Allow
        );
        assert!(matches!(
            p.evaluate(Protocol::Tcp, ip6("2001:db8::1"), 443),
            L4Decision::Deny { .. }
        ));
    }

    #[test]
    fn v4_rule_does_not_match_v6_addr() {
        let p = L4Policy::new([L4Rule::single_port(Protocol::Tcp, v4("0.0.0.0/0"), 443)]);
        // A v4 0.0.0.0/0 rule is sometimes mistakenly assumed to
        // cover v6 too; ipnet correctly treats them as separate
        // address families.
        assert!(matches!(
            p.evaluate(Protocol::Tcp, ip6("2001:db8::1"), 443),
            L4Decision::Deny { .. }
        ));
    }

    // ──────────────────────────────────────────────────────────────
    // Serialization (the eventual TOML policy-bundle consumer)
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn policy_round_trips_through_json() {
        let original = L4Policy::new([
            L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443),
            L4Rule::any_port(Protocol::Udp, v4("8.8.8.8/32")),
        ]);
        let json = serde_json::to_string(&original).unwrap();
        let round: L4Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(round.rules.len(), 2);
        assert_eq!(round.rules[0].port_lo, 443);
        assert_eq!(round.rules[0].port_hi, 443);
        assert_eq!(round.rules[1].port_lo, 0);
        assert_eq!(round.rules[1].port_hi, 0);
    }

    #[test]
    fn protocol_kebab_case_serializes_as_lowercase() {
        let json = serde_json::to_string(&Protocol::Tcp).unwrap();
        assert_eq!(json, "\"tcp\"");
        let parsed: Protocol = serde_json::from_str("\"udp\"").unwrap();
        assert_eq!(parsed, Protocol::Udp);
    }

    #[test]
    fn rule_rejects_unknown_field_at_parse() {
        // deny_unknown_fields on L4Rule — typo at parse time fails
        // loud, doesn't silently drop the bad key.
        let bad =
            r#"{"proto":"tcp","dst_cidr":"10.0.0.0/24","port_lo":443,"port_hi":443,"oops":true}"#;
        assert!(serde_json::from_str::<L4Rule>(bad).is_err());
    }

    // ──────────────────────────────────────────────────────────────
    // L4Gate trait — supervisor slot
    // ──────────────────────────────────────────────────────────────

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn noop_l4_gate_errors_not_wired_on_every_flow() {
        let g = NoopL4Gate;
        let err = block_on(g.evaluate(Protocol::Tcp, ip4("8.8.8.8"), 443)).expect_err("noop");
        assert_eq!(err, L4Error::NotWired);
    }

    #[test]
    fn live_l4_gate_allows_matching_flow() {
        let policy = L4Policy::new([L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443)]);
        let g = LiveL4Gate::new(policy);
        let d = block_on(g.evaluate(Protocol::Tcp, ip4("10.0.0.5"), 443)).expect("live ok");
        assert_eq!(d, L4Decision::Allow);
    }

    #[test]
    fn live_l4_gate_denies_off_policy_flow() {
        let policy = L4Policy::new([L4Rule::single_port(Protocol::Tcp, v4("10.0.0.0/24"), 443)]);
        let g = LiveL4Gate::new(policy);
        let d = block_on(g.evaluate(Protocol::Tcp, ip4("8.8.8.8"), 443)).expect("live ok");
        assert!(matches!(d, L4Decision::Deny { .. }));
    }

    // ──────────────────────────────────────────────────────────────
    // LiveL4Gate::from_specs — bundle spec → live gate translation
    // ──────────────────────────────────────────────────────────────

    fn spec(proto: &str, cidr: &str, port_lo: u16, port_hi: u16) -> mvm_core::policy::L4RuleSpec {
        mvm_core::policy::L4RuleSpec {
            proto: proto.to_string(),
            dst_cidr: cidr.to_string(),
            port_lo,
            port_hi,
        }
    }

    #[test]
    fn from_specs_translates_tcp_and_udp_rows() {
        let specs = [
            spec("tcp", "10.0.0.0/24", 443, 443),
            spec("udp", "8.8.8.8/32", 0, 0),
        ];
        let g = LiveL4Gate::from_specs(&specs).expect("translate");
        assert_eq!(g.policy.rules.len(), 2);
        assert_eq!(g.policy.rules[0].proto, Protocol::Tcp);
        assert_eq!(g.policy.rules[1].proto, Protocol::Udp);
    }

    #[test]
    fn from_specs_refuses_unknown_protocol() {
        let specs = [spec("icmp", "10.0.0.0/24", 0, 0)];
        let err = LiveL4Gate::from_specs(&specs).expect_err("unknown proto");
        match err {
            L4SpecError::UnknownProtocol { index, value } => {
                assert_eq!(index, 0);
                assert_eq!(value, "icmp");
            }
            other => panic!("expected UnknownProtocol, got {other:?}"),
        }
    }

    #[test]
    fn from_specs_refuses_bad_cidr() {
        let specs = [spec("tcp", "not-a-cidr", 443, 443)];
        let err = LiveL4Gate::from_specs(&specs).expect_err("bad cidr");
        match err {
            L4SpecError::BadCidr { index, value, .. } => {
                assert_eq!(index, 0);
                assert_eq!(value, "not-a-cidr");
            }
            other => panic!("expected BadCidr, got {other:?}"),
        }
    }

    #[test]
    fn from_specs_refuses_inverted_port_range() {
        let specs = [spec("tcp", "10.0.0.0/24", 500, 400)];
        let err = LiveL4Gate::from_specs(&specs).expect_err("inverted");
        match err {
            L4SpecError::InvertedPortRange {
                index,
                port_lo,
                port_hi,
            } => {
                assert_eq!(index, 0);
                assert_eq!(port_lo, 500);
                assert_eq!(port_hi, 400);
            }
            other => panic!("expected InvertedPortRange, got {other:?}"),
        }
    }

    #[test]
    fn from_specs_accepts_any_port_wildcard_zero_zero() {
        // The `port_lo == 0 && port_hi == 0` wildcard is the supported
        // shape — `from_specs` must not flag it as inverted.
        let specs = [spec("udp", "8.8.8.8/32", 0, 0)];
        let g = LiveL4Gate::from_specs(&specs).expect("zero-zero wildcard");
        assert_eq!(g.policy.rules.len(), 1);
        // Sanity-evaluate: any UDP port to that /32 should Allow.
        let d = block_on(g.evaluate(Protocol::Udp, ip4("8.8.8.8"), 53)).unwrap();
        assert_eq!(d, L4Decision::Allow);
    }

    #[test]
    fn from_specs_empty_input_yields_default_deny_gate() {
        let g = LiveL4Gate::from_specs(&[]).expect("empty ok");
        assert!(g.policy.rules.is_empty());
        // Every evaluate call on an empty gate should be Deny.
        let d = block_on(g.evaluate(Protocol::Tcp, ip4("1.1.1.1"), 443)).unwrap();
        assert!(matches!(d, L4Decision::Deny { .. }));
    }
}

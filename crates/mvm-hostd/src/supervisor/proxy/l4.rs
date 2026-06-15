//! L4 egress gate — supervisor `network` slot.
//!
//! The *decision* is now owned by `CanonicalEgress::permits` in
//! `mvm-core::policy::projection`. This module holds only the async
//! `L4Gate` trait (the supervisor slot boundary), the `NoopL4Gate`
//! fail-closed default, and `CanonicalL4Gate` — the live impl that
//! delegates every decision to `CanonicalEgress::permits`.
//!
//! ## Scope of this module
//!
//! - **Gate interface only.** `L4Gate::evaluate` is the async slot the
//!   supervisor's builder pattern wires; callers hold `Box<dyn L4Gate>`.
//! - **No policy evaluation logic here.** Rule lookup, CIDR matching, and
//!   mandatory-deny enforcement live in `mvm_core::policy::projection`.
//! - **Both IPv4 and IPv6** are handled by `CanonicalEgress::permits` via
//!   `ipnet::IpNet::contains`.
//! - **TCP and UDP** are the named variants; anything else (ICMP, `Other`)
//!   never matches `CanonicalRule::permits` and therefore denies.

use std::net::IpAddr;

use async_trait::async_trait;
use mvm_core::policy::projection::{CanonicalEgress, Proto};
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

// ──────────────────────────────────────────────────────────────────────
// L4Gate — supervisor slot consumed by the policy resolver.
//
// Symmetric with `SupervisorEgressProxy` (L7) / `ToolGate` / `KeystoreReleaser` /
// `ArtifactCollector`: a `Box<dyn L4Gate>` slot the supervisor consults
// at admission. `CanonicalL4Gate` is wired from a parsed bundle's
// `[[network.l4]]` rows; the smoltcp / TUN consumer that turns an
// `Allow` into accept-the-connection ships separately.
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

/// Live impl backed by a `CanonicalEgress`. Constructed from a parsed
/// bundle's `[[network.l4]]` rows via `mvm_core::policy::canonicalize_l4`.
///
/// Decision delegates entirely to `CanonicalEgress::permits` —
/// the single decision function shared by every enforcement layer.
/// `Protocol::Other` never maps to a named `Proto`, so it always denies.
#[derive(Debug)]
pub struct CanonicalL4Gate {
    egress: CanonicalEgress,
}

impl CanonicalL4Gate {
    pub fn new(egress: CanonicalEgress) -> Self {
        Self { egress }
    }
}

#[async_trait]
impl L4Gate for CanonicalL4Gate {
    async fn evaluate(
        &self,
        proto: Protocol,
        ip: IpAddr,
        port: u16,
    ) -> Result<L4Decision, L4Error> {
        let canon_proto = match proto {
            Protocol::Tcp => Proto::Tcp,
            Protocol::Udp => Proto::Udp,
            Protocol::Other(n) => {
                return Ok(L4Decision::Deny {
                    reason: format!("no L4 rule matched proto={n} {ip}:{port} (default deny)"),
                });
            }
        };
        if self.egress.permits(&canon_proto, ip, port) {
            Ok(L4Decision::Allow)
        } else {
            Ok(L4Decision::Deny {
                reason: format!(
                    "no L4 rule matched {proto:?} {ip}:{port} (default deny — \
                     add a rule to the policy bundle's [network] section)"
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::projection::{CanonicalRule, Proto};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn ip6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    fn rule(proto: Proto, cidr: &str, lo: u16, hi: u16) -> CanonicalRule {
        CanonicalRule {
            proto,
            net: cidr.parse().unwrap(),
            port_lo: lo,
            port_hi: hi,
        }
    }

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
    fn canonical_l4_gate_allows_matching_flow() {
        let egress = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "10.0.0.0/24", 443, 443)]);
        let g = CanonicalL4Gate::new(egress);
        let d = block_on(g.evaluate(Protocol::Tcp, ip4("10.0.0.5"), 443)).expect("live ok");
        assert_eq!(d, L4Decision::Allow);
    }

    #[test]
    fn canonical_l4_gate_denies_off_policy_flow() {
        let egress = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "10.0.0.0/24", 443, 443)]);
        let g = CanonicalL4Gate::new(egress);
        let d = block_on(g.evaluate(Protocol::Tcp, ip4("8.8.8.8"), 443)).expect("live ok");
        assert!(matches!(d, L4Decision::Deny { .. }));
    }

    #[test]
    fn canonical_l4_gate_denies_other_proto() {
        let egress = CanonicalEgress::Unrestricted;
        let g = CanonicalL4Gate::new(egress);
        let d = block_on(g.evaluate(Protocol::Other(1), ip4("1.1.1.1"), 0)).expect("other");
        assert!(matches!(d, L4Decision::Deny { .. }));
    }

    #[test]
    fn canonical_l4_gate_empty_rules_denies_everything() {
        let egress = CanonicalEgress::Rules(vec![]);
        let g = CanonicalL4Gate::new(egress);
        let d = block_on(g.evaluate(Protocol::Tcp, ip4("8.8.8.8"), 443)).expect("ok");
        assert!(matches!(d, L4Decision::Deny { .. }));
    }

    #[test]
    fn canonical_l4_gate_unrestricted_allows_tcp_and_udp() {
        let egress = CanonicalEgress::Unrestricted;
        let g = CanonicalL4Gate::new(egress);
        assert_eq!(
            block_on(g.evaluate(Protocol::Tcp, ip4("8.8.8.8"), 443)).unwrap(),
            L4Decision::Allow
        );
        assert_eq!(
            block_on(g.evaluate(Protocol::Udp, ip4("8.8.8.8"), 53)).unwrap(),
            L4Decision::Allow
        );
    }

    #[test]
    fn canonical_l4_gate_ipv6_rule_matches() {
        let egress = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "2606:4700::/32", 443, 443)]);
        let g = CanonicalL4Gate::new(egress);
        assert_eq!(
            block_on(g.evaluate(Protocol::Tcp, ip6("2606:4700:4700::1111"), 443)).unwrap(),
            L4Decision::Allow
        );
        assert!(matches!(
            block_on(g.evaluate(Protocol::Tcp, ip6("2001:db8::1"), 443)).unwrap(),
            L4Decision::Deny { .. }
        ));
    }

    #[test]
    fn canonical_l4_gate_v4_rule_does_not_match_v6_addr() {
        let egress = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "0.0.0.0/0", 443, 443)]);
        let g = CanonicalL4Gate::new(egress);
        assert!(matches!(
            block_on(g.evaluate(Protocol::Tcp, ip6("2001:db8::1"), 443)).unwrap(),
            L4Decision::Deny { .. }
        ));
    }

    // Serialization smoke — Protocol still round-trips (used on the wire).
    #[test]
    fn protocol_kebab_case_serializes_as_lowercase() {
        let json = serde_json::to_string(&Protocol::Tcp).unwrap();
        assert_eq!(json, "\"tcp\"");
        let parsed: Protocol = serde_json::from_str("\"udp\"").unwrap();
        assert_eq!(parsed, Protocol::Udp);
    }

    // mandatory-deny via CanonicalEgress::permits — loopback must always deny
    // even through Unrestricted.
    #[test]
    fn mandatory_deny_wins_even_through_unrestricted() {
        let egress = CanonicalEgress::Unrestricted;
        let g = CanonicalL4Gate::new(egress);
        // 127.0.0.1 is loopback → mandatory-deny range.
        let d = block_on(g.evaluate(Protocol::Tcp, ip4("127.0.0.1"), 80)).unwrap();
        assert!(
            matches!(d, L4Decision::Deny { .. }),
            "mandatory-deny must fire even for Unrestricted, got {d:?}"
        );
    }

    // Build via canonicalize_l4 — the normal resolver path.
    #[test]
    fn from_canonicalize_l4_allows_listed_flow() {
        use mvm_core::policy::L4RuleSpec;
        use mvm_core::policy::canonicalize_l4;
        let specs = [L4RuleSpec {
            proto: "tcp".to_string(),
            dst_cidr: "10.0.0.0/24".to_string(),
            port_lo: 443,
            port_hi: 443,
        }];
        let eg = canonicalize_l4(&specs).expect("parse ok");
        let g = CanonicalL4Gate::new(eg);
        assert_eq!(
            block_on(g.evaluate(Protocol::Tcp, ip4("10.0.0.5"), 443)).unwrap(),
            L4Decision::Allow
        );
        assert!(matches!(
            block_on(g.evaluate(Protocol::Tcp, ip4("10.0.0.5"), 22)).unwrap(),
            L4Decision::Deny { .. }
        ));
    }
}

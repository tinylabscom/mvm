//! Lower a resolved egress policy into rvproxy's native `[policy]` config table.
//!
//! The config half of moving claim-10 egress enforcement off mvm's in-line
//! splice and onto rvproxy's native flow API. rvproxy runs as a supervised
//! subprocess (`rvproxy run --config`), so the binding is *config*, not an
//! in-process trait — mvm emits the `[policy]` table rvproxy enforces.
//!
//! ## Fidelity
//!
//! rvproxy's `[policy]` table expresses the full coarse + L4 + DNS shape of
//! claim-10's egress gate:
//!   - `default_egress_deny` — the deny-by-default coarse gate,
//!   - `cidr_denylist` — the always-on mandatory-deny set (link-local + cloud
//!     metadata),
//!   - `l4_allowlist` — per-tenant L4 grants at full proto + CIDR + port-range
//!     precision (rvproxy `policy_flow_reason`),
//!   - `dns_allowlist` — the upstream DNS hostname sinkhole (dotted-suffix).
//!
//! So the lowering is an exact projection of the resolved `CanonicalEgress`
//! (proven by the parity tests: `permits_flow` agrees with
//! `CanonicalEgress::permits` for every probed proto/ip/port) plus the DNS
//! hostname gate (mirroring `DnsSinkholeScan`). The only claim-10 dimension that
//! does NOT lower to `[policy]` is the byte scans (placeholder-leak + undeclared
//! redaction), which ride the transform/redaction path; [`RvproxyPolicyGaps`]
//! records that residual so the splice keeps it.

use mvm_core::network_policy::MANDATORY_DENY_RANGES;
use mvm_core::policy::projection::{CanonicalEgress, Proto};
use serde::Serialize;
use std::net::IpAddr;

/// mvm's projection of a resolved egress policy into rvproxy's `[policy]` table.
/// Field names and semantics mirror rvproxy's `PolicyConfig`
/// (`rvproxy-policy::model::PolicyConfig`) so this serializes straight into the
/// config rvproxy reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RvproxyPolicy {
    /// Master egress switch. Always true here; the deny decision is expressed
    /// through `default_egress_deny` + the allow/deny lists so a single oracle
    /// ([`Self::permits_flow`]) governs the verdict.
    pub allow_guest_egress: bool,
    /// Deny a destination matching no allow rule (claim-10 deny-by-default).
    pub default_egress_deny: bool,
    /// IP-only destination allow-list. Unused by the precise lowering (L4 grants
    /// go to `l4_allowlist`); kept for completeness / the `open` posture.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cidr_allowlist: Vec<String>,
    /// Always-denied CIDRs (mandatory-deny: link-local + cloud metadata).
    pub cidr_denylist: Vec<String>,
    /// Upstream DNS hostname allow-list (dotted-suffix sinkhole).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_allowlist: Vec<String>,
    /// Per-tenant L4 grants: proto + CIDR + inclusive port range. Kept last
    /// because the `toml` crate renders a `Vec<struct>` as an array-of-tables
    /// (`[[l4_allowlist]]`), which must follow every scalar/inline-array field.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub l4_allowlist: Vec<RvproxyL4Rule>,
}

/// One L4 egress allow rule, mirroring rvproxy's `[[policy.l4_allowlist]]`
/// (`rvproxy-policy::L4RuleConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RvproxyL4Rule {
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    pub cidr: String,
    pub port_lo: u16,
    pub port_hi: u16,
}

impl RvproxyL4Rule {
    fn permits(&self, proto: Proto, ip: IpAddr, port: u16) -> bool {
        self.protocol == proto_str(proto)
            && cidr_contains(&self.cidr, ip)
            && self.port_lo <= port
            && port <= self.port_hi
    }
}

impl RvproxyPolicy {
    /// The egress verdict rvproxy will reach for a flow, mirroring its
    /// `policy_flow_reason` precedence exactly: a denylist match denies; an L4 or
    /// IP allow-list match admits; a non-empty allow-list with no match denies;
    /// deny-by-default with empty allow-lists denies; otherwise allow. This is the
    /// parity oracle the splice's gate must agree with.
    pub fn permits_flow(&self, proto: Proto, ip: IpAddr, port: u16) -> bool {
        if self
            .cidr_denylist
            .iter()
            .any(|cidr| cidr_contains(cidr, ip))
        {
            return false;
        }
        let l4_match = self
            .l4_allowlist
            .iter()
            .any(|rule| rule.permits(proto, ip, port));
        let cidr_match = self
            .cidr_allowlist
            .iter()
            .any(|cidr| cidr_contains(cidr, ip));
        if l4_match || cidr_match {
            return true;
        }
        if !self.l4_allowlist.is_empty() || !self.cidr_allowlist.is_empty() {
            return false;
        }
        !self.default_egress_deny
    }

    /// Whether `name` may be resolved upstream under the DNS hostname allow-list.
    /// Empty list = no restriction. Dotted-suffix, case/dot-normalized — mirrors
    /// rvproxy's `dns_allowlist_permits` and mvm's `DnsSinkholeScan`: `name` is
    /// admitted iff it equals a listed suffix or is a dotted subdomain of one
    /// (so `example.com` admits `api.example.com`, never `notexample.com`).
    pub fn dns_permits(&self, name: &str) -> bool {
        if self.dns_allowlist.is_empty() {
            return true;
        }
        let query = name.trim_matches('.').to_ascii_lowercase();
        self.dns_allowlist.iter().any(|suffix| {
            let suffix = suffix.trim_matches('.').to_ascii_lowercase();
            !suffix.is_empty() && (query == suffix || query.ends_with(&format!(".{suffix}")))
        })
    }
}

/// What a resolved policy carries that rvproxy's `[policy]` table cannot express,
/// so the splice must keep enforcing it. Now that L4 (proto/port) and DNS
/// hostnames lower natively, the only residual is the byte scans.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RvproxyPolicyGaps {
    /// Placeholder-leak backstop + undeclared redaction are byte scans, not
    /// `[policy]`; they ride the transform/redaction path (a later slice may move
    /// redaction to an rvproxy `secret-redaction-filter` plugin). Always true.
    pub byte_scans_in_splice: bool,
}

/// Lower a resolved egress projection (+ its DNS hostname allow-list) into the
/// rvproxy `[policy]` table and the residual that stays in the splice.
pub fn lower_policy(egress: &CanonicalEgress, dns_allow: &[String]) -> RvproxyLowering {
    let cidr_denylist: Vec<String> = MANDATORY_DENY_RANGES
        .iter()
        .map(|s| s.to_string())
        .collect();

    let (default_egress_deny, l4_allowlist) = match egress {
        // The `egress.mode = "open"` kill-switch: allow-unless-denied. Mandatory
        // deny still bites via the denylist.
        CanonicalEgress::Unrestricted => (false, Vec::new()),
        // Rules — deny-by-default, allow each grant at full proto/CIDR/port
        // precision. An empty rule set is deny-all (no allow rules + deny-by-
        // default).
        CanonicalEgress::Rules(rules) => {
            let l4 = rules
                .iter()
                .map(|r| RvproxyL4Rule {
                    protocol: proto_str(r.proto).to_string(),
                    cidr: r.net.to_string(),
                    port_lo: r.port_lo,
                    port_hi: r.port_hi,
                })
                .collect();
            (true, l4)
        }
    };

    RvproxyLowering {
        policy: RvproxyPolicy {
            allow_guest_egress: true,
            default_egress_deny,
            cidr_allowlist: Vec::new(),
            cidr_denylist,
            l4_allowlist,
            dns_allowlist: dns_allow.to_vec(),
        },
        gaps: RvproxyPolicyGaps {
            byte_scans_in_splice: true,
        },
    }
}

/// The result of [`lower_policy`]: the rvproxy `[policy]` table plus the residual
/// the splice still enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RvproxyLowering {
    pub policy: RvproxyPolicy,
    pub gaps: RvproxyPolicyGaps,
}

fn proto_str(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    cidr.parse::<ipnet::IpNet>()
        .map(|net| net.contains(&ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::projection::CanonicalRule;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(net: &str, proto: Proto, port_lo: u16, port_hi: u16) -> CanonicalRule {
        CanonicalRule {
            proto,
            net: net.parse().unwrap(),
            port_lo,
            port_hi,
        }
    }

    const PROBES: &[&str] = &[
        "93.184.216.34",   // in a typical allowed CIDR
        "8.8.8.8",         // a different public IP
        "169.254.169.254", // cloud metadata (mandatory-deny)
        "169.254.1.1",     // link-local (mandatory-deny)
        "127.0.0.1",       // loopback (mandatory-deny)
        "1.1.1.1",         // another allowed CIDR in tests
        "10.0.0.5",        // private
    ];
    const PORTS: &[u16] = &[0, 53, 80, 443, 8080, 65535];

    /// The lowering must reproduce `CanonicalEgress::permits` exactly for every
    /// probed (proto, ip, port) — full L4 parity, not just coarse IP. This is the
    /// binary-discriminating oracle WS-1.5 promotes to the live native path.
    fn assert_flow_parity(egress: CanonicalEgress) {
        let lowered = lower_policy(&egress, &[]);
        for probe in PROBES {
            let addr = ip(probe);
            for proto in [Proto::Tcp, Proto::Udp] {
                for &port in PORTS {
                    assert_eq!(
                        lowered.policy.permits_flow(proto, addr, port),
                        egress.permits(&proto, addr, port),
                        "verdict diverges for {proto:?} {addr}:{port} under {egress:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn unrestricted_lowers_to_allow_unless_mandatory_deny() {
        assert_flow_parity(CanonicalEgress::Unrestricted);
        let lowered = lower_policy(&CanonicalEgress::Unrestricted, &[]);
        assert!(!lowered.policy.default_egress_deny);
        assert!(lowered.policy.l4_allowlist.is_empty());
        assert!(lowered.policy.permits_flow(Proto::Tcp, ip("8.8.8.8"), 443));
        assert!(
            !lowered
                .policy
                .permits_flow(Proto::Tcp, ip("169.254.169.254"), 443)
        );
    }

    #[test]
    fn empty_rules_lower_to_deny_all() {
        let egress = CanonicalEgress::Rules(vec![]);
        assert_flow_parity(egress.clone());
        let lowered = lower_policy(&egress, &[]);
        assert!(lowered.policy.default_egress_deny);
        assert!(lowered.policy.l4_allowlist.is_empty());
        for probe in PROBES {
            assert!(!lowered.policy.permits_flow(Proto::Tcp, ip(probe), 443));
        }
    }

    #[test]
    fn l4_rules_lower_with_full_proto_and_port_parity() {
        let egress = CanonicalEgress::Rules(vec![
            rule("93.184.216.0/24", Proto::Tcp, 443, 443),
            rule("1.1.1.0/24", Proto::Udp, 53, 53),
        ]);
        assert_flow_parity(egress.clone());
        let lowered = lower_policy(&egress, &[]);
        assert!(lowered.policy.default_egress_deny);
        assert_eq!(lowered.policy.l4_allowlist.len(), 2);
        // Exact proto+port+CIDR admitted; wrong port/proto denied.
        assert!(
            lowered
                .policy
                .permits_flow(Proto::Tcp, ip("93.184.216.34"), 443)
        );
        assert!(
            !lowered
                .policy
                .permits_flow(Proto::Tcp, ip("93.184.216.34"), 8080)
        );
        assert!(
            !lowered
                .policy
                .permits_flow(Proto::Udp, ip("93.184.216.34"), 443)
        );
        assert!(lowered.policy.permits_flow(Proto::Udp, ip("1.1.1.1"), 53));
        // The L4 grants lowered natively → no L4 residual left for the splice.
        assert_eq!(
            lowered.gaps,
            RvproxyPolicyGaps {
                byte_scans_in_splice: true
            }
        );
    }

    #[test]
    fn mandatory_deny_overrides_an_l4_grant() {
        // A rule that would admit a mandatory-deny IP must still be denied.
        let egress = CanonicalEgress::Rules(vec![rule("169.254.0.0/16", Proto::Tcp, 0, 65535)]);
        assert_flow_parity(egress.clone());
        let lowered = lower_policy(&egress, &[]);
        assert!(
            !lowered
                .policy
                .permits_flow(Proto::Tcp, ip("169.254.169.254"), 80)
        );
    }

    #[test]
    fn dns_allowlist_lowers_and_matches_dotted_suffix() {
        let lowered = lower_policy(
            &CanonicalEgress::Rules(vec![]),
            &["example.com".to_string(), "Foo.NET".to_string()],
        );
        assert_eq!(lowered.policy.dns_allowlist.len(), 2);
        assert!(lowered.policy.dns_permits("example.com"));
        assert!(lowered.policy.dns_permits("api.example.com"));
        assert!(lowered.policy.dns_permits("API.EXAMPLE.COM."));
        assert!(lowered.policy.dns_permits("x.foo.net"));
        assert!(!lowered.policy.dns_permits("notexample.com"));
        assert!(!lowered.policy.dns_permits("evil.com"));
        // Empty list → no restriction.
        let open = lower_policy(&CanonicalEgress::Unrestricted, &[]);
        assert!(open.policy.dns_permits("anything.example"));
    }

    #[test]
    fn mandatory_deny_set_is_always_in_the_denylist() {
        let lowered = lower_policy(&CanonicalEgress::Unrestricted, &[]);
        assert_eq!(
            lowered.policy.cidr_denylist.len(),
            MANDATORY_DENY_RANGES.len()
        );
        assert!(
            lowered
                .policy
                .cidr_denylist
                .iter()
                .any(|c| c == "169.254.169.254/32")
        );
    }

    #[test]
    fn policy_serializes_to_rvproxy_toml_shape() {
        let lowered = lower_policy(
            &CanonicalEgress::Rules(vec![rule("93.184.216.0/24", Proto::Tcp, 443, 443)]),
            &["example.com".to_string()],
        );
        let toml = toml::to_string(&lowered.policy).unwrap();
        assert!(toml.contains("allow_guest_egress = true"));
        assert!(toml.contains("default_egress_deny = true"));
        assert!(toml.contains("169.254.169.254/32"));
        assert!(toml.contains("dns_allowlist = [\"example.com\"]"));
        // L4 rules serialize as a TOML array-of-tables rvproxy parses.
        assert!(toml.contains("[[l4_allowlist]]"));
        assert!(toml.contains("protocol = \"tcp\""));
        assert!(toml.contains("port_lo = 443"));
    }
}

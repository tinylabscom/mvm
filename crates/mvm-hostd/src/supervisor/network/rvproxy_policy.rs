//! Lower a resolved egress policy into rvproxy's native `[policy]` config table.
//!
//! The config half of moving claim-10 egress enforcement off mvm's in-line
//! splice and onto rvproxy's native flow API. rvproxy runs as a supervised
//! subprocess (`rvproxy run --config`), so the binding is *config*, not an
//! in-process trait — mvm emits the `[policy]` table rvproxy enforces.
//!
//! ## What lowers, and what stays in the splice
//!
//! rvproxy's `[policy]` table is an **IP-level** allow/deny: `default_egress_deny`
//! + `cidr_allowlist` + `cidr_denylist`. It expresses exactly:
//!   - deny-by-default (claim-10's coarse gate),
//!   - the always-on mandatory-deny set (link-local + cloud metadata) as a
//!     denylist,
//!   - per-tenant L4 grants *coarsened to their destination CIDRs*.
//!
//! It cannot express port/proto scoping, DNS hostname allow-lists, or the byte
//! scans (placeholder-leak, undeclared redaction). So this lowering is a **sound
//! coarse pre-filter**: rvproxy denies everything outside the allowed CIDRs and
//! the mandatory-deny set, and the splice's `L4PolicyScan` / `DnsSinkholeScan` /
//! byte scans refine *within* what rvproxy admits. The composition never
//! over-permits (rvproxy's allow is a superset of the precise policy; the splice
//! still drops wrong-port/proto/host) and never under-blocks (every destination
//! some rule could permit is admitted at the IP layer).
//!
//! [`RvproxyPolicyGaps`] enumerates what did NOT lower so the caller keeps the
//! splice for it — the coarsening is explicit, never silent.

use mvm_core::network_policy::MANDATORY_DENY_RANGES;
use mvm_core::policy::projection::CanonicalEgress;
use serde::Serialize;
use std::net::IpAddr;

/// mvm's projection of a resolved egress policy into rvproxy's `[policy]` table.
/// Field names and semantics mirror rvproxy's `PolicyConfig`
/// (`rvproxy-policy::model::PolicyConfig`) so this serializes straight into the
/// config rvproxy reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RvproxyPolicy {
    /// Master egress switch. Always true here; the deny decision is expressed
    /// through `default_egress_deny` + the lists so a single oracle
    /// ([`Self::permits_dest`]) governs the verdict.
    pub allow_guest_egress: bool,
    /// Deny a destination matching no allow rule (claim-10 deny-by-default).
    pub default_egress_deny: bool,
    /// Destination CIDRs egress is permitted to (coarsened L4 grants).
    pub cidr_allowlist: Vec<String>,
    /// Always-denied CIDRs (mandatory-deny: link-local + cloud metadata).
    pub cidr_denylist: Vec<String>,
}

impl RvproxyPolicy {
    /// The egress verdict rvproxy will reach for `ip`, mirroring its
    /// `policy_destination_reason` precedence exactly: denylist match denies;
    /// a non-empty allowlist with no match denies; deny-by-default with an empty
    /// allowlist denies; otherwise allow. This is the parity oracle the splice's
    /// coarse gate must agree with.
    pub fn permits_dest(&self, ip: IpAddr) -> bool {
        if self
            .cidr_denylist
            .iter()
            .any(|cidr| cidr_contains(cidr, ip))
        {
            return false;
        }
        if !self.cidr_allowlist.is_empty()
            && !self
                .cidr_allowlist
                .iter()
                .any(|cidr| cidr_contains(cidr, ip))
        {
            return false;
        }
        if self.default_egress_deny && self.cidr_allowlist.is_empty() {
            return false;
        }
        true
    }
}

/// What a resolved policy carries that rvproxy's IP-level `[policy]` table cannot
/// express, so the caller must keep the in-line splice stage for it. A non-zero /
/// true field means "the splice still owns this dimension."
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RvproxyPolicyGaps {
    /// L4 grants carry a proto and (often) a port range; rvproxy's allowlist is
    /// IP-only, so it would admit every proto/port to an allowed CIDR. The
    /// splice's `L4PolicyScan` must refine these. Counts the coarsened rules.
    pub l4_scoped_rules: usize,
    /// DNS hostname allow-list entries; rvproxy has no hostname sinkhole (only
    /// `allow_dns_local`/`allow_dns_upstream` booleans), so the splice's
    /// `DnsSinkholeScan` must run. Counts the hostnames.
    pub dns_hostnames: usize,
    /// Placeholder-leak backstop + undeclared redaction are byte scans, not
    /// `[policy]`; they stay in the splice (a later slice may move redaction to an
    /// rvproxy `secret-redaction-filter` plugin). Always true.
    pub byte_scans_in_splice: bool,
}

/// Lower a resolved egress projection (+ its DNS hostname allow-list) into the
/// rvproxy `[policy]` table and the residual that stays in the splice.
pub fn lower_policy(egress: &CanonicalEgress, dns_allow: &[String]) -> RvproxyLowering {
    let cidr_denylist: Vec<String> = MANDATORY_DENY_RANGES
        .iter()
        .map(|s| s.to_string())
        .collect();

    let (default_egress_deny, cidr_allowlist, l4_scoped_rules) = match egress {
        // The `egress.mode = "open"` kill-switch: allow-unless-denied. Mandatory
        // deny still bites via the denylist.
        CanonicalEgress::Unrestricted => (false, Vec::new(), 0),
        // Rules — deny-by-default, allow the rules' destination CIDRs. An empty
        // rule set is deny-all (empty allowlist + deny-by-default). Every rule is
        // proto-scoped (and usually port-scoped), so each is a splice residual.
        CanonicalEgress::Rules(rules) => {
            let mut allowlist: Vec<String> = rules.iter().map(|r| r.net.to_string()).collect();
            allowlist.sort();
            allowlist.dedup();
            (true, allowlist, rules.len())
        }
    };

    RvproxyLowering {
        policy: RvproxyPolicy {
            allow_guest_egress: true,
            default_egress_deny,
            cidr_allowlist,
            cidr_denylist,
        },
        gaps: RvproxyPolicyGaps {
            l4_scoped_rules,
            dns_hostnames: dns_allow.len(),
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

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    cidr.parse::<ipnet::IpNet>()
        .map(|net| net.contains(&ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::projection::{CanonicalRule, Proto};

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

    /// The coarse IP-level decision the rvproxy `[policy]` table is meant to
    /// reproduce: deny mandatory-deny, otherwise allow iff open or some rule's
    /// CIDR covers the destination. The splice refines proto/port/host within.
    fn coarse_permits(egress: &CanonicalEgress, ip: IpAddr) -> bool {
        if mvm_core::network_policy::is_mandatory_deny(ip) {
            return false;
        }
        match egress {
            CanonicalEgress::Unrestricted => true,
            CanonicalEgress::Rules(rules) => rules.iter().any(|r| r.net.contains(&ip)),
        }
    }

    const PROBES: &[&str] = &[
        "93.184.216.34",   // in a typical allowed CIDR
        "8.8.8.8",         // a different public IP
        "169.254.169.254", // cloud metadata (mandatory-deny)
        "169.254.1.1",     // link-local (mandatory-deny)
        "127.0.0.1",       // loopback (mandatory-deny)
        "10.0.0.5",        // private
    ];

    fn assert_parity(egress: CanonicalEgress, dns_allow: &[String]) {
        let lowered = lower_policy(&egress, dns_allow);
        for probe in PROBES {
            let addr = ip(probe);
            assert_eq!(
                lowered.policy.permits_dest(addr),
                coarse_permits(&egress, addr),
                "rvproxy verdict diverges from the coarse policy for {probe} under {egress:?}",
            );
        }
    }

    #[test]
    fn unrestricted_lowers_to_allow_unless_mandatory_deny() {
        assert_parity(CanonicalEgress::Unrestricted, &[]);
        let lowered = lower_policy(&CanonicalEgress::Unrestricted, &[]);
        assert!(!lowered.policy.default_egress_deny);
        assert!(lowered.policy.cidr_allowlist.is_empty());
        assert!(lowered.policy.permits_dest(ip("8.8.8.8")));
        assert!(!lowered.policy.permits_dest(ip("169.254.169.254")));
    }

    #[test]
    fn empty_rules_lower_to_deny_all() {
        let egress = CanonicalEgress::Rules(vec![]);
        assert_parity(egress.clone(), &[]);
        let lowered = lower_policy(&egress, &[]);
        assert!(lowered.policy.default_egress_deny);
        assert!(lowered.policy.cidr_allowlist.is_empty());
        for probe in PROBES {
            assert!(!lowered.policy.permits_dest(ip(probe)));
        }
    }

    #[test]
    fn cidr_rules_lower_to_allowlist_and_flag_l4_residual() {
        let egress = CanonicalEgress::Rules(vec![
            rule("93.184.216.0/24", Proto::Tcp, 443, 443),
            rule("93.184.216.0/24", Proto::Udp, 0, 65535),
        ]);
        assert_parity(egress.clone(), &[]);
        let lowered = lower_policy(&egress, &[]);
        assert!(lowered.policy.default_egress_deny);
        // Both rules share a CIDR → one deduped allowlist entry.
        assert_eq!(lowered.policy.cidr_allowlist, vec!["93.184.216.0/24"]);
        assert!(lowered.policy.permits_dest(ip("93.184.216.34")));
        assert!(!lowered.policy.permits_dest(ip("8.8.8.8")));
        // Every rule is proto/port-scoped → the splice's L4PolicyScan must run.
        assert_eq!(lowered.gaps.l4_scoped_rules, 2);
    }

    #[test]
    fn coarse_filter_never_under_blocks_a_permitted_destination() {
        // Soundness: every (proto, ip, port) the precise policy permits must be
        // admitted by the coarse rvproxy filter (the splice then refines). If the
        // coarse layer denied a permitted destination, egress would break.
        let egress = CanonicalEgress::Rules(vec![
            rule("93.184.216.0/24", Proto::Tcp, 443, 443),
            rule("1.1.1.0/24", Proto::Udp, 53, 53),
        ]);
        let lowered = lower_policy(&egress, &[]);
        for probe in PROBES {
            let addr = ip(probe);
            for proto in [Proto::Tcp, Proto::Udp] {
                for port in [53_u16, 443, 80, 8080] {
                    if egress.permits(&proto, addr, port) {
                        assert!(
                            lowered.policy.permits_dest(addr),
                            "coarse filter under-blocked {addr} which policy permits on {proto:?}:{port}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dns_hostnames_are_flagged_as_splice_residual() {
        let lowered = lower_policy(
            &CanonicalEgress::Rules(vec![]),
            &["api.example.com".to_string(), "cdn.example.com".to_string()],
        );
        assert_eq!(lowered.gaps.dns_hostnames, 2);
        assert!(lowered.gaps.byte_scans_in_splice);
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
    fn policy_serializes_to_rvproxy_toml_field_names() {
        let lowered = lower_policy(
            &CanonicalEgress::Rules(vec![rule("93.184.216.0/24", Proto::Tcp, 443, 443)]),
            &[],
        );
        let toml = toml::to_string(&lowered.policy).unwrap();
        assert!(toml.contains("allow_guest_egress = true"));
        assert!(toml.contains("default_egress_deny = true"));
        assert!(toml.contains("cidr_allowlist = [\"93.184.216.0/24\"]"));
        assert!(toml.contains("169.254.169.254/32"));
    }
}

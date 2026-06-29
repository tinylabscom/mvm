//! The host vsock egress gateway's allow/deny decision (ADR-100).
//!
//! Under the vsock-only invariant a workload guest has no NIC: it asks the host
//! to open an outbound connection over vsock, and this gate decides whether the
//! signed plan's network policy permits it. The decision reuses
//! [`CanonicalEgress`] — the *same* claim-10 function nftables / the
//! gateway-bridge enforce — so every backend agrees on one rule set. **Default is
//! deny:** an empty rule set permits nothing, and mandatory-deny / SSH flows are
//! refused regardless.
//!
//! This module is the pure decision; the vsock device calls it before opening any
//! host socket. The connect/proxy data path is the gateway's separate concern.

use std::net::{IpAddr, SocketAddr};

use mvm_core::policy::projection::{CanonicalEgress, Proto};

/// Outcome of an egress request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressVerdict {
    /// The plan permits a TCP connection to this destination.
    Allow { ip: IpAddr, port: u16 },
    /// Refused — policy did not admit it (claim-10 default-deny / mandatory-deny).
    Deny,
    /// The guest's connect request was malformed (not `ip:port`).
    Malformed,
}

/// The host-side egress decision for one VM, wrapping its resolved
/// [`CanonicalEgress`] grant.
#[derive(Debug, Clone)]
pub struct EgressGate {
    egress: CanonicalEgress,
}

impl EgressGate {
    /// A gate that denies everything — the posture for a VM with no admitted
    /// network policy (claim-10 default-deny).
    pub fn default_deny() -> Self {
        Self {
            egress: CanonicalEgress::Rules(Vec::new()),
        }
    }

    /// A gate over an explicit resolved grant.
    pub fn new(egress: CanonicalEgress) -> Self {
        Self { egress }
    }

    /// Build a gate from a VM's resolved [`NetworkPolicy`] via the shared claim-10
    /// projection. **Fails closed:** any projection error (e.g. a host-allowlist
    /// rule whose DNS pin hasn't been threaded in yet) yields default-deny rather
    /// than a permissive gate. This is the supervisor's path to the admitted
    /// plan's policy (ADR-100).
    ///
    /// [`NetworkPolicy`]: mvm_core::policy::network_policy::NetworkPolicy
    pub fn from_network_policy(
        policy: &mvm_core::policy::network_policy::NetworkPolicy,
        pins: &mvm_core::policy::dns_pin::DnsPinRegistry,
        now: &str,
    ) -> Self {
        match mvm_core::policy::projection::canonicalize_network_policy(policy, pins, now) {
            Ok(canon) => Self::new(canon),
            Err(_) => Self::default_deny(),
        }
    }

    /// Decide a TCP connect to an already-resolved address.
    pub fn decide_addr(&self, ip: IpAddr, port: u16) -> EgressVerdict {
        if self.egress.permits(&Proto::Tcp, ip, port) {
            EgressVerdict::Allow { ip, port }
        } else {
            EgressVerdict::Deny
        }
    }

    /// Decide a guest connect request of the form `"<ip>:<port>"` (a numeric
    /// address — DNS resolution, when added, happens before this). A request that
    /// does not parse is [`EgressVerdict::Malformed`] (fail-closed: no connection).
    pub fn decide_request(&self, target: &str) -> EgressVerdict {
        match target.trim().parse::<SocketAddr>() {
            Ok(addr) => self.decide_addr(addr.ip(), addr.port()),
            Err(_) => EgressVerdict::Malformed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::projection::CanonicalRule;

    fn allow_rule(cidr: &str, port: u16) -> CanonicalRule {
        CanonicalRule {
            proto: Proto::Tcp,
            net: cidr.parse().unwrap(),
            port_lo: port,
            port_hi: port,
        }
    }

    #[test]
    fn default_deny_refuses_everything() {
        let gate = EgressGate::default_deny();
        assert_eq!(gate.decide_request("1.1.1.1:443"), EgressVerdict::Deny);
        assert_eq!(gate.decide_request("93.184.216.34:80"), EgressVerdict::Deny);
    }

    #[test]
    fn allow_list_permits_only_the_listed_destination() {
        let gate = EgressGate::new(CanonicalEgress::Rules(vec![allow_rule("1.1.1.1/32", 443)]));
        assert_eq!(
            gate.decide_request("1.1.1.1:443"),
            EgressVerdict::Allow {
                ip: "1.1.1.1".parse().unwrap(),
                port: 443
            }
        );
        // Wrong port / wrong host → still denied.
        assert_eq!(gate.decide_request("1.1.1.1:80"), EgressVerdict::Deny);
        assert_eq!(gate.decide_request("8.8.8.8:443"), EgressVerdict::Deny);
    }

    #[test]
    fn ssh_flow_is_refused_even_when_listed() {
        // A grant that names port 22 must still be refused (claim-10 banned-SSH).
        let gate = EgressGate::new(CanonicalEgress::Rules(vec![allow_rule("1.1.1.1/32", 22)]));
        assert_eq!(gate.decide_request("1.1.1.1:22"), EgressVerdict::Deny);
    }

    #[test]
    fn malformed_request_fails_closed() {
        let gate = EgressGate::new(CanonicalEgress::Unrestricted);
        assert_eq!(gate.decide_request("not-an-addr"), EgressVerdict::Malformed);
        assert_eq!(gate.decide_request(""), EgressVerdict::Malformed);
    }

    #[test]
    fn unrestricted_permits_a_normal_flow() {
        let gate = EgressGate::new(CanonicalEgress::Unrestricted);
        assert_eq!(
            gate.decide_request("93.184.216.34:80"),
            EgressVerdict::Allow {
                ip: "93.184.216.34".parse().unwrap(),
                port: 80
            }
        );
    }

    /// The gate composes with the real `NetworkPolicy` projection — the path the
    /// HVF supervisor will thread in (deny-all ⇒ deny, unrestricted ⇒ admit).
    #[test]
    fn gate_honors_a_real_network_policy_projection() {
        use mvm_core::policy::dns_pin::DnsPinRegistry;
        use mvm_core::policy::network_policy::NetworkPolicy;
        use mvm_core::policy::projection::canonicalize_network_policy;

        let pins = DnsPinRegistry::new();
        let now = "2026-01-01T00:00:00Z";

        let deny = canonicalize_network_policy(&NetworkPolicy::deny_all(), &pins, now).unwrap();
        assert_eq!(
            EgressGate::new(deny).decide_request("1.1.1.1:443"),
            EgressVerdict::Deny
        );

        let open = canonicalize_network_policy(&NetworkPolicy::unrestricted(), &pins, now).unwrap();
        assert_eq!(
            EgressGate::new(open).decide_request("93.184.216.34:80"),
            EgressVerdict::Allow {
                ip: "93.184.216.34".parse().unwrap(),
                port: 80
            }
        );
    }

    /// `from_network_policy` is the supervisor's path: deny-all ⇒ deny,
    /// unrestricted ⇒ admit, and any projection error ⇒ fail-closed deny.
    #[test]
    fn from_network_policy_threads_the_real_policy_and_fails_closed() {
        use mvm_core::policy::dns_pin::DnsPinRegistry;
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let pins = DnsPinRegistry::new();
        let now = "2026-01-01T00:00:00Z";

        let deny = EgressGate::from_network_policy(&NetworkPolicy::deny_all(), &pins, now);
        assert_eq!(deny.decide_request("1.1.1.1:443"), EgressVerdict::Deny);

        let open = EgressGate::from_network_policy(&NetworkPolicy::unrestricted(), &pins, now);
        assert_eq!(
            open.decide_request("93.184.216.34:80"),
            EgressVerdict::Allow {
                ip: "93.184.216.34".parse().unwrap(),
                port: 80
            }
        );

        // A host-allowlist rule with no DNS pin can't project → fail closed (deny),
        // never a permissive gate.
        let unpinned = NetworkPolicy::allow_list(vec![HostPort {
            host: "example.com".into(),
            port: 443,
        }]);
        let gate = EgressGate::from_network_policy(&unpinned, &pins, now);
        assert_eq!(
            gate.decide_request("93.184.216.34:443"),
            EgressVerdict::Deny
        );
    }
}

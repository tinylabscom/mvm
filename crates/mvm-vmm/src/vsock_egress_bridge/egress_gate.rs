//! The host vsock egress gateway's allow/deny decision.
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

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use mvm_contract::peer::{PeerBinding, PeerName};
use mvm_core::policy::dns_guard::dns_answer_forbidden;
use mvm_core::policy::dns_pin::DnsPinRegistry;
use mvm_core::policy::projection::{CanonicalEgress, Proto};
use mvm_core::protocol::dns::DnsRecordType;

/// Outcome of an egress request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressVerdict {
    /// The plan permits traffic to this destination. `ips` are every admitted
    /// address (a pinned host can carry both an A and an AAAA record), IPv4
    /// first; stream callers connect to them in order, while datagram callers
    /// may send to each and accept the first valid response.
    Allow { ips: Vec<IpAddr>, port: u16 },
    /// Refused — policy did not admit it (claim-10 default-deny / mandatory-deny).
    /// Carries which refusal it was, so a caller can tell the guest.
    Deny(DenyReason),
    /// The guest's connect request was malformed (not `<ip>:<port>` or `<hostname>:<port>`).
    Malformed,
}

impl EgressVerdict {
    /// Whether this verdict refuses the request, whatever the reason. For
    /// callers (and assertions) that care that the gate said no, not why.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny(_))
    }
}

/// Which claim-10 refusal a [`EgressVerdict::Deny`] is.
///
/// The decision and its reason are one value because a caller that has to
/// explain the refusal cannot recompute it: the gate holds the pins and the
/// canonical rules, and by the time a 403 is being written they are gone. The
/// distinctions here are the ones a caller acts on differently — a host absent
/// from the allow-list is a different fix from the same host on an unadmitted
/// port, which is the pair a bare `--allow-host <host>` (meaning `<host>:443`)
/// most often lands a caller in.
///
/// This is deliberately about *policy shape*, not about the destination: it
/// names hosts and ports the operator already wrote on the command line, never
/// anything learned from the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// The workload admits no egress at all (claim-10 default-deny).
    NoEgressAdmitted,
    /// The destination host is not in the allow-list — no admission pin exists
    /// for it. `admitted_hosts` are the names that are pinned.
    HostNotAdmitted {
        /// The refused name, as the guest asked for it.
        host: String,
        /// Every host name the policy does admit.
        admitted_hosts: Vec<String>,
    },
    /// The host is admitted but not on this port. `admitted_ports` are the
    /// ports the policy admits for it.
    PortNotAdmitted {
        /// The admitted host.
        host: String,
        /// The refused port.
        port: u16,
        /// Ports the policy admits for `host`.
        admitted_ports: Vec<u16>,
    },
    /// A peer dial the plan does not admit — either the name is bound to no
    /// route, or it is bound on a different port. One variant covers both
    /// because a binding authorizes a `name:port` route rather than a peer,
    /// so "wrong port" is not a narrower miss than "wrong name".
    PeerNotAdmitted {
        /// The refused peer target as the guest asked for it (`name:port`).
        target: String,
        /// Every `name:port` route the plan admits for this workload.
        admitted_routes: Vec<String>,
    },
    /// A numeric destination outside every rule, or one under mandatory-deny
    /// (loopback / private / link-local) or a banned flow.
    AddressNotAdmitted {
        /// The refused address.
        ip: IpAddr,
        /// The refused port.
        port: u16,
    },
    /// An unrestricted gate could not resolve the name.
    ResolutionFailed {
        /// The name that would not resolve.
        host: String,
    },
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEgressAdmitted => {
                write!(f, "egress is deny-all for this workload")
            }
            Self::HostNotAdmitted {
                host,
                admitted_hosts,
            } if admitted_hosts.is_empty() => {
                write!(f, "{host} is not admitted; no hosts are admitted")
            }
            Self::HostNotAdmitted {
                host,
                admitted_hosts,
            } => {
                write!(
                    f,
                    "{host} is not admitted; allowed: {}",
                    admitted_hosts.join(", ")
                )
            }
            Self::PortNotAdmitted {
                host,
                port,
                admitted_ports,
            } if admitted_ports.is_empty() => {
                write!(f, "{host}:{port} is not admitted")
            }
            Self::PortNotAdmitted {
                host,
                port,
                admitted_ports,
            } => {
                let allowed = admitted_ports
                    .iter()
                    .map(|p| format!("{host}:{p}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "{host}:{port} is not admitted; allowed: {allowed}")
            }
            Self::PeerNotAdmitted {
                target,
                admitted_routes,
            } if admitted_routes.is_empty() => {
                write!(f, "{target} is not admitted; no peers are admitted")
            }
            Self::PeerNotAdmitted {
                target,
                admitted_routes,
            } => {
                write!(
                    f,
                    "{target} is not admitted; allowed: {}",
                    admitted_routes.join(", ")
                )
            }
            Self::AddressNotAdmitted { ip, port } => {
                write!(f, "{ip}:{port} is not admitted")
            }
            Self::ResolutionFailed { host } => {
                write!(f, "could not resolve {host}")
            }
        }
    }
}

/// Policy result for a guest DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsVerdict {
    /// The name was admitted and these answers survived family and rebinding
    /// filtering. An empty vector is a successful NODATA result.
    Resolved(Vec<IpAddr>),
    /// Policy refused the name, or its admitted upstream lookup failed.
    Refused,
}

/// The host-side egress decision for one VM, wrapping its resolved
/// [`CanonicalEgress`] grant plus the DNS pin registry used to resolve a
/// `hostname:port` request host-side (DNS-over-vsock).
#[derive(Debug, Clone)]
pub struct EgressGate {
    egress: CanonicalEgress,
    /// Host→pinned-IP map. A guest using a `socks5h` client sends a *hostname*; the
    /// trusted host resolves it here (against the same pins `canonicalize` used) and
    /// policy-checks the pinned IP before connecting. The guest never resolves.
    pins: DnsPinRegistry,
    /// Peer routes this workload may dial, admitted in its signed plan. Empty is
    /// the default and admits nothing, so east-west inherits claim-10's posture
    /// rather than needing its own.
    peers: Vec<PeerBinding>,
}

impl EgressGate {
    /// A gate that denies everything — the posture for a VM with no admitted
    /// network policy (claim-10 default-deny).
    pub fn default_deny() -> Self {
        Self {
            egress: CanonicalEgress::Rules(Vec::new()),
            pins: DnsPinRegistry::new(),
            peers: Vec::new(),
        }
    }

    /// A gate over an explicit resolved grant (no host-name resolution).
    pub fn new(egress: CanonicalEgress) -> Self {
        Self {
            egress,
            pins: DnsPinRegistry::new(),
            peers: Vec::new(),
        }
    }

    /// Build a gate from a VM's resolved [`NetworkPolicy`] via the shared claim-10
    /// projection. **Fails closed:** any projection error (e.g. a host-allowlist
    /// rule whose DNS pin hasn't been threaded in yet) yields default-deny rather
    /// than a permissive gate. This is the supervisor's path to the admitted
    /// plan's policy.
    ///
    /// [`NetworkPolicy`]: mvm_core::policy::network_policy::NetworkPolicy
    pub fn from_network_policy(
        policy: &mvm_core::policy::network_policy::NetworkPolicy,
        pins: &mvm_core::policy::dns_pin::DnsPinRegistry,
        now: &str,
    ) -> Self {
        match mvm_core::policy::projection::canonicalize_network_policy(policy, pins, now) {
            Ok(canon) => Self {
                egress: canon,
                pins: pins.clone(),
                peers: Vec::new(),
            },
            Err(_) => Self::default_deny(),
        }
    }

    /// Attach admitted peer routes. Separate from construction because every
    /// existing call site builds a gate with no peers, and a workload with no
    /// peer bindings must keep behaving exactly as it does today.
    #[must_use]
    pub fn with_peers(mut self, peers: Vec<PeerBinding>) -> Self {
        self.peers = peers;
        self
    }

    /// Decide a guest connect to `host:port`, whichever namespace it is in.
    ///
    /// **This is the one entry point every workload connect goes through.**
    /// The two namespaces are disjoint by construction — a target either ends
    /// in the peer suffix or it does not — so the branch is total and neither
    /// arm can shadow the other. Callers must not re-implement the branch:
    /// a second copy is how one of the two paths quietly stops being gated.
    /// `xtask check-single-network-path` pins the call sites for that reason.
    pub fn decide_target(&self, host: &str, port: u16) -> EgressVerdict {
        if PeerName::is_peer_target(host) {
            self.decide_peer(host, port)
        } else {
            self.decide_request(&format!("{host}:{port}"))
        }
    }

    /// Decide a dial to a peer name.
    ///
    /// Called only for targets [`PeerName::is_peer_target`] claims, so a
    /// malformed peer name lands here and is refused rather than falling
    /// through to host-name resolution. The returned address is the peer's
    /// admitted ingress mapping, so the caller connects to it exactly as it
    /// would to any other allowed destination.
    ///
    /// Deny is the default: a gate with no peer bindings admits no peer.
    pub fn decide_peer(&self, host: &str, port: u16) -> EgressVerdict {
        let Ok(name) = PeerName::parse(host) else {
            return EgressVerdict::Malformed;
        };
        let Some(binding) = self.peers.iter().find(|b| b.admits(&name, port)) else {
            return EgressVerdict::Deny(DenyReason::PeerNotAdmitted {
                target: format!("{name}:{port}"),
                admitted_routes: self
                    .peers
                    .iter()
                    .map(|b| format!("{}:{}", b.name, b.port))
                    .collect(),
            });
        };
        // A binding is validated before admission, so this parse cannot fail
        // for an admitted plan. Refusing rather than unwrapping keeps a
        // hand-built gate in a test from panicking the supervisor.
        let Ok(ip) = binding.host_addr.parse::<IpAddr>() else {
            return EgressVerdict::Deny(DenyReason::PeerNotAdmitted {
                target: format!("{name}:{port}"),
                admitted_routes: Vec::new(),
            });
        };
        EgressVerdict::Allow {
            ips: vec![ip],
            port: binding.host_port,
        }
    }

    /// Decide a TCP connect to an already-resolved address.
    ///
    /// When the address belongs to a pinned host, the verdict carries that
    /// host's whole admitted address set (IPv4 first), not just the single
    /// address requested. A guest that resolved a dual-stack host locally and
    /// dialed the numeric IPv6 (macOS `getaddrinfo` returns IPv6 first) then
    /// falls over to the pinned IPv4 sibling when the IPv6 route is unreachable
    /// instead of stranding the connect — the same happy-eyeballs behaviour the
    /// hostname path already gets. Every offered address is independently
    /// policy-checked, so widening the set never admits an unpinned target.
    pub fn decide_addr(&self, ip: IpAddr, port: u16) -> EgressVerdict {
        self.decide_addr_for_proto(Proto::Tcp, ip, port)
    }

    /// Decide a UDP datagram to an already-resolved address.
    pub fn decide_udp_addr(&self, ip: IpAddr, port: u16) -> EgressVerdict {
        self.decide_addr_for_proto(Proto::Udp, ip, port)
    }

    /// Decide a guest connect request — either a numeric `"<ip>:<port>"` or a
    /// `"<hostname>:<port>"` (DNS-over-vsock: the `socks5h` client sends a name and
    /// the host resolves it here against the pin registry, never the guest). A
    /// hostname with no matching pin is refused (`Deny`); an unparseable target is
    /// `Malformed`. Fail-closed throughout.
    pub fn decide_request(&self, target: &str) -> EgressVerdict {
        self.decide_request_with(target, resolve_hostname_ips)
    }

    /// Like [`decide_request`], but lets the caller supply the hostname resolver.
    /// This is the escape hatch for confined runtimes that must avoid libc/NSS
    /// hostname resolution and instead use a pure-Rust DNS path.
    pub fn decide_request_with<F>(&self, target: &str, resolve: F) -> EgressVerdict
    where
        F: Fn(&str) -> std::io::Result<Vec<IpAddr>>,
    {
        self.decide_request_with_proto(Proto::Tcp, target, resolve)
    }

    /// Decide a UDP datagram request, resolving hostnames on the host side.
    pub fn decide_udp_request_with<F>(&self, target: &str, resolve: F) -> EgressVerdict
    where
        F: Fn(&str) -> std::io::Result<Vec<IpAddr>>,
    {
        self.decide_request_with_proto(Proto::Udp, target, resolve)
    }

    /// Decide a UDP datagram request using the host resolver.
    pub fn decide_udp_request(&self, target: &str) -> EgressVerdict {
        self.decide_udp_request_with(target, resolve_hostname_ips)
    }

    /// Host names the policy admits, in registry order. The pin registry is the
    /// admission record — a name is pinned exactly when the allow-list named it —
    /// so this is what a caller can suggest instead of the refused destination.
    fn admitted_hosts(&self) -> Vec<String> {
        self.pins.pins.keys().cloned().collect()
    }

    /// Ports the policy admits for an already-pinned host, ascending. Derived by
    /// probing the canonical rules with the host's own pinned addresses, so it
    /// reports what the gate would actually admit rather than re-parsing the
    /// operator's input.
    fn admitted_ports_for(&self, proto: &Proto, ips: &[IpAddr]) -> Vec<u16> {
        let CanonicalEgress::Rules(rules) = &self.egress else {
            return Vec::new();
        };
        let mut ports: Vec<u16> = rules
            .iter()
            .filter(|rule| rule.proto == *proto)
            .filter(|rule| ips.iter().any(|ip| rule.net.contains(ip)))
            // A rule is a range; report its endpoints rather than expanding a
            // range that can span the whole port space.
            .flat_map(|rule| [rule.port_lo, rule.port_hi])
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Decide an ICMP echo to `host`, resolved host-side against the pins.
    ///
    /// ICMP has no port, so the `host:port` allow-list cannot express "may ping
    /// this". The rule is that a host admitted for *any* port may be pinged:
    /// `--allow-host example.com` (which means `example.com:443`) admits echo to
    /// example.com. A host absent from the allow-list is refused, so ping never
    /// widens the set of destinations a workload can reach — only what it may do
    /// with one it was already given.
    ///
    /// Returns the pinned addresses to echo, IPv4 first, matching the ordering
    /// every other verdict uses.
    pub fn decide_icmp_request(&self, host: &str) -> EgressVerdict {
        let Some(pin) = self.pins.lookup(host) else {
            return EgressVerdict::Deny(if self.admitted_hosts().is_empty() {
                DenyReason::NoEgressAdmitted
            } else {
                DenyReason::HostNotAdmitted {
                    host: host.to_string(),
                    admitted_hosts: self.admitted_hosts(),
                }
            });
        };
        // Mandatory-deny still applies: a pinned loopback/link-local address is
        // refused for echo exactly as it is for a stream, so ping cannot become a
        // probe of the host's own private networks.
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in pin.ips.iter().copied().filter(|ip| !is_icmp_denied(*ip)) {
            match ip {
                IpAddr::V4(_) => v4.push(ip),
                IpAddr::V6(_) => v6.push(ip),
            }
        }
        v4.extend(v6);
        if v4.is_empty() {
            return EgressVerdict::Deny(DenyReason::HostNotAdmitted {
                host: host.to_string(),
                admitted_hosts: self.admitted_hosts(),
            });
        }
        // Port 0 marks "no port applies" — ICMP carries none, and no rule can
        // admit port 0, so this can never be mistaken for a stream grant.
        EgressVerdict::Allow { ips: v4, port: 0 }
    }

    fn decide_addr_for_proto(&self, proto: Proto, ip: IpAddr, port: u16) -> EgressVerdict {
        if !self.egress.permits(&proto, ip, port) {
            // A pinned address on the wrong port is the port-mismatch case even
            // when the guest dialled it numerically, so name the host it belongs
            // to rather than reporting a bare address.
            return match self.pins.pin_containing(&ip) {
                Some(pin) => EgressVerdict::Deny(DenyReason::PortNotAdmitted {
                    host: pin.dest.clone(),
                    port,
                    admitted_ports: self.admitted_ports_for(&proto, &pin.ips),
                }),
                None => EgressVerdict::Deny(DenyReason::AddressNotAdmitted { ip, port }),
            };
        }
        let ips = match self.pins.pin_containing(&ip) {
            Some(pin) => admitted_ips(&self.egress, &proto, &pin.ips, port),
            None => Vec::new(),
        };
        // No pin (or a pin that admitted nothing for this port) ⇒ keep just the
        // requested address, which the guard above already confirmed admitted.
        let ips = if ips.is_empty() { vec![ip] } else { ips };
        EgressVerdict::Allow { ips, port }
    }

    fn decide_request_with_proto<F>(&self, proto: Proto, target: &str, resolve: F) -> EgressVerdict
    where
        F: Fn(&str) -> std::io::Result<Vec<IpAddr>>,
    {
        let target = target.trim();
        // Numeric ip:port — decide directly.
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return self.decide_addr_for_proto(proto, addr.ip(), addr.port());
        }
        // hostname:port — resolve host-side against the pinned set, then policy-check
        // each pinned IP. Admit iff some pinned IP is permitted.
        match target.rsplit_once(':') {
            Some((host, port_str)) => match port_str.parse::<u16>() {
                Ok(port) => self.decide_hostname_request(proto, host, port, resolve),
                Err(_) => EgressVerdict::Malformed,
            },
            None => EgressVerdict::Malformed,
        }
    }

    fn decide_hostname_request<F>(
        &self,
        proto: Proto,
        host: &str,
        port: u16,
        resolve: F,
    ) -> EgressVerdict
    where
        F: Fn(&str) -> std::io::Result<Vec<IpAddr>>,
    {
        let pinned = self.pins.lookup(host).is_some();
        let candidates = if let Some(pin) = self.pins.lookup(host) {
            pin.ips.clone()
        } else if matches!(self.egress, CanonicalEgress::Unrestricted) {
            match resolve(host) {
                Ok(ips) => ips,
                Err(_) => {
                    return EgressVerdict::Deny(DenyReason::ResolutionFailed {
                        host: host.to_string(),
                    });
                }
            }
        } else {
            return EgressVerdict::Deny(if self.admitted_hosts().is_empty() {
                DenyReason::NoEgressAdmitted
            } else {
                DenyReason::HostNotAdmitted {
                    host: host.to_string(),
                    admitted_hosts: self.admitted_hosts(),
                }
            });
        };
        let ips = admitted_ips(&self.egress, &proto, &candidates, port);
        if !ips.is_empty() {
            return EgressVerdict::Allow { ips, port };
        }
        // Pinned but nothing admitted for this port is the port mismatch; an
        // unpinned name only reaches here on an unrestricted gate, where the
        // refusal came from the address filter rather than the allow-list.
        EgressVerdict::Deny(if pinned {
            DenyReason::PortNotAdmitted {
                host: host.to_string(),
                port,
                admitted_ports: self.admitted_ports_for(&proto, &candidates),
            }
        } else {
            DenyReason::HostNotAdmitted {
                host: host.to_string(),
                admitted_hosts: self.admitted_hosts(),
            }
        })
    }

    /// Resolve an admitted DNS name through the same policy seam as TCP egress.
    ///
    /// Admission pins always win and preserve explicitly admitted private
    /// addresses. Only an unrestricted gate may perform a live lookup; those
    /// answers are filtered for private, loopback, link-local, and unique-local
    /// rebinding targets before the guest sees them. Every other name is refused
    /// without invoking `resolve`.
    pub fn dns_verdict<F>(&self, name: &str, qtype: DnsRecordType, resolve: F) -> DnsVerdict
    where
        F: Fn(&str) -> std::io::Result<Vec<IpAddr>>,
    {
        let (candidates, explicitly_pinned) = if let Some(pin) = self.pins.lookup(name) {
            (pin.ips.clone(), true)
        } else if matches!(self.egress, CanonicalEgress::Unrestricted) {
            match resolve(name) {
                Ok(ips) => (ips, false),
                Err(_) => return DnsVerdict::Refused,
            }
        } else {
            return DnsVerdict::Refused;
        };

        let want_ipv4 = matches!(qtype, DnsRecordType::A);
        DnsVerdict::Resolved(
            candidates
                .into_iter()
                .filter(|ip| ip.is_ipv4() == want_ipv4)
                .filter(|ip| explicitly_pinned || !dns_answer_forbidden(*ip))
                .collect(),
        )
    }
}

/// Whether ICMP echo to `ip` is refused outright. ICMP has no port, so this asks
/// the shared claim-10 predicate the only way it can: an address that no TCP port
/// could ever reach is one mandatory-deny refuses, and it is refused for echo too.
fn is_icmp_denied(ip: IpAddr) -> bool {
    // `permits` applies mandatory-deny before consulting any rule, so an
    // unrestricted grant isolates exactly that check.
    !CanonicalEgress::Unrestricted.permits(&Proto::Tcp, ip, 443)
}

fn admitted_ips(
    egress: &CanonicalEgress,
    proto: &Proto,
    candidates: &[IpAddr],
    port: u16,
) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in candidates.iter().copied() {
        if !egress.permits(proto, ip, port) {
            continue;
        }
        match ip {
            IpAddr::V4(_) => v4.push(ip),
            IpAddr::V6(_) => v6.push(ip),
        }
    }
    v4.extend(v6);
    v4
}

fn resolve_hostname_ips(host: &str) -> std::io::Result<Vec<IpAddr>> {
    Ok((host, 0u16)
        .to_socket_addrs()?
        .map(|addr| addr.ip())
        .collect())
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

    /// The refusal a caller most often meets, and the one that reads as a
    /// broken network rather than a policy answer: a bare `--allow-host <host>`
    /// means `<host>:443`, so an `http://` URL asks for port 80 and is correctly
    /// denied. The verdict has to carry enough to say which port was asked for
    /// and which the policy admits, because that difference is the whole answer.
    #[test]
    fn wrong_port_on_an_admitted_host_explains_the_port_mismatch() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec!["93.184.216.34".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: "example.com".into(),
            port: 443,
        }]);
        let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

        let verdict = gate.decide_request("example.com:80");
        let EgressVerdict::Deny(reason) = verdict else {
            panic!("port 80 must be denied, got {verdict:?}");
        };
        assert_eq!(
            reason,
            DenyReason::PortNotAdmitted {
                host: "example.com".to_string(),
                port: 80,
                admitted_ports: vec![443],
            }
        );
        let rendered = reason.to_string();
        assert!(rendered.contains("example.com:80"), "{rendered}");
        assert!(rendered.contains("example.com:443"), "{rendered}");
    }

    /// A host absent from the allow-list is a different answer from a wrong
    /// port, and naming the admitted hosts is what turns it into one.
    #[test]
    fn unlisted_host_names_the_hosts_that_are_admitted() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec!["93.184.216.34".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: "example.com".into(),
            port: 443,
        }]);
        let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

        let verdict = gate.decide_request("evil.test:443");
        let EgressVerdict::Deny(reason) = verdict else {
            panic!("an unlisted host must be denied, got {verdict:?}");
        };
        assert_eq!(
            reason,
            DenyReason::HostNotAdmitted {
                host: "evil.test".to_string(),
                admitted_hosts: vec!["example.com".to_string()],
            }
        );
        assert!(reason.to_string().contains("example.com"));
    }

    /// ICMP has no port, so a host admitted for any port may be pinged. This is
    /// the decision that makes `--allow-host example.com` (meaning
    /// `example.com:443`) enough for `ping example.com`, without letting ping
    /// reach a host the allow-list never named.
    #[test]
    fn icmp_is_admitted_for_a_host_on_the_allow_list_whatever_its_port() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec!["93.184.216.34".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: "example.com".into(),
            port: 443,
        }]);
        let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

        assert_eq!(
            gate.decide_icmp_request("example.com"),
            EgressVerdict::Allow {
                ips: vec!["93.184.216.34".parse().unwrap()],
                port: 0,
            },
            "a host admitted on any port may be pinged"
        );

        // ...but ping never widens the destination set.
        let verdict = gate.decide_icmp_request("evil.test");
        let EgressVerdict::Deny(reason) = verdict else {
            panic!("an unlisted host must not be pingable, got {verdict:?}");
        };
        assert!(reason.to_string().contains("example.com"), "{reason}");
    }

    /// Mandatory-deny outranks the allow-list for echo exactly as it does for a
    /// stream, so an explicitly pinned loopback address cannot turn ping into a
    /// probe of the host's own networks.
    #[test]
    fn icmp_refuses_a_pinned_mandatory_deny_address() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "localhost.test",
            vec!["127.0.0.1".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: "localhost.test".into(),
            port: 443,
        }]);
        let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

        assert!(
            gate.decide_icmp_request("localhost.test").is_deny(),
            "a pinned loopback address must not be pingable"
        );
    }

    /// A deny-all workload cannot ping anything, and says so as a policy answer
    /// rather than an unknown-host one.
    #[test]
    fn icmp_on_a_deny_all_gate_reports_no_egress() {
        let gate = EgressGate::default_deny();
        let verdict = gate.decide_icmp_request("example.com");
        let EgressVerdict::Deny(reason) = verdict else {
            panic!("deny-all must refuse echo, got {verdict:?}");
        };
        assert_eq!(reason, DenyReason::NoEgressAdmitted);
    }

    #[test]
    fn default_deny_refuses_everything() {
        let gate = EgressGate::default_deny();
        assert!(gate.decide_request("1.1.1.1:443").is_deny());
        assert!(gate.decide_request("93.184.216.34:80").is_deny());
    }

    #[test]
    fn allow_list_permits_only_the_listed_destination() {
        let gate = EgressGate::new(CanonicalEgress::Rules(vec![allow_rule("1.1.1.1/32", 443)]));
        assert_eq!(
            gate.decide_request("1.1.1.1:443"),
            EgressVerdict::Allow {
                ips: vec!["1.1.1.1".parse().unwrap()],
                port: 443
            }
        );
        // Wrong port / wrong host → still denied.
        assert!(gate.decide_request("1.1.1.1:80").is_deny());
        assert!(gate.decide_request("8.8.8.8:443").is_deny());
    }

    #[test]
    fn ssh_flow_is_refused_even_when_listed() {
        // A grant that names port 22 must still be refused (claim-10 banned-SSH).
        let gate = EgressGate::new(CanonicalEgress::Rules(vec![allow_rule("1.1.1.1/32", 22)]));
        assert!(gate.decide_request("1.1.1.1:22").is_deny());
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
                ips: vec!["93.184.216.34".parse().unwrap()],
                port: 80
            }
        );
    }

    #[test]
    fn udp_decision_uses_udp_rules_without_widening_tcp() {
        let gate = EgressGate::new(CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Udp,
            net: "192.0.2.1/32".parse().unwrap(),
            port_lo: 5353,
            port_hi: 5353,
        }]));
        assert_eq!(
            gate.decide_udp_request("192.0.2.1:5353"),
            EgressVerdict::Allow {
                ips: vec!["192.0.2.1".parse().unwrap()],
                port: 5353,
            }
        );
        assert!(gate.decide_request("192.0.2.1:5353").is_deny());
    }

    #[test]
    fn unrestricted_hostname_without_pin_resolves_host_side() {
        let gate = EgressGate::new(CanonicalEgress::Unrestricted);
        let verdict = gate.decide_hostname_request(Proto::Tcp, "cache.nixos.org", 443, |_host| {
            Ok(vec!["151.101.1.91".parse().unwrap()])
        });
        assert_eq!(
            verdict,
            EgressVerdict::Allow {
                ips: vec!["151.101.1.91".parse().unwrap()],
                port: 443
            }
        );
    }

    #[test]
    fn pinned_allow_list_without_matching_pin_still_denies_hostname() {
        let gate = EgressGate::new(CanonicalEgress::Rules(vec![allow_rule(
            "151.101.1.91/32",
            443,
        )]));
        let verdict = gate.decide_hostname_request(Proto::Tcp, "cache.nixos.org", 443, |_host| {
            Ok(vec!["151.101.1.91".parse().unwrap()])
        });
        assert!(verdict.is_deny());
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
        assert!(
            EgressGate::new(deny)
                .decide_request("1.1.1.1:443")
                .is_deny()
        );

        let open = canonicalize_network_policy(&NetworkPolicy::unrestricted(), &pins, now).unwrap();
        assert_eq!(
            EgressGate::new(open).decide_request("93.184.216.34:80"),
            EgressVerdict::Allow {
                ips: vec!["93.184.216.34".parse().unwrap()],
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
        assert!(deny.decide_request("1.1.1.1:443").is_deny());

        let open = EgressGate::from_network_policy(&NetworkPolicy::unrestricted(), &pins, now);
        assert_eq!(
            open.decide_request("93.184.216.34:80"),
            EgressVerdict::Allow {
                ips: vec!["93.184.216.34".parse().unwrap()],
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
        assert!(gate.decide_request("93.184.216.34:443").is_deny());
    }

    /// An IP-host allow-list with the matching pin admits exactly that
    /// destination — the supervisor's resolved-pin path (a literal IP "resolves"
    /// to itself).
    #[test]
    fn ip_allow_list_with_pin_admits_only_that_destination() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let now = "2026-01-01T00:00:00Z";
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "192.168.4.23",
            vec!["192.168.4.23".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: "192.168.4.23".into(),
            port: 19099,
        }]);
        let gate = EgressGate::from_network_policy(&policy, &pins, now);
        assert_eq!(
            gate.decide_request("192.168.4.23:19099"),
            EgressVerdict::Allow {
                ips: vec!["192.168.4.23".parse().unwrap()],
                port: 19099
            }
        );
        assert!(gate.decide_request("192.168.4.23:80").is_deny());
        assert!(gate.decide_request("8.8.8.8:19099").is_deny());
    }

    /// DNS-over-vsock: a `socks5h` client sends a *hostname*; the gate resolves it
    /// host-side against the pin registry, admits the pinned IP only for the
    /// policy-allowed port, and refuses unknown names / wrong ports / non-IP-stack
    /// junk — all without the guest ever resolving anything.
    #[test]
    fn hostname_request_resolved_host_side_against_pins() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let now = "2026-01-01T00:00:00Z";
        let pinned: IpAddr = "93.184.216.34".parse().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "api.example.test",
            vec![pinned],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: "api.example.test".into(),
            port: 443,
        }]);
        let gate = EgressGate::from_network_policy(&policy, &pins, now);

        // hostname:port → resolved + admitted to the pinned IP.
        assert_eq!(
            gate.decide_request("api.example.test:443"),
            EgressVerdict::Allow {
                ips: vec![pinned],
                port: 443
            }
        );
        // right host, disallowed port → deny.
        assert!(gate.decide_request("api.example.test:80").is_deny());
        // unknown host (no pin) → deny, not malformed.
        assert!(gate.decide_request("evil.example.test:443").is_deny());
        // unparseable → malformed.
        assert_eq!(
            gate.decide_request("not-a-target"),
            EgressVerdict::Malformed
        );
        // the pinned IP directly still works (numeric path).
        assert_eq!(
            gate.decide_request("93.184.216.34:443"),
            EgressVerdict::Allow {
                ips: vec![pinned],
                port: 443
            }
        );
    }

    #[test]
    fn admitted_ips_keeps_only_permitted_and_orders_ipv4_first() {
        let egress = CanonicalEgress::Rules(vec![
            allow_rule("93.184.216.34/32", 443),
            allow_rule("2606:2800:220:1:248:1893:25c8:1946/128", 443),
        ]);
        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        let v6: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        let unlisted: IpAddr = "8.8.8.8".parse().unwrap();

        // Resolver order is v6-first (as a dual-stack host often returns); the
        // unlisted address is dropped and the admitted set is reordered v4-first.
        let got = admitted_ips(&egress, &Proto::Tcp, &[v6, unlisted, v4], 443);
        assert_eq!(got, vec![v4, v6]);

        // Wrong port admits nothing.
        assert!(admitted_ips(&egress, &Proto::Tcp, &[v4, v6], 80).is_empty());
    }

    #[test]
    fn hostname_request_returns_all_admitted_ips_ipv4_first() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let v6: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec![v6, v4],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]);
        let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

        match gate.decide_request("example.com:443") {
            EgressVerdict::Allow { ips, port } => {
                assert_eq!(ips, vec![v4, v6]);
                assert_eq!(port, 443);
            }
            EgressVerdict::Deny(_) | EgressVerdict::Malformed => panic!("expected allow"),
        }
        assert!(gate.decide_request("example.com:80").is_deny());
    }

    /// A guest that resolved a dual-stack pinned host locally (macOS getaddrinfo
    /// returns IPv6 first, so the guest picks it) and connects to the *numeric*
    /// IPv6 target must still be handed the pinned IPv4 sibling — IPv4 first — so
    /// the host connect falls over to IPv4 when the IPv6 route is unreachable
    /// instead of stranding on the lone IPv6.
    #[test]
    fn numeric_pinned_ipv6_target_offers_ipv4_sibling_for_fallover() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let v6: IpAddr = "2606:4700:10::6814:179a".parse().unwrap();
        let v4: IpAddr = "104.20.23.154".parse().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec![v6, v4],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let gate = EgressGate::from_network_policy(
            &NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]),
            &pins,
            "2026-01-01T00:00:00Z",
        );

        // The guest connects to the numeric IPv6 address it resolved.
        match gate.decide_request("[2606:4700:10::6814:179a]:443") {
            EgressVerdict::Allow { ips, port } => {
                assert_eq!(port, 443);
                assert_eq!(
                    ips,
                    vec![v4, v6],
                    "numeric IPv6 connect must offer the pinned IPv4 sibling first"
                );
            }
            EgressVerdict::Deny(_) | EgressVerdict::Malformed => {
                panic!("expected Allow with fallover candidates")
            }
        }
    }

    #[test]
    fn literal_ipv4_target_offers_pinned_ipv6_sibling() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let v6: IpAddr = "2606:4700:10::6814:179a".parse().unwrap();
        let v4: IpAddr = "104.20.23.154".parse().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec![v6, v4],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]);
        let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

        assert_eq!(
            gate.decide_request("104.20.23.154:443"),
            EgressVerdict::Allow {
                ips: vec![v4, v6],
                port: 443,
            }
        );
    }

    #[test]
    fn literal_shared_ip_uses_lowest_dest_pin_for_fallback() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let shared_v6: IpAddr = "2606:4700:10::6814:179a".parse().unwrap();
        let alpha_v4: IpAddr = "104.20.0.1".parse().unwrap();
        let zebra_v4: IpAddr = "104.20.0.2".parse().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "zebra.example",
            vec![shared_v6, zebra_v4],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        pins.add(DnsPin::at(
            "alpha.example",
            vec![shared_v6, alpha_v4],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![
            HostPort::new("alpha.example", 443),
            HostPort::new("zebra.example", 443),
        ]);
        let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

        assert_eq!(
            gate.decide_request("[2606:4700:10::6814:179a]:443"),
            EgressVerdict::Allow {
                ips: vec![alpha_v4, shared_v6],
                port: 443,
            }
        );
    }

    #[test]
    fn dns_verdict_uses_pin_without_upstream_lookup() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::protocol::dns::DnsRecordType;

        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        let v6: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec![v6, v4],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let gate = EgressGate::from_network_policy(
            &NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]),
            &pins,
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(
            gate.dns_verdict("example.com", DnsRecordType::A, |_| {
                panic!("pinned names must not reach upstream DNS")
            }),
            DnsVerdict::Resolved(vec![v4])
        );
        assert_eq!(
            gate.dns_verdict("example.com", DnsRecordType::Aaaa, |_| {
                panic!("pinned names must not reach upstream DNS")
            }),
            DnsVerdict::Resolved(vec![v6])
        );
    }

    #[test]
    fn dns_verdict_refuses_unadmitted_name_without_lookup() {
        use mvm_core::protocol::dns::DnsRecordType;

        let gate = EgressGate::default_deny();
        assert_eq!(
            gate.dns_verdict("evil.test", DnsRecordType::A, |_| {
                panic!("unadmitted names must not reach upstream DNS")
            }),
            DnsVerdict::Refused
        );
    }

    #[test]
    fn dns_verdict_filters_unrestricted_rebinding_answers() {
        use mvm_core::protocol::dns::DnsRecordType;

        let gate = EgressGate::new(CanonicalEgress::Unrestricted);
        assert_eq!(
            gate.dns_verdict("host.test", DnsRecordType::A, |_| {
                Ok(vec![
                    "93.184.216.34".parse().unwrap(),
                    "10.1.2.3".parse().unwrap(),
                ])
            }),
            DnsVerdict::Resolved(vec!["93.184.216.34".parse().unwrap()])
        );
    }

    #[test]
    fn dns_verdict_keeps_explicit_private_pin() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::protocol::dns::DnsRecordType;

        let private: IpAddr = "192.168.4.23".parse().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "192.168.4.23",
            vec![private],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let gate = EgressGate::from_network_policy(
            &NetworkPolicy::allow_list(vec![HostPort::new("192.168.4.23", 19099)]),
            &pins,
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(
            gate.dns_verdict("192.168.4.23", DnsRecordType::A, |_| {
                panic!("explicit pins must not reach upstream DNS")
            }),
            DnsVerdict::Resolved(vec![private])
        );
    }

    #[test]
    fn dns_verdict_refuses_upstream_failure() {
        use mvm_core::protocol::dns::DnsRecordType;

        let gate = EgressGate::new(CanonicalEgress::Unrestricted);
        assert_eq!(
            gate.dns_verdict("missing.test", DnsRecordType::A, |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no records",
                ))
            }),
            DnsVerdict::Refused
        );
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;

    fn peer(name: &str, port: u16, host_addr: &str, host_port: u16) -> PeerBinding {
        PeerBinding {
            name: PeerName::parse(name).expect("valid peer name"),
            port,
            host_addr: host_addr.into(),
            host_port,
        }
    }

    fn gate_with(peers: Vec<PeerBinding>) -> EgressGate {
        EgressGate::default_deny().with_peers(peers)
    }

    #[test]
    fn a_bound_route_resolves_to_the_peers_admitted_ingress_address() {
        let gate = gate_with(vec![peer("db.mvm.peer", 5432, "127.0.0.1", 34567)]);
        assert_eq!(
            gate.decide_peer("db.mvm.peer", 5432),
            EgressVerdict::Allow {
                ips: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
                port: 34567,
            }
        );
    }

    /// The whole posture in one test: a gate that admits no peer admits no
    /// peer. East-west inherits claim-10's default rather than having its own.
    #[test]
    fn a_gate_with_no_peer_bindings_admits_nothing() {
        let gate = EgressGate::default_deny();
        let verdict = gate.decide_peer("db.mvm.peer", 5432);
        assert!(matches!(verdict, EgressVerdict::Deny(_)));
        if let EgressVerdict::Deny(reason) = verdict {
            assert!(reason.to_string().contains("no peers are admitted"));
        }
    }

    /// A binding authorizes one route. The same peer on another port is a
    /// destination nobody signed for.
    #[test]
    fn a_bound_peer_on_an_unbound_port_is_refused() {
        let gate = gate_with(vec![peer("db.mvm.peer", 5432, "127.0.0.1", 34567)]);
        let verdict = gate.decide_peer("db.mvm.peer", 5433);
        assert!(matches!(verdict, EgressVerdict::Deny(_)));
        if let EgressVerdict::Deny(reason) = verdict {
            let rendered = reason.to_string();
            assert!(rendered.contains("db.mvm.peer:5433"));
            assert!(
                rendered.contains("db.mvm.peer:5432"),
                "refusal names the route that is admitted"
            );
        }
    }

    #[test]
    fn an_unbound_peer_name_is_refused_and_the_refusal_lists_what_is_admitted() {
        let gate = gate_with(vec![peer("db.mvm.peer", 5432, "127.0.0.1", 34567)]);
        let verdict = gate.decide_peer("cache.mvm.peer", 5432);
        if let EgressVerdict::Deny(reason) = verdict {
            assert!(reason.to_string().contains("db.mvm.peer:5432"));
        } else {
            panic!("an unbound peer must be denied");
        }
    }

    /// A malformed peer target reaches this decision (the branch is claimed on
    /// suffix alone) and must not be admitted or handed onward.
    #[test]
    fn a_malformed_peer_name_is_malformed_not_allowed() {
        let gate = gate_with(vec![peer("db.mvm.peer", 5432, "127.0.0.1", 34567)]);
        assert_eq!(
            gate.decide_peer("-db.mvm.peer", 5432),
            EgressVerdict::Malformed
        );
    }

    /// Peer routes and ordinary egress are separate namespaces. Admitting a
    /// peer must not widen what the host-name path allows.
    #[test]
    fn a_peer_binding_does_not_widen_ordinary_egress() {
        let gate = gate_with(vec![peer("db.mvm.peer", 5432, "127.0.0.1", 34567)]);
        assert!(matches!(
            gate.decide_request("db.mvm.peer:5432"),
            EgressVerdict::Deny(_) | EgressVerdict::Malformed
        ));
        assert!(matches!(
            gate.decide_request("127.0.0.1:34567"),
            EgressVerdict::Deny(_) | EgressVerdict::Malformed
        ));
    }

    /// The first matching binding wins, deterministically, so a duplicated
    /// name cannot make resolution depend on iteration order.
    #[test]
    fn the_first_matching_binding_wins() {
        let gate = gate_with(vec![
            peer("db.mvm.peer", 5432, "127.0.0.1", 1111),
            peer("db.mvm.peer", 5432, "127.0.0.1", 2222),
        ]);
        assert_eq!(
            gate.decide_peer("db.mvm.peer", 5432),
            EgressVerdict::Allow {
                ips: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
                port: 1111,
            }
        );
    }
}

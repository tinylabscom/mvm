//! Raw-L3 egress decision gate for the host-forwarded packet tunnel.
//!
//! The guest hands the host raw IPv4 packets over the network tunnel. Before
//! any of them can leave the host, each destination has to be checked against
//! the admitted [`NetworkPolicy`] projected onto the concrete IP set the
//! admission-time DNS resolver pinned. This module owns that decision: parse a
//! packet's destination, look the `(ip, port)` pair up in a precomputed
//! allow-set, and return allow/drop. It performs no I/O and forwards nothing —
//! the forwarding data path lands in a later slice; today allowed packets are
//! only counted and audited.
//!
//! Fail-closed is the rule throughout: an unparseable packet, an unpinned
//! destination host, or a destination with no IPv4 pin all resolve to drop.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use mvm_core::policy::dns_pin::DnsPinRegistry;
use mvm_core::policy::network_policy::NetworkPolicy;
use serde::{Deserialize, Serialize};

/// IPv4 protocol number for TCP.
const IP_PROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
const IP_PROTO_UDP: u8 = 17;
/// Minimum IPv4 header length in bytes (no options).
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Why a guest packet was denied egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum L3DropReason {
    /// The bytes weren't a well-formed IPv4 packet we could inspect.
    Unparseable,
    /// The destination IP is not pinned by any admitted host.
    UnpinnedDst,
    /// The destination IP is pinned, but not on this destination port.
    PortNotAllowed,
}

/// Outcome of gating a single guest packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3Decision {
    /// The destination is admitted; the packet may egress.
    Allow,
    /// The packet is denied for the given reason.
    Drop(L3DropReason),
}

/// Serde-facing shape of an [`L3ForwardPolicy`]. The precomputed allow-set is
/// derived from these two inputs, so only they cross the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct L3ForwardPolicyWire {
    policy: NetworkPolicy,
    pins: DnsPinRegistry,
}

/// Admitted-policy gate that decides whether a guest IPv4 packet may egress.
///
/// Constructed from the admitted [`NetworkPolicy`] plus the admission-time
/// [`DnsPinRegistry`]. The allow-set is precomputed once: for every admitted
/// `host:port` rule, every IPv4 the registry pinned for that host contributes
/// an `(ip, port)` pair. A host with no pin contributes nothing — fail-closed.
/// An unrestricted policy resolves to no rules and therefore an empty allow-set
/// (this gate only ever admits explicitly pinned destinations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "L3ForwardPolicyWire", from = "L3ForwardPolicyWire")]
pub struct L3ForwardPolicy {
    policy: NetworkPolicy,
    pins: DnsPinRegistry,
    /// `(dst_ip, dst_port)` pairs admitted for port-bearing protocols.
    allow_ip_port: HashSet<(Ipv4Addr, u16)>,
    /// Every admitted dst IP, on any admitted port. Used for portless
    /// protocols (e.g. ICMP), which are gated on destination IP alone.
    allow_ip_any: HashSet<Ipv4Addr>,
}

impl L3ForwardPolicy {
    /// Build the gate, precomputing the allow-set from the admitted policy's
    /// rules projected onto their pinned IPv4 addresses.
    pub fn new(policy: NetworkPolicy, pins: DnsPinRegistry) -> Self {
        let mut allow_ip_port = HashSet::new();
        let mut allow_ip_any = HashSet::new();
        if let Some(rules) = policy.resolve_rules() {
            for rule in &rules {
                let Some(pin) = pins.lookup(&rule.host) else {
                    continue;
                };
                for ip in &pin.ips {
                    if let IpAddr::V4(v4) = ip {
                        allow_ip_port.insert((*v4, rule.port));
                        allow_ip_any.insert(*v4);
                    }
                }
            }
        }
        Self {
            policy,
            pins,
            allow_ip_port,
            allow_ip_any,
        }
    }

    /// Decide a destination + optional L4 port against the allow-set.
    ///
    /// Port-bearing protocols (TCP/UDP) match on the exact `(ip, port)` pair.
    /// Portless protocols (`dst_port == None`, e.g. ICMP) are admitted when the
    /// destination IP is pinned on any admitted port. `proto` is retained for
    /// call-site clarity and future per-protocol policy; the decision keys on
    /// destination IP and port today.
    pub fn decide(&self, dst: Ipv4Addr, _proto: u8, dst_port: Option<u16>) -> L3Decision {
        match dst_port {
            Some(port) => {
                if self.allow_ip_port.contains(&(dst, port)) {
                    L3Decision::Allow
                } else if self.allow_ip_any.contains(&dst) {
                    L3Decision::Drop(L3DropReason::PortNotAllowed)
                } else {
                    L3Decision::Drop(L3DropReason::UnpinnedDst)
                }
            }
            None => {
                if self.allow_ip_any.contains(&dst) {
                    L3Decision::Allow
                } else {
                    L3Decision::Drop(L3DropReason::UnpinnedDst)
                }
            }
        }
    }

    /// Parse `packet` and decide it in one step. An unparseable packet is a
    /// drop with [`L3DropReason::Unparseable`].
    pub fn decide_packet(&self, packet: &[u8]) -> L3Decision {
        match parse_ipv4_dst_and_l4(packet) {
            Some((dst, proto, dst_port)) => self.decide(dst, proto, dst_port),
            None => L3Decision::Drop(L3DropReason::Unparseable),
        }
    }

    /// The admitted policy this gate was built from.
    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// The DNS pin registry this gate was built from.
    pub fn pins(&self) -> &DnsPinRegistry {
        &self.pins
    }
}

impl From<L3ForwardPolicyWire> for L3ForwardPolicy {
    fn from(wire: L3ForwardPolicyWire) -> Self {
        Self::new(wire.policy, wire.pins)
    }
}

impl From<L3ForwardPolicy> for L3ForwardPolicyWire {
    fn from(gate: L3ForwardPolicy) -> Self {
        Self {
            policy: gate.policy,
            pins: gate.pins,
        }
    }
}

/// Minimal, bounds-checked IPv4 destination + L4 parse.
///
/// Returns the destination address, the IP protocol number, and — for
/// TCP/UDP — the destination port. Every field is read only after a length
/// check, and anything that isn't a well-formed IPv4 packet (too short, wrong
/// version, truncated header, truncated L4 port) returns `None` so callers
/// fail closed.
pub fn parse_ipv4_dst_and_l4(packet: &[u8]) -> Option<(Ipv4Addr, u8, Option<u16>)> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    // High nibble is the IP version; must be 4.
    if packet[0] >> 4 != 4 {
        return None;
    }
    // Low nibble is IHL in 32-bit words; header is IHL*4 bytes, min 20.
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER_LEN || packet.len() < header_len {
        return None;
    }
    let proto = packet[9];
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let dst_port = match proto {
        IP_PROTO_TCP | IP_PROTO_UDP => {
            // Destination port is the second 16-bit field of the L4 header.
            let port_off = header_len + 2;
            let end = port_off.checked_add(2)?;
            if packet.len() < end {
                return None;
            }
            Some(u16::from_be_bytes([packet[port_off], packet[port_off + 1]]))
        }
        _ => None,
    };
    Some((dst, proto, dst_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::dns_pin::DnsPin;
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

    fn ipv4(s: &str) -> Ipv4Addr {
        s.parse().expect("ipv4 literal")
    }

    /// Gate admitting `api.example.com:443`, pinned to a single IPv4.
    fn gate_for(host: &str, port: u16, pinned_ips: &[&str]) -> L3ForwardPolicy {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new(host, port)]);
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            host,
            pinned_ips.iter().map(|s| ipv4(s).into()).collect(),
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        L3ForwardPolicy::new(policy, pins)
    }

    /// A minimal IPv4/TCP packet targeting `dst:dst_port`.
    fn ipv4_tcp(dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0_u8; 24];
        p[0] = 0x45; // version 4, IHL 5 (20-byte header)
        p[9] = IP_PROTO_TCP;
        p[16..20].copy_from_slice(&dst.octets());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn l3_gate_allows_pinned_ip_and_port() {
        let gate = gate_for("api.example.com", 443, &["93.184.216.34"]);
        assert_eq!(
            gate.decide(ipv4("93.184.216.34"), IP_PROTO_TCP, Some(443)),
            L3Decision::Allow
        );
        // Full-packet path agrees.
        assert_eq!(
            gate.decide_packet(&ipv4_tcp(ipv4("93.184.216.34"), 443)),
            L3Decision::Allow
        );
    }

    #[test]
    fn l3_gate_drops_unpinned_ip() {
        let gate = gate_for("api.example.com", 443, &["93.184.216.34"]);
        assert_eq!(
            gate.decide(ipv4("203.0.113.7"), IP_PROTO_TCP, Some(443)),
            L3Decision::Drop(L3DropReason::UnpinnedDst)
        );
    }

    #[test]
    fn l3_gate_drops_banned_port() {
        let gate = gate_for("api.example.com", 443, &["93.184.216.34"]);
        assert_eq!(
            gate.decide(ipv4("93.184.216.34"), IP_PROTO_TCP, Some(80)),
            L3Decision::Drop(L3DropReason::PortNotAllowed)
        );
    }

    #[test]
    fn l3_gate_portless_proto_allows_pinned_ip_on_any_port() {
        // ICMP has no port; a pinned dst IP is admitted on IP alone.
        let gate = gate_for("api.example.com", 443, &["93.184.216.34"]);
        assert_eq!(
            gate.decide(ipv4("93.184.216.34"), 1, None),
            L3Decision::Allow
        );
        assert_eq!(
            gate.decide(ipv4("203.0.113.7"), 1, None),
            L3Decision::Drop(L3DropReason::UnpinnedDst)
        );
    }

    #[test]
    fn l3_gate_multi_pin_admits_every_pinned_ip() {
        let gate = gate_for(
            "api.example.com",
            443,
            &["93.184.216.34", "104.18.7.42", "104.18.32.1"],
        );
        for ip in ["93.184.216.34", "104.18.7.42", "104.18.32.1"] {
            assert_eq!(
                gate.decide(ipv4(ip), IP_PROTO_TCP, Some(443)),
                L3Decision::Allow,
                "{ip} must be admitted"
            );
        }
    }

    #[test]
    fn l3_gate_host_without_pin_contributes_nothing() {
        // Admitted host, but the resolver never pinned it → fail closed.
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        let gate = L3ForwardPolicy::new(policy, DnsPinRegistry::new());
        assert_eq!(
            gate.decide(ipv4("93.184.216.34"), IP_PROTO_TCP, Some(443)),
            L3Decision::Drop(L3DropReason::UnpinnedDst)
        );
    }

    #[test]
    fn l3_gate_ipv6_pin_is_skipped_for_ipv4_gate() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("dns.google", 443)]);
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "dns.google",
            vec!["2001:4860:4860::8888".parse().expect("ipv6")],
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        let gate = L3ForwardPolicy::new(policy, pins);
        // No IPv4 pins → empty allow-set → everything drops.
        assert_eq!(
            gate.decide(ipv4("8.8.8.8"), IP_PROTO_TCP, Some(443)),
            L3Decision::Drop(L3DropReason::UnpinnedDst)
        );
    }

    #[test]
    fn l3_gate_decide_packet_unparseable_is_dropped() {
        let gate = gate_for("api.example.com", 443, &["93.184.216.34"]);
        // Too short to be an IPv4 header.
        assert_eq!(
            gate.decide_packet(&[1, 2, 3]),
            L3Decision::Drop(L3DropReason::Unparseable)
        );
    }

    #[test]
    fn parse_rejects_short_and_non_ipv4() {
        assert!(parse_ipv4_dst_and_l4(&[]).is_none());
        assert!(parse_ipv4_dst_and_l4(&[0x45; 19]).is_none()); // < 20 bytes
        let mut v6ish = vec![0_u8; 20];
        v6ish[0] = 0x60; // version 6
        assert!(parse_ipv4_dst_and_l4(&v6ish).is_none());
    }

    #[test]
    fn parse_rejects_bogus_ihl() {
        let mut p = vec![0_u8; 20];
        p[0] = 0x44; // version 4, IHL 4 → 16-byte header, below the 20 minimum
        assert!(parse_ipv4_dst_and_l4(&p).is_none());
    }

    #[test]
    fn parse_rejects_truncated_l4_port() {
        // Valid 20-byte IPv4/TCP header but no room for the ports.
        let mut p = vec![0_u8; 21];
        p[0] = 0x45;
        p[9] = IP_PROTO_TCP;
        assert!(parse_ipv4_dst_and_l4(&p).is_none());
    }

    #[test]
    fn parse_extracts_dst_proto_and_port() {
        let packet = ipv4_tcp(ipv4("93.184.216.34"), 443);
        let (dst, proto, port) = parse_ipv4_dst_and_l4(&packet).expect("parse");
        assert_eq!(dst, ipv4("93.184.216.34"));
        assert_eq!(proto, IP_PROTO_TCP);
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parse_portless_proto_has_no_port() {
        let mut p = vec![0_u8; 20];
        p[0] = 0x45;
        p[9] = 1; // ICMP
        p[16..20].copy_from_slice(&ipv4("93.184.216.34").octets());
        let (dst, proto, port) = parse_ipv4_dst_and_l4(&p).expect("parse");
        assert_eq!(dst, ipv4("93.184.216.34"));
        assert_eq!(proto, 1);
        assert_eq!(port, None);
    }

    #[test]
    fn l3_forward_policy_serde_roundtrip_rebuilds_allow_set() {
        let gate = gate_for("api.example.com", 443, &["93.184.216.34"]);
        let json = serde_json::to_string(&gate).expect("serialize");
        let parsed: L3ForwardPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, gate);
        // The precomputed allow-set survives the round-trip via reconstruction.
        assert_eq!(
            parsed.decide(ipv4("93.184.216.34"), IP_PROTO_TCP, Some(443)),
            L3Decision::Allow
        );
    }

    /// Whole-word substring match: the identifier must not be flanked by another
    /// identifier char, so `NetMessage` matches `NetMessage` but not
    /// `SomeNetMessageThing`.
    fn contains_word(haystack: &str, word: &str) -> bool {
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        haystack.match_indices(word).any(|(idx, _)| {
            let before = haystack[..idx].chars().next_back();
            let after = haystack[idx + word.len()..].chars().next();
            before.is_none_or(|c| !is_ident(c)) && after.is_none_or(|c| !is_ident(c))
        })
    }

    /// Keep only real data-plane code: drop the unit-test module (whose own
    /// allow-list names the banned identifiers on purpose) and line comments, so
    /// the scan can never trip on a fixture or a "we do NOT use X" note.
    fn strip_tests_and_comments(src: &str) -> String {
        let mut out = String::new();
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("mod tests") {
                break;
            }
            let code = line.split_once("//").map_or(line, |(head, _)| head);
            out.push_str(code);
            out.push('\n');
        }
        out
    }

    /// Guard: the raw-L3 packet-tunnel data plane must never grow a TLS-MITM /
    /// stream-substitution surface or re-import the old semantic `mvm-net`
    /// protocol (typed DnsQuery/TcpOpen messages, synthetic 198.19/16 DNS
    /// mapping). This forwards raw IPv4 packets gated by dst IP — nothing else.
    ///
    /// In scope: exactly the six data-plane sources below. The supervisor's
    /// separate HTTPS-terminating egress path legitimately uses `egress_ca` /
    /// `stream_transform`, so `supervisor/` is deliberately NOT scanned.
    #[test]
    fn l3_data_plane_has_no_mitm_or_semantic_protocol_symbols() {
        let manifest = env!("CARGO_MANIFEST_DIR"); // .../crates/mvm-hostd
        let files = [
            format!("{manifest}/src/net_l3.rs"),
            format!("{manifest}/src/host_tun.rs"),
            format!("{manifest}/src/network_tunnel.rs"),
            format!("{manifest}/src/bin/mvm-network-tunnel-worker.rs"),
            format!("{manifest}/../mvm-core/src/protocol/network_tunnel.rs"),
            format!("{manifest}/../mvm-backend/src/network_tunnel_spawn.rs"),
        ];
        // MITM / semantic-protocol identifiers the raw-L3 plane must never carry.
        let banned = [
            "TlsTransform",
            "EgressCa",
            "egress_ca",
            "StreamTransform",
            "stream_transform",
            "SyntheticDnsMap",
            "NetMessage",
        ];
        for path in &files {
            let src = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read data-plane source {path}: {e}"));
            let code = strip_tests_and_comments(&src);
            for word in &banned {
                assert!(
                    !contains_word(&code, word),
                    "banned MITM/semantic identifier `{word}` appeared in data-plane file {path}"
                );
            }
        }
    }

    #[test]
    fn guard_detects_a_planted_banned_identifier() {
        // Self-check the whole-word matcher the guard relies on.
        let planted = "let x: TlsTransform = build();";
        assert!(contains_word(planted, "TlsTransform"));
        assert!(!contains_word("let net_message = 1;", "NetMessage"));
        assert!(!contains_word("egress_carrier", "egress_ca"));
    }
}

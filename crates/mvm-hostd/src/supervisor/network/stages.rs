//! Plan 129 egress-proxy seams (plan 123 Phase A / A3): two pluggable stages
//! on the per-packet egress path. **No-op by default** — Plan 129 supplies the
//! real handlers later. These are designed to run *inside*
//! `run_packet_pipeline` (the claim-10 egress chokepoint every guest byte
//! transits), so they are never a bypass.
//!
//! A3.1 (this) introduces the seam: the traits + no-op defaults. A3.2 wires
//! them into the pipeline runner + the gateway bridge (substitution maps to the
//! existing `Verdict::Modify` rebuild path; a scan `Drop` maps to the same
//! fail-closed kill the observers use).

use mvm_core::network_policy::{NetworkPolicy, is_mandatory_deny};

use crate::supervisor::network::packet::{L4Proto, ParsedPacket};
use crate::supervisor::network::{FlowDirection, PacketCtx};

/// Outcome of the scan stage. `Pass` forwards the packet; `Drop` kills the
/// flow — the same fail-closed path as `Verdict::Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    Pass,
    Drop,
}

/// Rewrites outbound L4 payload bytes when a secret binding applies (Plan 129
/// substitution). The default is pass-through.
pub trait SubstitutionStage: Send + Sync {
    /// Stable identifier for audit / metrics.
    fn name(&self) -> &'static str;

    /// Return `Some(new_payload)` to rewrite the outbound L4 payload, or `None`
    /// to pass it through unchanged.
    fn substitute(&self, _ctx: &PacketCtx<'_>, _pkt: &ParsedPacket<'_>) -> Option<Vec<u8>> {
        None
    }
}

/// Observes the outbound payload and may request a drop (Plan 129 leak-scan).
/// The default observes nothing and always passes.
pub trait ScanStage: Send + Sync {
    /// Stable identifier for audit / metrics.
    fn name(&self) -> &'static str;

    fn scan(&self, _ctx: &PacketCtx<'_>, _pkt: &ParsedPacket<'_>) -> ScanOutcome {
        ScanOutcome::Pass
    }
}

/// Default no-op substitution: never rewrites.
pub struct NoopSubstitution;

impl SubstitutionStage for NoopSubstitution {
    fn name(&self) -> &'static str {
        "noop-substitution"
    }
}

/// Default no-op scan: never drops.
pub struct NoopScan;

impl ScanStage for NoopScan {
    fn name(&self) -> &'static str {
        "noop-scan"
    }
}

/// DNS sink-hole scan (plan 123 A4): inspects outbound UDP/53 queries and drops
/// any whose queried host is outside the tenant allow-list. A dropped query is
/// sink-holed — the guest's resolver gets no answer — and, because the drop runs
/// inside `run_packet_pipeline`, the kill is recorded on the chain-signed flow
/// audit (the claim-10 egress chokepoint, so never a bypass).
///
/// Only UDP/53 is inspected; every other packet passes untouched (least
/// privilege). An unparseable DNS message also passes: a parse failure must not
/// silently widen policy, and the L3/L4 default-deny still gates the flow either
/// way. `allowed_suffixes` matches the query name as an exact host or a dotted
/// suffix — `corp.internal` admits `corp.internal` and `db.corp.internal`, never
/// `evilcorp.internal`.
pub struct DnsSinkholeScan {
    allowed_suffixes: Vec<String>,
}

impl DnsSinkholeScan {
    pub fn new(allowed_suffixes: Vec<String>) -> Self {
        Self {
            allowed_suffixes: allowed_suffixes
                .into_iter()
                .map(|s| s.trim_matches('.').to_ascii_lowercase())
                .collect(),
        }
    }

    fn is_allowed(&self, qname: &str) -> bool {
        let q = qname.trim_matches('.').to_ascii_lowercase();
        self.allowed_suffixes
            .iter()
            .any(|suffix| q == *suffix || q.ends_with(&format!(".{suffix}")))
    }
}

impl ScanStage for DnsSinkholeScan {
    fn name(&self) -> &'static str {
        "dns-sinkhole"
    }

    fn scan(&self, _ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> ScanOutcome {
        // Only DNS over UDP/53 is policy-checked; everything else passes.
        if pkt.five_tuple.proto != L4Proto::Udp || pkt.five_tuple.dst_port != 53 {
            return ScanOutcome::Pass;
        }
        match dns_query_qname(pkt.l4_payload) {
            // Sink-hole a denied host; an allowed (or unparseable) query passes.
            Some(qname) if !self.is_allowed(&qname) => ScanOutcome::Drop,
            _ => ScanOutcome::Pass,
        }
    }
}

/// Extract the query name from a DNS message's first question, lowercased and
/// dot-joined (`www.example.com`). Returns `None` for anything that isn't a
/// well-formed query with at least one question — a short message, zero
/// questions, a compression pointer inside the qname (never valid in a
/// question), or a label that runs past the buffer. Queries do not compress the
/// question qname, so a straight label walk suffices; a pointer is refused
/// rather than chased.
fn dns_query_qname(payload: &[u8]) -> Option<String> {
    // 12-byte header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2).
    if payload.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([payload[4], payload[5]]) == 0 {
        return None; // qdcount == 0 → no question to read
    }
    let mut i = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *payload.get(i)? as usize;
        if len == 0 {
            break; // root label ends the qname
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer / reserved — not valid in a question
        }
        i += 1;
        let end = i.checked_add(len)?;
        labels.push(String::from_utf8_lossy(payload.get(i..end)?).to_ascii_lowercase());
        i = end;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

/// Host-side enforcement of the mandatory-deny egress ranges (link-local,
/// cloud-metadata `169.254.169.254`, …) as a `ScanStage` (plan 123 A2 /
/// claim 10). Drops any **egress** packet whose L3 destination is in
/// `mvm_core::network_policy::mandatory_deny_ranges()`, at the gateway-bridge
/// chokepoint every guest byte transits.
///
/// Defense-in-depth, not the primary control: the guest's `netinit` installs
/// the same ranges as kernel routes, but a compromised guest can delete those
/// routes — the host-side drop here can't be stripped from inside the guest.
/// Applies to every tenant regardless of the admitted policy (mandatory = not
/// opt-out), so it composes *under* any per-tenant allow-list scan. Ingress is
/// ignored: an ingress frame's L3 dst is the guest itself, not a remote host.
pub struct MandatoryDenyEgressScan;

impl ScanStage for MandatoryDenyEgressScan {
    fn name(&self) -> &'static str {
        "mandatory-deny-egress"
    }

    fn scan(&self, ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> ScanOutcome {
        match ctx.direction {
            FlowDirection::Egress => {}
            _ => return ScanOutcome::Pass,
        }
        if is_mandatory_deny(pkt.five_tuple.dst_ip) {
            ScanOutcome::Drop
        } else {
            ScanOutcome::Pass
        }
    }
}

/// Enforces a resolved [`NetworkPolicy`] on the egress packet path (plan 123 A2
/// / claim 10): the L4 allow-list backstop. `unrestricted` passes everything;
/// an allow-list (including `deny_all`, the empty list) passes only packets
/// whose `dst ip:port` matches an **IP-literal** rule and drops the rest —
/// fail-closed.
///
/// Hostname rules can't be matched here (an L4 packet carries no name), so they
/// match nothing and the packet drops. That's deliberate: hostname allow-listing
/// is the DNS layer's job ([`DnsSinkholeScan`] sink-holes denied lookups; DNS
/// pinning maps an allowed name to its IPs). This scan is the IP/port backstop
/// that catches a guest dialing a raw IP. Compose it *under*
/// [`MandatoryDenyEgressScan`] (mandatory-deny always wins) via a scan chain.
pub struct NetworkPolicyScan {
    policy: NetworkPolicy,
}

impl NetworkPolicyScan {
    pub fn new(policy: NetworkPolicy) -> Self {
        Self { policy }
    }
}

impl ScanStage for NetworkPolicyScan {
    fn name(&self) -> &'static str {
        "network-policy"
    }

    fn scan(&self, ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> ScanOutcome {
        match ctx.direction {
            FlowDirection::Egress => {}
            _ => return ScanOutcome::Pass,
        }
        let rules = match self.policy.resolve_rules() {
            None => return ScanOutcome::Pass, // unrestricted — no filtering
            Some(rules) => rules,
        };
        let dst_ip = pkt.five_tuple.dst_ip;
        let dst_port = pkt.five_tuple.dst_port;
        // An IP-literal rule matches when both the literal IP and the port equal
        // the packet's destination. Hostname rules never parse as an IP here, so
        // they match nothing — the packet drops (fail-closed).
        let allowed = rules.iter().any(|r| {
            r.port == dst_port
                && r.host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip == dst_ip)
        });
        if allowed {
            ScanOutcome::Pass
        } else {
            ScanOutcome::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::network::FlowDirection;
    use crate::supervisor::network::packet::{FiveTuple, L4Proto};
    use mvm_core::network_policy::{HostPort, NetworkPolicy};

    #[test]
    fn noop_stages_pass_through_and_never_drop() {
        let pkt = ParsedPacket {
            five_tuple: FiveTuple {
                proto: L4Proto::Tcp,
                src_ip: "10.0.0.2".parse().unwrap(),
                dst_ip: "1.1.1.1".parse().unwrap(),
                src_port: 5000,
                dst_port: 443,
            },
            l4_payload: b"hello-SECRET",
            raw_frame: b"hello-SECRET",
        };
        let ctx = PacketCtx {
            vm_name: "vm",
            tenant: "t",
            direction: FlowDirection::Egress,
            flow_id: "vm-egress",
        };
        // No binding applies → no rewrite; scan never drops. This is the
        // claim-10-safe default posture before Plan 129 plugs in real handlers.
        assert_eq!(NoopSubstitution.substitute(&ctx, &pkt), None);
        assert_eq!(NoopScan.scan(&ctx, &pkt), ScanOutcome::Pass);
    }

    fn egress_ctx() -> PacketCtx<'static> {
        PacketCtx {
            vm_name: "vm",
            tenant: "t",
            direction: FlowDirection::Egress,
            flow_id: "vm-egress",
        }
    }

    /// A UDP/53 packet carrying `payload` as its DNS message.
    fn dns_packet(payload: &[u8]) -> ParsedPacket<'_> {
        ParsedPacket {
            five_tuple: FiveTuple {
                proto: L4Proto::Udp,
                src_ip: "10.0.0.2".parse().unwrap(),
                dst_ip: "1.1.1.1".parse().unwrap(),
                src_port: 5353,
                dst_port: 53,
            },
            l4_payload: payload,
            raw_frame: payload,
        }
    }

    /// A minimal well-formed DNS standard query (1 question, A/IN) for `name`.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut m = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: standard query, RD set
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0); // root label terminates the qname
        m.extend_from_slice(&[0x00, 0x01]); // qtype A
        m.extend_from_slice(&[0x00, 0x01]); // qclass IN
        m
    }

    #[test]
    fn dns_sinkhole_drops_a_denied_lookup() {
        // A4: a DNS query (UDP/53) for a host outside the allow-list is dropped
        // at the egress chokepoint — sink-holed — instead of being resolved.
        let query = dns_query("tracker.evil.example");
        let pkt = dns_packet(&query);
        let scan = DnsSinkholeScan::new(vec!["corp.internal".to_string()]);
        assert_eq!(scan.scan(&egress_ctx(), &pkt), ScanOutcome::Drop);
    }

    #[test]
    fn dns_sinkhole_allows_an_exact_or_subdomain_host() {
        let scan = DnsSinkholeScan::new(vec!["corp.internal".to_string()]);
        for host in ["corp.internal", "db.corp.internal"] {
            let q = dns_query(host);
            assert_eq!(
                scan.scan(&egress_ctx(), &dns_packet(&q)),
                ScanOutcome::Pass,
                "{host} is within the allow-list"
            );
        }
    }

    #[test]
    fn dns_sinkhole_rejects_a_suffix_lookalike() {
        // The allow-list match is dotted-suffix, not raw `ends_with`: a lookalike
        // registrable domain that merely ends in the allowed string is denied.
        let scan = DnsSinkholeScan::new(vec!["corp.internal".to_string()]);
        let q = dns_query("evilcorp.internal");
        assert_eq!(scan.scan(&egress_ctx(), &dns_packet(&q)), ScanOutcome::Drop);
    }

    #[test]
    fn dns_sinkhole_passes_non_dns_traffic() {
        // Only UDP/53 is inspected; a TCP/443 flow (and any non-53 UDP) passes
        // untouched — the scan never widens beyond DNS.
        let scan = DnsSinkholeScan::new(vec!["corp.internal".to_string()]);
        let tcp = ParsedPacket {
            five_tuple: FiveTuple {
                proto: L4Proto::Tcp,
                src_ip: "10.0.0.2".parse().unwrap(),
                dst_ip: "1.1.1.1".parse().unwrap(),
                src_port: 5000,
                dst_port: 443,
            },
            l4_payload: b"not-dns",
            raw_frame: b"not-dns",
        };
        assert_eq!(scan.scan(&egress_ctx(), &tcp), ScanOutcome::Pass);
    }

    #[test]
    fn dns_sinkhole_passes_unparseable_dns() {
        // A truncated / malformed DNS message fails open (passes): a parse
        // failure must not silently drop, and the L3/L4 default-deny still gates
        // the flow. Empty allow-list → everything would be denied if parsed, so
        // this also proves the parse guard runs before the policy check.
        let scan = DnsSinkholeScan::new(vec![]);
        let truncated = dns_packet(b"\x12\x34\x01");
        assert_eq!(scan.scan(&egress_ctx(), &truncated), ScanOutcome::Pass);
    }

    fn ingress_ctx() -> PacketCtx<'static> {
        PacketCtx {
            vm_name: "vm",
            tenant: "t",
            direction: FlowDirection::Ingress,
            flow_id: "vm-ingress",
        }
    }

    /// A TCP packet to `dst_ip:dst_port` with an empty payload.
    fn tcp_packet(dst_ip: std::net::IpAddr, dst_port: u16) -> ParsedPacket<'static> {
        ParsedPacket {
            five_tuple: FiveTuple {
                proto: L4Proto::Tcp,
                src_ip: "10.0.0.2".parse().unwrap(),
                dst_ip,
                src_port: 5000,
                dst_port,
            },
            l4_payload: b"",
            raw_frame: b"",
        }
    }

    #[test]
    fn mandatory_deny_drops_egress_to_metadata_ip() {
        // Host-side defense-in-depth: the cloud-metadata IP (link-local
        // 169.254.0.0/16) is always denied at the gateway chokepoint, whatever
        // the tenant policy. The guest-side netinit route-deny is strippable by
        // a compromised guest; this host-side drop is not.
        let pkt = tcp_packet("169.254.169.254".parse().unwrap(), 80);
        assert_eq!(
            MandatoryDenyEgressScan.scan(&egress_ctx(), &pkt),
            ScanOutcome::Drop
        );
    }

    #[test]
    fn mandatory_deny_passes_egress_to_public_ip() {
        let pkt = tcp_packet("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(
            MandatoryDenyEgressScan.scan(&egress_ctx(), &pkt),
            ScanOutcome::Pass
        );
    }

    #[test]
    fn mandatory_deny_ignores_ingress() {
        // Egress-only: an ingress frame's L3 dst is the guest, not a remote
        // host, so the mandatory-deny ranges don't apply. Constructed with a
        // metadata dst to prove the direction gate (not the IP check) is what
        // lets it pass.
        let pkt = tcp_packet("169.254.169.254".parse().unwrap(), 80);
        assert_eq!(
            MandatoryDenyEgressScan.scan(&ingress_ctx(), &pkt),
            ScanOutcome::Pass
        );
    }

    #[test]
    fn network_policy_deny_all_drops_every_egress() {
        // deny_all resolves to an empty allow-list → nothing matches → every
        // egress packet drops. The strictest claim-10 posture.
        let scan = NetworkPolicyScan::new(NetworkPolicy::deny_all());
        let pkt = tcp_packet("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(scan.scan(&egress_ctx(), &pkt), ScanOutcome::Drop);
    }

    #[test]
    fn network_policy_unrestricted_passes_egress() {
        let scan = NetworkPolicyScan::new(NetworkPolicy::unrestricted());
        let pkt = tcp_packet("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(scan.scan(&egress_ctx(), &pkt), ScanOutcome::Pass);
    }

    #[test]
    fn network_policy_allow_list_passes_matching_ip_literal() {
        let scan = NetworkPolicyScan::new(NetworkPolicy::allow_list(vec![HostPort::new(
            "1.2.3.4", 443,
        )]));
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.2.3.4".parse().unwrap(), 443)),
            ScanOutcome::Pass
        );
        // Same IP, different port → no rule matches → drop (fail-closed).
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.2.3.4".parse().unwrap(), 80)),
            ScanOutcome::Drop
        );
        // Different IP → drop.
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("9.9.9.9".parse().unwrap(), 443)),
            ScanOutcome::Drop
        );
    }

    #[test]
    fn network_policy_allow_list_hostname_rule_drops_fail_closed() {
        // A hostname rule can't be matched at L4 (the packet has no name), so it
        // matches nothing and the packet drops. Hostname allow-listing is the
        // DNS layer's job; this L4 scan must never fail *open* on a name it
        // can't resolve.
        let scan = NetworkPolicyScan::new(NetworkPolicy::allow_list(vec![HostPort::new(
            "api.example.com",
            443,
        )]));
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.2.3.4".parse().unwrap(), 443)),
            ScanOutcome::Drop
        );
    }

    #[test]
    fn network_policy_ignores_ingress() {
        // Egress-only: an ingress frame's L3 dst is the guest, not a remote
        // host. deny_all would drop everything if it ran on ingress; the
        // direction gate is what lets this pass.
        let scan = NetworkPolicyScan::new(NetworkPolicy::deny_all());
        let pkt = tcp_packet("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(scan.scan(&ingress_ctx(), &pkt), ScanOutcome::Pass);
    }
}

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

use std::sync::Arc;

use mvm_core::network_policy::{NetworkPolicy, is_mandatory_deny};

use crate::keyholder::substitution::PLACEHOLDER_PREFIX;
use crate::supervisor::network::packet::{L4Proto, ParsedPacket};
use crate::supervisor::network::{FlowDirection, PacketCtx};
use crate::supervisor::pii_redactor::{PiiRedactor, REDACTION_MASK};
use crate::supervisor::proxy::l4::{L4Decision, L4Policy, Protocol};
use crate::supervisor::secrets_scanner::SecretsScanner;

/// Outcome of the scan stage. `Pass` forwards the packet; `Drop` kills the
/// flow — the same fail-closed path as `Verdict::Drop`. `by` names the scan that
/// dropped (its [`ScanStage::name`]); the pipeline carries it into the
/// `gateway.flow_observer_fault` audit entry so the chain log records the actual
/// enforcement (`dns-sinkhole` / `l4-policy` / `mandatory-deny-egress`) rather
/// than the generic chain wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    Pass,
    Drop { by: &'static str },
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

/// Plan 129 Phase E — the egress secret/PII redactor. A `SubstitutionStage`
/// (the `Verdict::Modify` rebuild path), **not** a scan/drop: an *undeclared*
/// secret-shaped or PII run on outbound bytes is masked in place (replaced with
/// [`REDACTION_MASK`]) and the request continues, rather than dropping the whole
/// flow. This is the backstop for the no-secret-on-the-guest invariant when a
/// secret reaches the guest by some path *other* than a declared
/// `mvm.secret(...)` (baked in, hardcoded, fetched) — declared secrets are
/// substituted host-side via the endpoint and never on the guest in the first
/// place. (A leaked *placeholder* is still dropped by [`PlaceholderLeakScan`] —
/// that's a host/transport bug, fail-closed; a raw secret-shaped blob is a
/// workload mistake, mask-and-continue.)
pub struct RedactingSubstitution {
    secrets: SecretsScanner,
    pii: PiiRedactor,
}

/// The rule categories that fired during a [`RedactingSubstitution::redact_bytes`]
/// pass — secret-pattern names then PII-rule names. Names only, never the matched
/// bytes (claim-13 discipline), so this is safe to carry into an audit entry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RedactionHits {
    pub secrets: Vec<&'static str>,
    pub pii: Vec<&'static str>,
}

impl RedactionHits {
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.pii.is_empty()
    }

    /// Fold another pass's categories in (used when redacting several fields —
    /// e.g. each header value + the body — of one request).
    pub fn merge(&mut self, other: RedactionHits) {
        self.secrets.extend(other.secrets);
        self.pii.extend(other.pii);
    }
}

impl RedactingSubstitution {
    /// The curated secret-pattern + PII rulesets (`DEFAULT_RULES`).
    pub fn with_default_rules() -> Self {
        Self {
            secrets: SecretsScanner::with_default_rules(),
            pii: PiiRedactor::with_default_rules(),
        }
    }

    /// Mask undeclared secret-shaped + PII runs in `payload`, returning the
    /// rewritten bytes and the categories that fired. Returns `None` when the
    /// payload is clean (the caller forwards it unchanged). Secret-shaped first,
    /// then PII; both mask to [`REDACTION_MASK`].
    ///
    /// This is the single redaction definition shared by both host-side egress
    /// chokepoints — the packet-level gateway bridge (`substitute`, libkrun/FC)
    /// and the request-level substitution endpoint (`substitution_proxy`,
    /// QEMU + any backend that routes egress through the per-VM endpoint) — so
    /// the two scrub identically with no drift. Plan 129 Phase E / ADR-067.
    pub fn redact_bytes(&self, payload: &[u8]) -> Option<(Vec<u8>, RedactionHits)> {
        let (after_secrets, secrets) = self.secrets.redact(payload, REDACTION_MASK);
        let (after_pii, pii) = self.pii.redact(&after_secrets);
        let hits = RedactionHits { secrets, pii };
        if hits.is_empty() {
            return None; // clean payload — pass through unchanged.
        }
        Some((after_pii, hits))
    }
}

impl SubstitutionStage for RedactingSubstitution {
    fn name(&self) -> &'static str {
        "redact-secrets-pii"
    }

    fn substitute(&self, _ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> Option<Vec<u8>> {
        let (redacted, hits) = self.redact_bytes(pkt.l4_payload)?;
        // Observability only: the categories that fired + the destination,
        // never the matched bytes (claim-13 discipline).
        tracing::warn!(
            dst = %pkt.five_tuple.dst_ip,
            dst_port = pkt.five_tuple.dst_port,
            secrets = ?hits.secrets,
            pii = ?hits.pii,
            "egress redactor masked undeclared secret/PII content"
        );
        Some(redacted)
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
            Some(qname) if !self.is_allowed(&qname) => ScanOutcome::Drop { by: self.name() },
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
            ScanOutcome::Drop { by: self.name() }
        } else {
            ScanOutcome::Pass
        }
    }
}

/// Drops any egress packet whose L4 payload contains a substitution
/// placeholder — the host-owned [`PLACEHOLDER_PREFIX`] namespace (Plan 129 /
/// ADR-067 §1 leak backstop). The legitimate substitution path routes
/// placeholders to the host-local endpoint, never out the raw egress wire, so a
/// placeholder seen here is a guest trying to smuggle the token out a side
/// channel. It can't smuggle a *value* (it never held one); this stops the
/// token leaking too. Fail-closed; egress only (an ingress frame's payload is
/// inbound, not guest-authored).
///
/// Baseline detector: a single reserved-prefix scan, no false positives on
/// normal traffic (the namespace is ours). The broader secret-shaped/PII/
/// entropy detector set over `core::redact` is the larger Phase E1 follow-up.
pub struct PlaceholderLeakScan;

impl ScanStage for PlaceholderLeakScan {
    fn name(&self) -> &'static str {
        "placeholder-leak"
    }

    fn scan(&self, ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> ScanOutcome {
        match ctx.direction {
            FlowDirection::Egress => {}
            _ => return ScanOutcome::Pass,
        }
        let needle = PLACEHOLDER_PREFIX.as_bytes();
        if pkt.l4_payload.windows(needle.len()).any(|w| w == needle) {
            ScanOutcome::Drop { by: self.name() }
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
            ScanOutcome::Drop { by: self.name() }
        }
    }
}

/// Runs an ordered list of [`ScanStage`]s **fail-closed**: the packet passes
/// only if every stage passes; the first stage that returns `Drop` short-
/// circuits. This is how the egress scans compose on the single
/// `ObserverWiring.scan` slot — `[MandatoryDenyEgressScan, NetworkPolicyScan]`
/// so mandatory-deny always wins and the per-tenant L4 filter runs under it.
pub struct ScanChain {
    stages: Vec<Arc<dyn ScanStage>>,
}

impl ScanChain {
    pub fn new(stages: Vec<Arc<dyn ScanStage>>) -> Self {
        Self { stages }
    }
}

impl ScanStage for ScanChain {
    fn name(&self) -> &'static str {
        "scan-chain"
    }

    fn scan(&self, ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> ScanOutcome {
        for stage in &self.stages {
            // Propagate the dropping stage's identity, not the chain's, so the
            // audit names the actual enforcement.
            if let ScanOutcome::Drop { by } = stage.scan(ctx, pkt) {
                return ScanOutcome::Drop { by };
            }
        }
        ScanOutcome::Pass
    }
}

/// Enforces the policy bundle's L4 [`L4Policy`] (proto + dst CIDR + port range)
/// on the egress packet path (plan 123 Slice 3 / claim 10), reusing the
/// supervisor's tested `L4Policy::evaluate` (first-match-wins, default-deny).
///
/// This is the per-tenant filter the bundle actually carries
/// (`mvm_core::policy::NetworkPolicy.l4`). Its rules are CIDRs, so they match a
/// packet's destination IP directly — no hostname-resolution gap (that concern
/// belongs to [`DnsSinkholeScan`] at the DNS layer; the iptables-typed
/// [`NetworkPolicyScan`] is the host:port allow-list variant for that path).
/// Egress-only; an ingress frame's L3 dst is the guest. Compose it *under*
/// [`MandatoryDenyEgressScan`] via a [`ScanChain`].
pub struct L4PolicyScan {
    policy: L4Policy,
}

impl L4PolicyScan {
    pub fn new(policy: L4Policy) -> Self {
        Self { policy }
    }
}

impl ScanStage for L4PolicyScan {
    fn name(&self) -> &'static str {
        "l4-policy"
    }

    fn scan(&self, ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> ScanOutcome {
        match ctx.direction {
            FlowDirection::Egress => {}
            _ => return ScanOutcome::Pass,
        }
        let proto = match pkt.five_tuple.proto {
            L4Proto::Tcp => Protocol::Tcp,
            L4Proto::Udp => Protocol::Udp,
        };
        match self
            .policy
            .evaluate(proto, pkt.five_tuple.dst_ip, pkt.five_tuple.dst_port)
        {
            L4Decision::Allow => ScanOutcome::Pass,
            L4Decision::Deny { .. } => ScanOutcome::Drop { by: self.name() },
        }
    }
}

/// Build the egress `ScanStage` for a VM's gateway bridge, composing the
/// per-tenant egress filters under the always-on host-side mandatory-deny:
///
/// - `MandatoryDenyEgressScan` — always (link-local + cloud metadata).
/// - `PlaceholderLeakScan` — always (Plan 129 / ADR-067 §1): drops any egress
///   carrying a substitution placeholder out the raw wire. Always-on because
///   the placeholder namespace is host-reserved and the scan is a cheap
///   single-prefix check — a workload that never uses secrets never trips it.
/// - `L4PolicyScan(l4)` — when the bundle resolved an L4 policy (CIDR/port).
/// - `DnsSinkholeScan(dns_allow)` — when `dns_allow` (the bundle's egress
///   allow-list hostnames) is non-empty: sink-holes UDP/53 lookups for hosts
///   outside the list. An **empty** `dns_allow` deliberately adds no sink-hole
///   (it would otherwise drop every lookup); host gating is opt-in via a
///   non-empty allow-list.
pub fn build_egress_scan(l4: Option<L4Policy>, dns_allow: Vec<String>) -> Arc<dyn ScanStage> {
    // Always-on host backstops: mandatory-deny egress ranges + placeholder-leak.
    let mut stages: Vec<Arc<dyn ScanStage>> = vec![
        Arc::new(MandatoryDenyEgressScan),
        Arc::new(PlaceholderLeakScan),
    ];
    if let Some(p) = l4 {
        stages.push(Arc::new(L4PolicyScan::new(p)));
    }
    if !dns_allow.is_empty() {
        stages.push(Arc::new(DnsSinkholeScan::new(dns_allow)));
    }
    Arc::new(ScanChain::new(stages))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::network::FlowDirection;
    use crate::supervisor::network::packet::{FiveTuple, L4Proto};
    use crate::supervisor::proxy::l4::LiveL4Gate;
    use mvm_core::network_policy::{HostPort, NetworkPolicy};
    use mvm_core::policy::L4RuleSpec;

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

    fn tcp_egress(payload: &[u8]) -> ParsedPacket<'_> {
        ParsedPacket {
            five_tuple: FiveTuple {
                proto: L4Proto::Tcp,
                src_ip: "10.0.0.2".parse().unwrap(),
                dst_ip: "1.1.1.1".parse().unwrap(),
                src_port: 5000,
                dst_port: 443,
            },
            l4_payload: payload,
            raw_frame: payload,
        }
    }

    #[test]
    fn redacting_substitution_masks_secret_and_passes_clean() {
        let r = RedactingSubstitution::with_default_rules();
        // A clean payload passes through (None — no rewrite).
        assert_eq!(
            r.substitute(&egress_ctx(), &tcp_egress(b"GET / nothing here")),
            None
        );
        // A payload carrying an undeclared secret-shaped token is rewritten with
        // the mask, and the original token is gone.
        let key = "sk-".to_owned() + &"z".repeat(48);
        let body = format!("POST {{\"k\":\"{key}\"}}").into_bytes();
        let out = r
            .substitute(&egress_ctx(), &tcp_egress(&body))
            .expect("secret-bearing payload must be rewritten");
        let masked = String::from_utf8_lossy(&out);
        assert!(
            !masked.contains(&key),
            "secret survived redaction: {masked}"
        );
        assert!(masked.contains("XXX"), "no mask present: {masked}");
    }

    #[test]
    fn placeholder_leak_drops_egress_carrying_a_placeholder() {
        // ADR-067 §1 backstop: a placeholder smuggled out the raw egress path
        // (not the host-local substitution endpoint) is dropped.
        let payload = b"POST /x HTTP/1.1\r\nAuthorization: Bearer mvm-secret-deadbeef\r\n\r\n";
        assert_eq!(
            PlaceholderLeakScan.scan(&egress_ctx(), &tcp_egress(payload)),
            ScanOutcome::Drop {
                by: "placeholder-leak"
            }
        );
    }

    #[test]
    fn placeholder_leak_passes_clean_egress() {
        let payload = b"POST /x HTTP/1.1\r\nAuthorization: Bearer ya29.real-token\r\n\r\n";
        assert_eq!(
            PlaceholderLeakScan.scan(&egress_ctx(), &tcp_egress(payload)),
            ScanOutcome::Pass
        );
    }

    #[test]
    fn placeholder_leak_ignores_ingress() {
        // An ingress frame's payload is inbound, not guest-authored — never our
        // placeholder to police.
        let payload = b"...mvm-secret-deadbeef...";
        let ctx = ingress_ctx();
        assert_eq!(
            PlaceholderLeakScan.scan(&ctx, &tcp_egress(payload)),
            ScanOutcome::Pass
        );
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
        assert_eq!(
            scan.scan(&egress_ctx(), &pkt),
            ScanOutcome::Drop { by: "dns-sinkhole" }
        );
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
        assert_eq!(
            scan.scan(&egress_ctx(), &dns_packet(&q)),
            ScanOutcome::Drop { by: "dns-sinkhole" }
        );
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
            ScanOutcome::Drop {
                by: "mandatory-deny-egress"
            }
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
        assert_eq!(
            scan.scan(&egress_ctx(), &pkt),
            ScanOutcome::Drop {
                by: "network-policy"
            }
        );
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
            ScanOutcome::Drop {
                by: "network-policy"
            }
        );
        // Different IP → drop.
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("9.9.9.9".parse().unwrap(), 443)),
            ScanOutcome::Drop {
                by: "network-policy"
            }
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
            ScanOutcome::Drop {
                by: "network-policy"
            }
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

    #[test]
    fn scan_chain_drops_if_any_stage_drops() {
        // Fail-closed composition: mandatory-deny passes a public IP, but the
        // chained deny_all NetworkPolicyScan drops it → the chain drops.
        let chain = ScanChain::new(vec![
            Arc::new(MandatoryDenyEgressScan) as Arc<dyn ScanStage>,
            Arc::new(NetworkPolicyScan::new(NetworkPolicy::deny_all())),
        ]);
        let pkt = tcp_packet("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(
            chain.scan(&egress_ctx(), &pkt),
            ScanOutcome::Drop {
                by: "network-policy"
            }
        );
    }

    #[test]
    fn scan_chain_passes_when_every_stage_passes() {
        // mandatory-deny passes a public IP + an allow-list permitting it →
        // the whole chain passes.
        let chain = ScanChain::new(vec![
            Arc::new(MandatoryDenyEgressScan) as Arc<dyn ScanStage>,
            Arc::new(NetworkPolicyScan::new(NetworkPolicy::allow_list(vec![
                HostPort::new("1.1.1.1", 443),
            ]))),
        ]);
        let pkt = tcp_packet("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(chain.scan(&egress_ctx(), &pkt), ScanOutcome::Pass);
    }

    #[test]
    fn scan_chain_empty_passes() {
        // A chain of no stages is vacuously pass — the safe default before any
        // scan is composed in.
        let chain = ScanChain::new(vec![]);
        let pkt = tcp_packet("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(chain.scan(&egress_ctx(), &pkt), ScanOutcome::Pass);
    }

    #[test]
    fn scan_chain_mandatory_deny_wins_over_a_permissive_policy() {
        // Even unrestricted (pass-all) composed with mandatory-deny still drops
        // the metadata IP: mandatory-deny is not overridable by a per-tenant
        // policy, whatever the order.
        let chain = ScanChain::new(vec![
            Arc::new(NetworkPolicyScan::new(NetworkPolicy::unrestricted())) as Arc<dyn ScanStage>,
            Arc::new(MandatoryDenyEgressScan),
        ]);
        let pkt = tcp_packet("169.254.169.254".parse().unwrap(), 80);
        assert_eq!(
            chain.scan(&egress_ctx(), &pkt),
            ScanOutcome::Drop {
                by: "mandatory-deny-egress"
            }
        );
    }

    #[test]
    fn build_egress_scan_none_chains_mandatory_deny_and_placeholder_leak() {
        // No per-tenant policy → the always-on backstops (mandatory-deny +
        // placeholder-leak). A metadata IP drops (mandatory-deny wins, first in
        // the chain); a public IP with clean payload passes (no L4 filter).
        let scan = build_egress_scan(None, vec![]);
        assert_eq!(scan.name(), "scan-chain");
        assert_eq!(
            scan.scan(
                &egress_ctx(),
                &tcp_packet("169.254.169.254".parse().unwrap(), 80)
            ),
            ScanOutcome::Drop {
                by: "mandatory-deny-egress"
            }
        );
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.1.1.1".parse().unwrap(), 443)),
            ScanOutcome::Pass
        );
    }

    #[test]
    fn build_egress_scan_always_includes_placeholder_leak_backstop() {
        // The placeholder-leak backstop is always in the live chain, even with
        // no per-tenant policy: a public IP carrying a placeholder is dropped.
        let scan = build_egress_scan(None, vec![]);
        let leak = b"POST /x HTTP/1.1\r\nAuthorization: Bearer mvm-secret-deadbeef\r\n\r\n";
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_egress(leak)),
            ScanOutcome::Drop {
                by: "placeholder-leak"
            }
        );
    }

    #[test]
    fn build_egress_scan_some_chains_policy_under_mandatory_deny() {
        // A deny_all L4 policy → the chain drops every egress packet; the
        // metadata IP is dropped by the mandatory-deny stage too.
        let scan = build_egress_scan(Some(L4Policy::deny_all()), vec![]);
        assert_eq!(scan.name(), "scan-chain");
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.1.1.1".parse().unwrap(), 443)),
            ScanOutcome::Drop { by: "l4-policy" }
        );
    }

    #[test]
    fn build_egress_scan_chains_dns_sinkhole_when_allow_list_present() {
        // A non-empty DNS allow-list adds DnsSinkholeScan under mandatory-deny:
        // a UDP/53 query for a non-allowed host drops; an allowed one passes.
        let scan = build_egress_scan(None, vec!["example.com".to_string()]);
        assert_eq!(scan.name(), "scan-chain");
        assert_eq!(
            scan.scan(&egress_ctx(), &dns_packet(&dns_query("tracker.evil.test"))),
            ScanOutcome::Drop { by: "dns-sinkhole" }
        );
        assert_eq!(
            scan.scan(&egress_ctx(), &dns_packet(&dns_query("api.example.com"))),
            ScanOutcome::Pass
        );
    }

    #[test]
    fn build_egress_scan_empty_dns_allow_list_adds_no_sinkhole() {
        // An empty DNS allow-list must NOT add DnsSinkholeScan (that would drop
        // every lookup). With no L4 policy either, only the always-on backstops
        // remain, so a DNS lookup passes (not sink-holed).
        let scan = build_egress_scan(None, vec![]);
        assert_eq!(scan.name(), "scan-chain");
        assert_eq!(
            scan.scan(&egress_ctx(), &dns_packet(&dns_query("anything.test"))),
            ScanOutcome::Pass
        );
    }

    /// An `L4Policy` permitting tcp to `cidr:port` only, built via the
    /// supervisor's `from_specs` translator (proto + CIDR parsing).
    fn l4_allow(cidr: &str, port: u16) -> L4Policy {
        LiveL4Gate::from_specs(&[L4RuleSpec {
            proto: "tcp".into(),
            dst_cidr: cidr.into(),
            port_lo: port,
            port_hi: port,
        }])
        .unwrap()
        .policy
    }

    #[test]
    fn l4_policy_deny_all_drops_every_egress() {
        // An empty L4Policy is default-deny → every egress packet drops.
        let scan = L4PolicyScan::new(L4Policy::deny_all());
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.1.1.1".parse().unwrap(), 443)),
            ScanOutcome::Drop { by: "l4-policy" }
        );
    }

    #[test]
    fn l4_policy_allows_only_matching_proto_ip_port() {
        let scan = L4PolicyScan::new(l4_allow("1.2.3.4/32", 443));
        // Exact (tcp, ip, port) match → pass.
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.2.3.4".parse().unwrap(), 443)),
            ScanOutcome::Pass
        );
        // Wrong port and wrong IP → no rule matches → default-deny drop.
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("1.2.3.4".parse().unwrap(), 80)),
            ScanOutcome::Drop { by: "l4-policy" }
        );
        assert_eq!(
            scan.scan(&egress_ctx(), &tcp_packet("9.9.9.9".parse().unwrap(), 443)),
            ScanOutcome::Drop { by: "l4-policy" }
        );
    }

    #[test]
    fn l4_policy_ignores_ingress() {
        // Egress-only: deny_all would drop everything on ingress, but the
        // direction gate lets it pass (ingress dst is the guest).
        let scan = L4PolicyScan::new(L4Policy::deny_all());
        assert_eq!(
            scan.scan(&ingress_ctx(), &tcp_packet("1.1.1.1".parse().unwrap(), 443)),
            ScanOutcome::Pass
        );
    }
}

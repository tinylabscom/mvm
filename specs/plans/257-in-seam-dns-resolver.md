# ADR-032 Part 2 — In-Seam DNS Resolver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a NIC-less guest working, host-mediated, audited name resolution — a guest DNS stub on 127.0.0.1:53 forwards each query over the existing vsock egress plane to a policy-gated host resolver that answers only allow-listed names (pins-first, no live lookup), filters answers against a strict SSRF/rebinding classifier, chain-audits every query, and is rate-limited.

**Architecture:** One `NetworkPolicy` → one `EgressGate` gates both the DNS name and the TCP connect. A new `MVM_DNS/1` first-line marker routes per-query vsock streams into the existing `raw_egress` dispatch to a host `dns_handler`; an in-house `forbid(unsafe)` DNS codec in `mvm-protocol` parses the query and encodes the answer; the guest stub folds into `mvm-egress-client`.

**Tech Stack:** Rust; `mvm-protocol` (no_std forbid-unsafe DNS codec), `mvm-core` (SSRF/rebinding IP classifier, shared `TokenBucket`), `mvm-agentd` (guest UDP+TCP stub in `mvm-egress-client`), `mvm-hostd` (host `dns_handler` + `MVM_DNS/1` dispatch + `EventCategory::Dns` audit), `mvm-runtime` (`EgressGate::dns_verdict`), `cargo-fuzz`, cucumber `@live`.

Branches off `fix/egress-connect-completion` (Part 1: honest CONNECT ack + happy-eyeballs). Delivers a guest DNS stub on `127.0.0.1:53` that forwards over the existing vsock egress plane to a host DNS handler which resolves only allow-listed names, filters answers, audits every query, and is rate-limited. One `NetworkPolicy` drives both the DNS name gate and the TCP connect gate.

## Baked-in decisions

- **Pins-first answer source.** An allow-listed QNAME is answered directly from `EgressGate`'s pin registry (`gate.pins.lookup(name).ips`, already resolved at admission by `mvm_core::policy::dns_pin::resolve_network_policy_pins`). No live upstream lookup. Fall back to a gated upstream lookup (`raw_egress::resolve_hostname_ips_pure`) **only** for the `Unrestricted`/wildcard-parent-domain case with no pin — mirroring `EgressGate::decide_hostname_request`'s three-way branch. DNS-tunneling is closed by construction: a name not admitted by policy never triggers an upstream query.
- **Dedicated DNS-answer IP classifier (guard 2), stricter than TCP.** Reject A/AAAA answers in RFC1918 (`10/8`, `172.16/12`, `192.168/16`), IPv6 ULA (`fc00::/7`), link-local (`169.254/16`, `fe80::/10`), loopback (`127/8`, `::1`), and metadata (`169.254.169.254`) **unless that exact IP is explicitly allow-listed** (i.e. pin-sourced). `MANDATORY_DENY_RANGES` (`crates/mvm-protocol/src/policy/network_policy.rs:498`) is **not** touched — the deliberate RFC1918-allowed TCP-connect posture stays; the DNS answer filter is a separate, stricter predicate.
- **Transport.** Per-query vsock stream reusing the existing raw-egress connection: guest dials host vsock port `5253`, writes a new `MVM_DNS/1\n` first-line marker, then a 2-byte-length-prefixed DNS query (DNS-over-TCP framing); host replies with a length-prefixed response. Dispatched by a new branch in `raw_egress::handle_raw_conn` (async) and `handle_raw_conn_blocking` (vsock), beside the existing `http_forward::FRAME_LINE` branch.
- **Codec** lives in `mvm-protocol` (`#![no_std]` + `forbid(unsafe_code)`), question + A/AAAA answers only, bounded, fail-closed. Not `hickory-proto`.
- **Guest stub** folds into `mvm-egress-client` (`crates/mvm-agentd/src/egress_client.rs`), UDP + TCP on `127.0.0.1:53`, reusing `HostVsockSession`.
- **Audit** reuses the per-VM chain-signed `Recorder` (`crate::supervisor::audit_recorder::Recorder`, `record_unbound`) already threaded into the substitution endpoint; new `EventCategory::Dns`.
- **Rate-limit** reuses a `TokenBucket` (consolidated into `mvm_core::rate_limit`) plus a concurrency cap.

## Global Constraints (apply to every task)

- No `#[allow(clippy::...)]` anywhere in hand-written code — restructure instead (dedicated params struct / builder when a function trips `too_many_arguments`).
- No spec/PR/plan refs in code comments (CI-gated: `Plan N`, `ADR-\d+`, `#\d+`, `W\d.`), and no plan-navigation comments in final code. Comments explain *why*, not *which task*.
- Traits/enums over stringly-typed flags; **exhaustive matches — no `_ =>` on our own enums**.
- No backwards-compat shims/aliases; hard renames.
- `mvm-protocol` stays `#![no_std]` + `forbid(unsafe_code)`; the codec must build on `wasm32-unknown-unknown`.
- The DNS handler is a **claim-10 security seam**: the codec fuzz target, the answer-IP filter unit matrix, and per-query chain-signed audit are **load-bearing, not optional**.
- All `~/.mvm` paths go through `mvm_core::config` helpers.
- Before **every** commit: `cargo nextest run` for the touched crates + `cargo clippy --workspace -- -D warnings` + `cargo fmt --all -- --check`. (Doctests via `cargo test -p <crate> --doc` when a task adds doc examples.)
- Prefer many small single-purpose pure functions; if you can't unit-test a function without a VM, split it.

## Task dependency order

1 → 2 (fuzz needs codec). 3 independent. 4 needs 1 + 3. 5 needs 4. 6 needs 4. 7 needs 1's marker constant + `HostVsockSession` (independent of host branch to compile; e2e needs 4). 8 independent. 9 needs 4–8.

---

## Task 1 — In-house `forbid(unsafe)` DNS codec in `mvm-protocol`

**Files**
- Create `crates/mvm-protocol/src/protocol/dns.rs`
- Modify `crates/mvm-protocol/src/protocol/mod.rs` (add `pub mod dns;` after `pub mod broker;` — line 8 region)
- Modify `crates/mvm-core/src/protocol.rs` (add `pub use mvm_protocol::protocol::dns;` re-export so `mvm_core::protocol::dns` resolves, mirroring `mvm_core::policy::dns_pin`)
- Test: inline `#[cfg(test)] mod tests` in `crates/mvm-protocol/src/protocol/dns.rs`

**Interfaces**

Consumes: `&[u8]` (untrusted wire bytes), `core::net::{IpAddr, Ipv4Addr, Ipv6Addr}`.
Produces:
```rust
// crates/mvm-protocol/src/protocol/dns.rs
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Largest DNS message this codec will parse or emit. DNS-over-TCP frames
/// are length-prefixed; anything larger is refused before allocation.
pub const MAX_DNS_MESSAGE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType { A, Aaaa }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Lower-cased, trailing-dot-stripped ASCII name (bounded to 253 bytes).
    pub name: String,
    pub qtype: DnsRecordType,
    pub id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCodecError {
    TooLong, TooShort, NotAQuery, UnsupportedQType,
    BadLabel, TrailingGarbage, MultiQuestion,
}

/// Parse a single-question A/AAAA query. Fail-closed on anything else.
pub fn decode_query(bytes: &[u8]) -> Result<DnsQuestion, DnsCodecError>;

/// RCODE for a response with no matching admitted answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode { NoError, Refused }

/// Encode a response echoing `q`, with one A/AAAA RR per ip (TTL fixed),
/// NAME compressed to the question (0xC00C), CLASS=IN. `ips` must match
/// `q.qtype`'s family; mismatched entries are skipped.
pub fn encode_response(q: &DnsQuestion, rcode: DnsRcode, ips: &[IpAddr]) -> Vec<u8>;
```

**TDD steps**

- [x] **Step 1: Write failing tests (real).**
```rust
#[test]
fn decode_rejects_oversized_and_short() {
    assert_eq!(decode_query(&[0u8; MAX_DNS_MESSAGE + 1]), Err(DnsCodecError::TooLong));
    assert_eq!(decode_query(&[0u8; 4]), Err(DnsCodecError::TooShort));
}

#[test]
fn decode_parses_single_a_question() {
    // id=0x1234, RD=1, qd=1; QNAME example.com; QTYPE=A(1) QCLASS=IN(1)
    let mut m = vec![0x12,0x34, 0x01,0x00, 0x00,0x01, 0,0, 0,0, 0,0];
    for label in ["example","com"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0x00, 0x00,0x01, 0x00,0x01]);
    let q = decode_query(&m).unwrap();
    assert_eq!(q, DnsQuestion { name: "example.com".into(), qtype: DnsRecordType::A, id: 0x1234 });
}

#[test]
fn decode_rejects_response_bit_and_multi_question() {
    let mut m = vec![0x00,0x01, 0x80,0x00, 0x00,0x01, 0,0, 0,0, 0,0]; // QR=1
    m.extend_from_slice(&[0x01,b'a',0x00, 0x00,0x01, 0x00,0x01]);
    assert_eq!(decode_query(&m), Err(DnsCodecError::NotAQuery));
}

#[test]
fn encode_a_response_roundtrips_answer_ips() {
    let q = DnsQuestion { name: "example.com".into(), qtype: DnsRecordType::A, id: 0x1234 };
    let out = encode_response(&q, DnsRcode::NoError, &["93.184.216.34".parse().unwrap()]);
    assert_eq!(&out[0..2], &[0x12, 0x34]);         // id echoed
    assert_eq!(out[2] & 0x80, 0x80);               // QR=1
    assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1); // ANCOUNT=1
    assert!(out.len() <= MAX_DNS_MESSAGE);
}

#[test]
fn encode_refused_has_zero_answers_and_rcode5() {
    let q = DnsQuestion { name: "evil.test".into(), qtype: DnsRecordType::Aaaa, id: 7 };
    let out = encode_response(&q, DnsRcode::Refused, &[]);
    assert_eq!(out[3] & 0x0f, 5);
    assert_eq!(u16::from_be_bytes([out[6], out[7]]), 0);
}

#[test]
fn decode_never_panics_on_arbitrary_bytes() {
    for seed in 0u16..2000 {
        let b: Vec<u8> = (0..seed as usize % 300).map(|i| (i as u8) ^ (seed as u8)).collect();
        let _ = decode_query(&b); // must return, never panic
    }
}
```
- [x] **Step 2: Run — expect FAIL (module missing).** `cargo nextest run -p mvm-protocol dns::`
- [x] **Step 3: Minimal impl in `dns.rs`.** 12-byte header parse (reject `TooShort` < 12, `TooLong` > `MAX_DNS_MESSAGE`); require `qr==0` else `NotAQuery`; `qdcount==1` else `MultiQuestion`; read labels (len-prefixed, reject 0xC0 compression pointers in questions, cap total 253, reject label > 63) into a lowercased dotted name; map QTYPE 1→`A`, 28→`Aaaa`, else `UnsupportedQType`; require QCLASS IN(1); reject trailing bytes → `TrailingGarbage`. `encode_response`: header with `qr=1, rd copied, ra=1, rcode`, echo the question section verbatim, append `ips.len()` RRs (NAME `0xC0 0x0C`, TYPE per qtype, CLASS `0x00 0x01`, TTL `0x00000078`, RDLENGTH 4/16, RDATA). All arithmetic bounded; `#![forbid(unsafe_code)]` inherited from crate.
- [x] **Step 4: Run — expect PASS.** Also `cargo build -p mvm-protocol --target wasm32-unknown-unknown` (no_std clean).
- [x] **Step 5: Commit.** `feat(protocol): in-house forbid(unsafe) DNS question/A/AAAA codec`.

---

## Task 2 — `fuzz_dns_codec` target (claim-5 sibling)

**Files**
- Create `crates/mvm-agentd/fuzz/fuzz_targets/fuzz_dns_codec.rs`
- Modify `crates/mvm-agentd/fuzz/Cargo.toml` (add `mvm-protocol` path dep near line 30; add `[[bin]] name = "fuzz_dns_codec"` after the `fuzz_builder_request` block ~line 73)

**Interfaces**

Consumes: `&[u8]`. Produces: no return (must never panic).
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use mvm_protocol::protocol::dns::{decode_query, encode_response, DnsRcode};

fuzz_target!(|data: &[u8]| {
    if let Ok(q) = decode_query(data) {
        // Re-encoding an accepted question must also never panic and stays bounded.
        let _ = encode_response(&q, DnsRcode::NoError, &[]);
    }
});
```

**TDD steps** (fuzz builds, not nextest)
- [x] **Step 1: Add the target + manifest entry.**
- [x] **Step 2: Build the target (pinned nightly used by the fuzz lane).** From `crates/mvm-agentd/fuzz`, `cargo +$(cat rust-toolchain.toml | sed -n 's/channel = "\(.*\)"/\1/p') fuzz build fuzz_dns_codec` — expect it compiles.
- [x] **Step 3: Smoke run.** `cargo fuzz run fuzz_dns_codec -- -runs=100000 -max_len=4096` — expect no crash. Add a seed corpus file `corpus/fuzz_dns_codec/example_a.bin` (the Task 1 example-query bytes).
- [x] **Step 4: Commit.** `test(fuzz): DNS codec fuzz target sibling to the vsock-framing fuzzers`.

---

## Task 3 — DNS-answer IP classifier (guard 2) + unit matrix

**Files**
- Create `crates/mvm-core/src/policy/dns_guard.rs`
- Modify `crates/mvm-core/src/policy/mod.rs` (add `pub mod dns_guard;`)
- Test: inline in `dns_guard.rs`

**Interfaces**
```rust
// crates/mvm-core/src/policy/dns_guard.rs
use std::net::IpAddr;

/// True when a resolved A/AAAA answer must not be handed to a workload
/// unless that exact IP was explicitly allow-listed. Stricter than
/// `CanonicalEgress`'s mandatory-deny: it also covers RFC1918 and IPv6 ULA,
/// which the TCP-connect posture deliberately permits.
pub fn dns_answer_forbidden(ip: IpAddr) -> bool;
```

**TDD steps**
- [ ] **Step 1: Failing matrix (real).**
```rust
fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

#[test]
fn public_addresses_are_allowed() {
    for s in ["93.184.216.34", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946"] {
        assert!(!dns_answer_forbidden(ip(s)), "{s} should be allowed");
    }
}

#[test]
fn private_link_local_loopback_ula_metadata_are_forbidden() {
    for s in [
        "10.0.0.5", "172.16.9.9", "192.168.1.1",      // RFC1918
        "169.254.169.254", "169.254.10.1",            // metadata + link-local v4
        "127.0.0.1",                                   // loopback v4
        "::1",                                         // loopback v6
        "fe80::1",                                      // link-local v6
        "fc00::1", "fd12:3456::1",                     // ULA
    ] {
        assert!(dns_answer_forbidden(ip(s)), "{s} should be forbidden");
    }
}
```
- [ ] **Step 2: Run — expect FAIL.** `cargo nextest run -p mvm-core dns_guard`
- [ ] **Step 3: Minimal impl using std predicates + explicit ULA/link-local checks.**
```rust
pub fn dns_answer_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80   // fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00   // fc00::/7 ULA
        }
    }
}
```
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit.** `feat(core): DNS-answer SSRF/rebinding classifier (RFC1918+ULA strict)`.

---

## Task 4 — Host DNS handler + `MVM_DNS/1` dispatch (pins-first resolution)

**Files**
- Modify `crates/mvm-runtime/src/vsock_egress_bridge/egress_gate.rs` (add the pure `DnsVerdict` + `EgressGate::dns_verdict`; ~after `admitted_ips` at line 166)
- Create `crates/mvm-hostd/src/supervisor/dns_handler.rs`
- Modify `crates/mvm-hostd/src/supervisor/mod.rs` (add `pub mod dns_handler;`)
- Modify `crates/mvm-hostd/src/supervisor/raw_egress.rs` (new branch in `handle_raw_conn` ~line 88 and `handle_raw_conn_blocking` ~line 254)
- Tests: inline in both `egress_gate.rs` and `dns_handler.rs`

**Interfaces**

Pure seam on `EgressGate` (reuses private `self.pins` + `self.egress`):
```rust
// egress_gate.rs
use mvm_core::policy::dns_guard::dns_answer_forbidden;
use mvm_core::protocol::dns::DnsRecordType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsVerdict {
    /// Name admitted; these answer IPs survived the answer filter (may be empty → NODATA).
    Resolved(Vec<IpAddr>),
    /// Name not admitted by policy — no upstream lookup performed.
    Refused,
}

impl EgressGate {
    /// Pins-first: an allow-listed name answers from its admission pins (explicit,
    /// so private/ULA pins are kept). Unrestricted with no pin falls back to a
    /// gated upstream lookup and drops any `dns_answer_forbidden` answer. Any other
    /// case is `Refused` — no upstream query, closing DNS tunneling by construction.
    pub fn dns_verdict<F>(&self, name: &str, qtype: DnsRecordType, resolve: F) -> DnsVerdict
    where F: Fn(&str) -> std::io::Result<Vec<IpAddr>>;
}
```

Host handler:
```rust
// dns_handler.rs
use std::time::Duration;
use mvm_runtime::vmm::egress_gate::EgressGate;

pub const FRAME_LINE: &str = "MVM_DNS/1";

/// Serve one framed DNS query over an async guest stream: read the 2-byte
/// length + query, decode, gate the QNAME, resolve, filter, encode, write back.
/// Fail-closed on any malformed/oversized frame.
pub async fn serve_dns<S>(guest: S, gate: &EgressGate, timeout: Duration) -> std::io::Result<()>
where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin;

#[cfg(target_os = "linux")]
pub fn serve_dns_blocking(guest: std::fs::File, gate: &EgressGate, timeout: Duration) -> std::io::Result<()>;
```
(The upstream fallback closure passed by the handler is `raw_egress::resolve_hostname_ips_pure` — the same one already threaded into `gate.decide_request_with`.)

**TDD steps**

- [ ] **Step 1: Failing pure-seam tests in `egress_gate.rs`.**
```rust
#[test]
fn dns_verdict_pins_first_answers_from_pin_without_upstream() {
    use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    let mut pins = DnsPinRegistry::new();
    let v4: IpAddr = "93.184.216.34".parse().unwrap();
    pins.add(DnsPin::at("example.com", vec![v4], "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"));
    let gate = EgressGate::from_network_policy(
        &NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]), &pins, "2026-01-01T00:00:00Z");
    let v = gate.dns_verdict("example.com", DnsRecordType::A, |_| panic!("no upstream for pinned name"));
    assert_eq!(v, DnsVerdict::Resolved(vec![v4]));
}

#[test]
fn dns_verdict_refuses_unadmitted_name_without_lookup() {
    let gate = EgressGate::default_deny();
    let v = gate.dns_verdict("evil.test", DnsRecordType::A, |_| panic!("must not resolve"));
    assert_eq!(v, DnsVerdict::Refused);
}

#[test]
fn dns_verdict_unrestricted_drops_private_rebind_answer() {
    use mvm_core::policy::projection::CanonicalEgress;
    let gate = EgressGate::new(CanonicalEgress::Unrestricted);
    // Upstream returns a public + a private (rebind) address; private is dropped.
    let v = gate.dns_verdict("host.test", DnsRecordType::A,
        |_| Ok(vec!["93.184.216.34".parse().unwrap(), "10.1.2.3".parse().unwrap()]));
    assert_eq!(v, DnsVerdict::Resolved(vec!["93.184.216.34".parse().unwrap()]));
}

#[test]
fn dns_verdict_explicit_private_allowlist_is_kept() {
    use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    let mut pins = DnsPinRegistry::new();
    let p: IpAddr = "192.168.4.23".parse().unwrap();
    pins.add(DnsPin::at("192.168.4.23", vec![p], "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"));
    let gate = EgressGate::from_network_policy(
        &NetworkPolicy::allow_list(vec![HostPort::new("192.168.4.23", 19099)]), &pins, "2026-01-01T00:00:00Z");
    assert_eq!(gate.dns_verdict("192.168.4.23", DnsRecordType::A, |_| panic!()),
               DnsVerdict::Resolved(vec![p]));
}
```
- [ ] **Step 2: Run — expect FAIL.** `cargo nextest run -p mvm-runtime dns_verdict`
- [ ] **Step 3: Minimal `dns_verdict` impl mirroring `decide_hostname_request`'s branch.**
```rust
pub fn dns_verdict<F>(&self, name: &str, qtype: DnsRecordType, resolve: F) -> DnsVerdict
where F: Fn(&str) -> std::io::Result<Vec<IpAddr>> {
    let (candidates, explicit) = if let Some(pin) = self.pins.lookup(name) {
        (pin.ips.clone(), true)
    } else if matches!(self.egress, CanonicalEgress::Unrestricted) {
        match resolve(name) { Ok(ips) => (ips, false), Err(_) => return DnsVerdict::Refused }
    } else {
        return DnsVerdict::Refused;
    };
    let want_v4 = matches!(qtype, DnsRecordType::A);
    let answers = candidates.into_iter()
        .filter(|ip| ip.is_ipv4() == want_v4)
        .filter(|ip| explicit || !dns_answer_forbidden(*ip))
        .collect();
    DnsVerdict::Resolved(answers)
}
```
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Failing handler test in `dns_handler.rs`** (in-memory duplex, echoes the decode→verdict→encode path against a default-deny gate → REFUSED, and an unrestricted gate + stub resolver → answer).
```rust
#[tokio::test]
async fn serve_dns_refuses_unadmitted_name() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use mvm_core::protocol::dns::{DnsQuestion, DnsRecordType, encode_query_for_test};
    let gate = EgressGate::default_deny();
    let (mut client, server) = tokio::io::duplex(4096);
    let h = tokio::spawn(async move { serve_dns(server, &gate, Duration::from_secs(1)).await });
    let q = build_a_query("blocked.test", 0x2222); // helper: raw bytes
    client.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
    client.write_all(&q).await.unwrap();
    let mut len = [0u8; 2]; client.read_exact(&mut len).await.unwrap();
    let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[3] & 0x0f, 5, "RCODE=REFUSED");
    h.await.unwrap().unwrap();
}
```
- [ ] **Step 6: Run — expect FAIL.** `cargo nextest run -p mvm-hostd dns_handler`
- [ ] **Step 7: Minimal `serve_dns`.** Read 2-byte len (reject > `MAX_DNS_MESSAGE`), read payload, `decode_query` (on `Err` → write a `Refused` response for a best-effort echoed id or close), `gate.dns_verdict(name, qtype, |h| resolve_hostname_ips_pure(h, timeout))`, map `Refused → encode_response(Refused,&[])`, `Resolved(ips) → encode_response(NoError,&ips)`, write 2-byte len + bytes. Add the `MVM_DNS/1` branch to `handle_raw_conn` (`if target == dns_handler::FRAME_LINE { return dns_handler::serve_dns(guest, gate, timeout).await; }`) and to `handle_raw_conn_blocking` (`serve_dns_blocking`). Add a small `build_a_query`/`encode_query_for_test` helper behind `#[cfg(test)]` (or a `pub(crate)` encoder) so tests can synthesize queries.
- [ ] **Step 8: Run — expect PASS.**
- [ ] **Step 9: Commit.** `feat(hostd): host DNS handler + MVM_DNS/1 dispatch with pins-first resolution`.

---

## Task 5 — Per-query chain-signed audit (`EventCategory::Dns`)

**Files**
- Modify `crates/mvm-hostd/src/supervisor/audit_recorder.rs` (add `EventCategory::Dns`; `as_str()` → `"dns"`; `bump_metric` arm; update the 3 category-enumerating tests + the `nine`→`ten` prometheus test)
- Modify `crates/mvm-core/src/observability/metrics.rs` (add `audit_dns_total` field + `new`/`Default` init + snapshot field + `prometheus_exposition` line, mirroring `audit_secret_total`)
- Create `crates/mvm-hostd/src/supervisor/dns_audit.rs` (emit helpers, sibling to `secret_audit.rs`)
- Modify `crates/mvm-hostd/src/supervisor/mod.rs` (add `pub mod dns_audit;`)
- Modify `crates/mvm-hostd/src/supervisor/dns_handler.rs` (`serve_dns`/`serve_dns_blocking` gain `recorder: Option<&Recorder>`)
- Modify `crates/mvm-hostd/src/supervisor/raw_egress.rs` (`serve_raw_egress`/`serve_raw_egress_vsock`/`handle_raw_conn*` thread `recorder: Option<Arc<Recorder>>`)
- Modify `crates/mvm-hostd/src/bin/mvm-substitution-endpoint.rs` (`serve_raw` builds the recorder via the endpoint's existing `build_audit_recorder(&cfg.tenant_id)` and passes it in)

**Interfaces**
```rust
// dns_audit.rs
use crate::supervisor::audit_recorder::{EventCategory, Recorder};
use mvm_runtime::vmm::egress_gate::DnsVerdict;
use mvm_core::protocol::dns::DnsRecordType;

/// Chain-audit one resolved query (metadata only: qname, qtype, verdict, ips).
/// Never records payload bytes. Best-effort; a signer error is logged, not fatal.
pub async fn emit_dns_query(recorder: &Recorder, name: &str, qtype: DnsRecordType, verdict: &DnsVerdict);
```
`EventCategory::Dns` → `as_str()=="dns"`, `requires_plan_context()==false`; events `dns.resolved` / `dns.refused`.

**TDD steps**
- [ ] **Step 1: Failing test in `dns_audit.rs` using `CapturingAuditSigner`.**
```rust
#[tokio::test]
async fn emits_dns_refused_with_metadata_only() {
    use std::sync::Arc;
    use mvm_core::plan::TenantId;
    use crate::supervisor::audit::CapturingAuditSigner;
    let signer = Arc::new(CapturingAuditSigner::new());
    let rec = Recorder::new(signer.clone(), TenantId("local".into()));
    emit_dns_query(&rec, "evil.test", DnsRecordType::A, &DnsVerdict::Refused).await;
    let e = &signer.entries()[0];
    assert_eq!(e.event, "dns.refused");
    assert_eq!(e.labels.get("qname"), Some(&"evil.test".to_string()));
    assert_eq!(e.labels.get("category"), Some(&"dns".to_string()));
    assert!(!signer.entries()[0].labels.values().any(|v| v.contains("payload")));
}

#[tokio::test]
async fn emits_dns_resolved_with_ip_list() {
    /* Resolved(vec![93.184.216.34]) -> event "dns.resolved", labels qtype=a, ips=93.184.216.34 */
}
```
- [ ] **Step 2: Run — expect FAIL.** `cargo nextest run -p mvm-hostd dns_audit`
- [ ] **Step 3: Add `EventCategory::Dns`** (+ metrics field + exhaustive `bump_metric` arm + update the enumerating tests); implement `emit_dns_query` via `recorder.record_unbound(EventCategory::Dns, event, extras)` with `event = if Refused {"dns.refused"} else {"dns.resolved"}` and `extras = [("qname",name),("qtype",qtype_str),("verdict",..),("ips",joined)]`.
- [ ] **Step 4: Thread `recorder: Option<&Recorder>` through `serve_dns`** and call `emit_dns_query` after computing the verdict; thread `Option<Arc<Recorder>>` through `serve_raw_egress*`/`handle_raw_conn*` (the existing HTTP-forward/raw branches ignore it for now); in `serve_raw` build it from `build_audit_recorder(&cfg.tenant_id)` and pass through.
- [ ] **Step 5: Run — expect PASS.** `cargo nextest run -p mvm-core -p mvm-hostd`.
- [ ] **Step 6: Commit.** `feat(hostd): chain-signed per-query DNS audit via EventCategory::Dns`.

---

## Task 6 — Per-workload rate-limit (token bucket) + concurrency cap

**Files**
- Create `crates/mvm-core/src/rate_limit.rs` (pure `TokenBucket`, lifted from the broker copy)
- Modify `crates/mvm-core/src/lib.rs` (add `pub mod rate_limit;`)
- Modify `crates/mvm-hostd/src/broker/handlers/host_audit_v1.rs` (replace the private `TokenBucket` with `mvm_core::rate_limit::TokenBucket` — removes the duplicate; existing broker rate-limit tests stay green)
- Modify `crates/mvm-hostd/src/supervisor/dns_handler.rs` (a shared `DnsRateGuard { bucket: Mutex<TokenBucket>, inflight: Semaphore }` held by the serve loop; `serve_dns` consults it)
- Modify `crates/mvm-hostd/src/supervisor/raw_egress.rs` (`serve_raw_egress*` construct one `Arc<DnsRateGuard>` and pass it per connection)

**Interfaces**
```rust
// crates/mvm-core/src/rate_limit.rs
pub struct TokenBucket { /* tokens, capacity, refill_per_sec, last_refill */ }
impl TokenBucket {
    pub fn new(tokens_per_sec: u32) -> Self;
    pub fn try_take(&mut self) -> bool;
}
```
```rust
// dns_handler.rs
pub struct DnsRateGuard { /* Mutex<TokenBucket> + tokio::sync::Semaphore */ }
impl DnsRateGuard {
    pub fn new(queries_per_sec: u32, max_inflight: usize) -> Self;
    /// None => rate-limited (drop the query, emit no upstream lookup).
    pub async fn admit(&self) -> Option<tokio::sync::SemaphorePermit<'_>>;
}
```

**TDD steps**
- [ ] **Step 1: Failing tests.** (a) move/duplicate the broker's `try_take` unit tests into `rate_limit.rs` (deterministic — `new(0)` never admits, `new(1)` admits once then denies within the same second); (b) `DnsRateGuard::admit` returns `None` when the bucket is empty; the concurrency `Semaphore` caps in-flight to `max_inflight`.
- [ ] **Step 2: Run — expect FAIL.** `cargo nextest run -p mvm-core rate_limit` / `-p mvm-hostd dns_handler`
- [ ] **Step 3: Impl.** Lift `TokenBucket` verbatim into `mvm_core::rate_limit`; point the broker at it (delete the private copy + its now-duplicate `use`); implement `DnsRateGuard` and gate `serve_dns` (rate-limited query → encode `Refused`/drop + `emit_dns_query` with `verdict=rate_limited`, no upstream lookup).
- [ ] **Step 4: Run — expect PASS.** `cargo nextest run -p mvm-core -p mvm-hostd`.
- [ ] **Step 5: Commit.** `feat: shared TokenBucket + per-workload DNS rate-limit and concurrency cap`.

---

## Task 7 — Guest DNS stub (UDP + TCP `127.0.0.1:53`) in `mvm-egress-client`

**Files**
- Modify `crates/mvm-agentd/src/egress_client.rs` (add a `dns_stub` submodule; spawn its UDP + TCP listeners from `run`/`run_until_shutdown` alongside the existing SOCKS listener)
- Modify `crates/mvm-core/src/guest_netd.rs` (add `pub const DEFAULT_DNS_STUB_LISTEN: &str = "127.0.0.1:53";` and `pub const DNS_FRAME_LINE: &str = "MVM_DNS/1";` next to the egress-proxy consts, so the guest stub and host handler share one marker string)
- Modify `crates/mvm-hostd/src/supervisor/dns_handler.rs` (`FRAME_LINE` re-exports `mvm_core::guest_netd::DNS_FRAME_LINE` — one source of truth)

**Interfaces**
```rust
// egress_client.rs (dns_stub)
/// Bind UDP + TCP on `listen` (127.0.0.1:53). Each query opens one host vsock
/// session, writes "MVM_DNS/1\n" then the 2-byte-length-framed query, reads the
/// length-framed response, and returns it to the guest resolver. Reuses HostVsockSession.
pub async fn run_dns_stub(listen: std::net::SocketAddr) -> std::io::Result<()>;

async fn forward_query_over_vsock(query: &[u8]) -> std::io::Result<Vec<u8>>; // hermetic-testable seam
```

**TDD steps**
- [ ] **Step 1: Failing hermetic test for the framing seam** (in-memory duplex standing in for the host vsock stream): assert the stub writes `MVM_DNS/1\n`, then `len_be(query)`, then `query`, and returns the response payload after the host writes `len_be(resp)+resp`.
```rust
#[tokio::test]
async fn stub_frames_marker_len_query_and_reads_len_response() {
    let (host_side, stub_side) = tokio::io::duplex(4096);
    let session = HostVsockSession::new(stub_side);
    let task = tokio::spawn(forward_query_over_session(session, b"QUERYBYTES".to_vec()));
    // host reads marker line
    let mut host = host_side;
    let mut line = Vec::new(); read_until_lf(&mut host, &mut line).await;
    assert_eq!(line, b"MVM_DNS/1\n");
    let mut len = [0u8;2]; host.read_exact(&mut len).await.unwrap();
    assert_eq!(u16::from_be_bytes(len) as usize, "QUERYBYTES".len());
    /* echo a canned response with its own 2-byte length; assert task returns it */
}
```
(Refactor `forward_query_over_vsock` to a generic `forward_query_over_session<U: AsyncRead+AsyncWrite>` so it unit-tests without AF_VSOCK.)
- [ ] **Step 2: Run — expect FAIL.** `cargo nextest run -p mvm-agentd egress_client::dns_stub`
- [ ] **Step 3: Impl `dns_stub`.** `UdpSocket::bind(listen)` loop (recv datagram → `forward_query_over_session(HostVsockSession::connect(port), datagram)` → send_to reply); `TcpListener::bind(listen)` loop (read 2-byte len + query per RFC 7766 → forward → write 2-byte len + resp). Spawn both from `run` (non-fatal if `:53` bind fails, logged — the proxy still serves). Bind requires privilege; `mvm-oci-init` spawns the egress client as uid 0 (Task 8 keeps that).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit.** `feat(agentd): guest DNS stub (UDP+TCP :53) forwarding over the vsock seam`.

---

## Task 8 — Seed guest `/etc/resolv.conf → nameserver 127.0.0.1`

**Files**
- Modify `crates/mvm-agentd/src/guest_net.rs` (add `pub const LOOPBACK_STUB_RESOLVER` + a thin `seed_loopback_resolver()` wrapping `seed_resolv_conf_bytes(&render_resolv_conf(&[Ipv4Addr::LOCALHOST.into()]))`; unit-test the rendered body)
- Modify `crates/mvm-agentd/src/bin/mvm-oci-init.rs` (in the `mvm.vsock_egress=1` branch, ~lines 33-48, call `seed_loopback_resolver()` right after `bring_loopback_up()` and before spawning the egress client)
- Modify the nix busybox `/init` path equivalent if it spawns the egress client (grep `mvm.vsock_egress` in the guest-agent boot path; apply the same seed there)

**Interfaces**
```rust
// guest_net.rs
#[cfg(target_os = "linux")]
pub fn seed_loopback_resolver() -> Result<(), String>; // writes "nameserver 127.0.0.1\n"
```

**TDD steps**
- [ ] **Step 1: Failing test (hermetic, pure render).** `render_resolv_conf(&["127.0.0.1".parse().unwrap()])` yields `b"nameserver 127.0.0.1\n"` — already covered by `render_resolv_conf` tests; add one asserting `seed`-body equals that for the loopback stub input. (The `std::fs`/bind-mount body stays `#[cfg(target_os="linux")]` and is exercised by the existing `seed_resolv_conf_bytes` fallback path.)
- [ ] **Step 2: Run — expect FAIL.** `cargo nextest run -p mvm-agentd guest_net`
- [ ] **Step 3: Impl `seed_loopback_resolver`;** wire the oci-init call in the vsock-egress branch.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit.** `feat(agentd): point NIC-less guest resolv.conf at the loopback DNS stub`.

---

## Task 9 — `@live` BDD scenarios + claim/witness wiring

**Files**
- Modify `features/suites/s2_egress_vsock/admitted_egress_live.feature` (add DNS scenarios) or create `features/suites/s2_egress_vsock/in_seam_dns_live.feature`
- Modify the claim catalog + `xtask check-claim-catalog` mapping if the DNS handler is registered as a claim-10 witness (add the codec fuzz target + answer-filter matrix + audit test as named witnesses)
- Reuse existing steps in `crates/mvm-conformance/tests/steps/cli.rs` (`I run mvmctl with {string}`, `the command exits with code {int}`, `the output contains {string}`) — no new step code

**Interfaces**: none (BDD text + existing steps).

**TDD steps** (live lane; run on a host with a working backend, `MVM_BDD_LIVE=1`)
- [ ] **Step 1: Add scenarios** (guest commands need no extra tooling — resolution is proven through a proxied fetch of an allow-listed name, and refusal through a non-admitted name; avoid `nslookup`/`getent`, absent in bare alpine).
```gherkin
  @live
  Scenario: An admitted name resolves and connects through the in-seam resolver
    When I run mvmctl with "machine run --image alpine --allow-host example.com -- wget -q -O - https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"

  @live
  Scenario: A non-admitted name is refused, not resolved
    When I run mvmctl with "machine run --image alpine --allow-host example.com -- wget -q -O - https://not-admitted.test"
    Then the command exits with code 1

  @live
  Scenario: DNS queries land in the chain-signed audit log
    When I run mvmctl with "machine run --image alpine --allow-host example.com -- wget -q -O - https://example.com"
    And I run mvmctl with "trust audit verify"
    Then the command exits with code 0
    And the output contains "dns.resolved"
```
- [ ] **Step 2: Run hermetic lane first (must not regress).** `cargo nextest run -p mvm-conformance` (the `@live` scenarios skip without `MVM_BDD_LIVE`).
- [ ] **Step 3: Run live on a backend host.** `MVM_BDD_LIVE=1 cargo nextest run -p mvm-conformance` — expect PASS. (Defer to the KVM/HVF box per the live-witness policy; CI gates the hermetic path.)
- [ ] **Step 4: Update `xtask check-claim-catalog` witness rows;** run `cargo run -p xtask -- check-claim-catalog`.
- [ ] **Step 5: Commit.** `test(bdd): in-seam DNS live scenarios + claim-10 witness wiring`.

---

## Deferred follow-ups (record in this plan's `### deferred follow-ups`)

- Wildcard / parent-domain allow-listing widens the DNS channel to subdomains of an admitted domain; it stays audited + rate-limited, exact-name preferred. No code change here — documented non-goal.
- `serve_raw_egress*` now carries `Option<Arc<Recorder>>`; the HTTP-forward and raw-TCP branches could also emit `flow.egress.*` audit through it (currently DNS-only).
- Consolidating any remaining private token-bucket copies onto `mvm_core::rate_limit::TokenBucket`.

## Cross-references to keep in sync (same change)

`specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`, and the ADR-032 status (`Proposed` → `Accepted` once Part 2 lands) move with the task checkboxes.

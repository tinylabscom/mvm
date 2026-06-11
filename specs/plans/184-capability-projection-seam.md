# Plan 184 — Capability projection seam (ADR-080 P5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One resolved policy, two enforcement projections that provably agree — the canonical egress grant set (CIDR-keyed, feeds the existing kernel layer) and the WASI outbound grant set (hostname-keyed, feeds the future wasmtime runner) — with the ADR-080 §8 P5 witnesses: a property-based cross-projection consistency test, a DNS-rebinding/mandatory-deny negative fixture, and a clamp (intersection-only) test.

**Architecture:** A new pure module `mvm-core::policy::projection`. `canonicalize_effective()` lowers an `EffectivePolicy` + admission-time `DnsPinRegistry` into a `CanonicalEgress` over one pinned address space (hostnames are resolved to pins *before* projection; the coarse layer enforces pinned IPs, not live DNS). `to_wasi_grants()` walks the same inputs through a *separate* code path producing the hostname-keyed shape; the property witness asserts both decide identically for any probe. Mandatory-deny ranges refuse at projection time, unconditionally. `clamp()` is the intersection-only merge (a request can attenuate, never widen). No enforcement lands here — this is the seam both enforcers will consume (kernel wiring and the wasmtime runner are later plans).

**Tech Stack:** Rust, existing `mvm-core` deps only (`ipnet`, `thiserror`, `chrono`, `serde` — **no new dependencies**; the property test uses a hand-rolled deterministic xorshift, not proptest). Tests via `cargo nextest`.

**Plan number:** 184 was free at authoring time (181 highest on main; 182 in-flight in a parallel worktree; 183 taken by PR #799). Re-verify against open PRs and run `cargo run -p xtask -- check-spec-numbers` before merging.

**Execution notes:** Work in a git worktree, not the main checkout (parallel sessions race the index). After `EnterWorktree`, `cd` to the worktree's *absolute* path and verify `pwd`/branch before any commit. Commit messages carry no AI co-author trailer. This plan was authored in a Bash-denied session; execution requires a session where Bash is permitted.

**Existing code this plan builds on (read before starting):**
- `crates/mvm-core/src/policy/resolver.rs:87` — `EffectivePolicy { network, egress, ... }`, the resolved-policy input.
- `crates/mvm-core/src/policy/policies.rs:32` — `NetworkPolicy { l4: Vec<L4RuleSpec>, .. }`; `policies.rs:102` — `L4RuleSpec { proto, dst_cidr, port_lo, port_hi }` (string CIDR; `(0,0)` = any-port wildcard); `policies.rs:136` — `EgressPolicy { mode: Option<String>, allow_list: Vec<(String, u16)>, .. }` (`mode = Some("open")` is the kill-switch; `port = 0` = any-port wildcard).
- `crates/mvm-core/src/policy/dns_pin.rs:55` — `DnsPin { dest, ips, resolved_at, expires_at }`, `is_valid_at(now: &str)`; `dns_pin.rs:161` — `DnsPinRegistry::lookup`.
- `crates/mvm-core/src/policy/network_policy.rs:459` — `MANDATORY_DENY_RANGES`; `:482` — `mandatory_deny_ranges() -> Vec<IpNet>`; `:504` — `is_mandatory_deny(IpAddr) -> bool`.
- `crates/mvm-hostd/src/supervisor/gateway_bridge.rs:162` — `PlanFlowPolicy::from_effective` (the existing coarse gate this seam will later feed; **not modified by this plan**).

---

### Task 1: `Proto` + `CanonicalRule` — the canonical rule atom

**Files:**
- Create: `crates/mvm-core/src/policy/projection.rs`
- Modify: `crates/mvm-core/src/policy/mod.rs` (add `pub mod projection;`)

- [x] **Step 1: Write the failing tests**

Create `crates/mvm-core/src/policy/projection.rs` with the module doc, the test module, and nothing else yet:

```rust
//! Egress policy projection seam.
//!
//! One resolved [`EffectivePolicy`] projects to two enforcement
//! shapes: the canonical CIDR-keyed grant set the kernel layer
//! (nftables / `LiveL4Gate` / `PlanFlowPolicy`) consumes, and the
//! hostname-keyed outbound grant set the WASI context builder
//! consumes. Hostnames are pinned to IPs at projection time (via
//! the admission-time [`DnsPinRegistry`]) so both projections are
//! compared and enforced over the same pinned address space —
//! live DNS never widens reach. Mandatory-deny ranges refuse at
//! projection time, unconditionally: a grant that resolves into a
//! denied range is an error, not a pin.
//!
//! This module is decision logic only — no enforcement, no I/O,
//! no resolver. The cross-projection consistency property test is
//! the anti-drift witness: both projections must decide
//! identically for every probe.
//!
//! [`EffectivePolicy`]: crate::policy::resolver::EffectivePolicy
//! [`DnsPinRegistry`]: crate::policy::dns_pin::DnsPinRegistry

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn canonical_rule_permits_inside_net_and_port_range() {
        let rule = CanonicalRule {
            proto: Proto::Tcp,
            net: net("10.0.0.0/24"),
            port_lo: 443,
            port_hi: 443,
        };
        assert!(rule.permits(&Proto::Tcp, ip("10.0.0.7"), 443));
    }

    #[test]
    fn canonical_rule_denies_wrong_proto_ip_or_port() {
        let rule = CanonicalRule {
            proto: Proto::Tcp,
            net: net("10.0.0.0/24"),
            port_lo: 443,
            port_hi: 443,
        };
        assert!(!rule.permits(&Proto::Udp, ip("10.0.0.7"), 443), "proto mismatch");
        assert!(!rule.permits(&Proto::Tcp, ip("10.0.1.7"), 443), "ip outside net");
        assert!(!rule.permits(&Proto::Tcp, ip("10.0.0.7"), 80), "port outside range");
    }

    #[test]
    fn canonical_rule_supports_ipv6() {
        let rule = CanonicalRule {
            proto: Proto::Udp,
            net: net("2001:db8::/32"),
            port_lo: 0,
            port_hi: 65535,
        };
        assert!(rule.permits(&Proto::Udp, ip("2001:db8::1"), 53));
        assert!(!rule.permits(&Proto::Udp, ip("2001:db9::1"), 53));
    }

    #[test]
    fn proto_parses_tcp_udp_and_refuses_unknown() {
        assert_eq!(Proto::parse("tcp").unwrap(), Proto::Tcp);
        assert_eq!(Proto::parse("udp").unwrap(), Proto::Udp);
        assert!(matches!(
            Proto::parse("icmp"),
            Err(ProjectionError::UnknownProto { .. })
        ));
    }
}
```

Add to `crates/mvm-core/src/policy/mod.rs` (alongside the existing `pub mod` lines):

```rust
pub mod projection;
```

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `cargo nextest run -p mvm-core projection`
Expected: compile error — `CanonicalRule`, `Proto`, `ProjectionError` not found.

- [ ] **Step 3: Write the minimal implementation**

Add above the test module in `projection.rs`:

```rust
use std::net::IpAddr;

use ipnet::IpNet;
use thiserror::Error;

/// L4 protocol of a canonical rule. The string forms `"tcp"` /
/// `"udp"` are the `L4RuleSpec.proto` wire values; anything else
/// refuses at projection time (loud failure at admission, not a
/// silent drop at runtime — same posture as `LiveL4Gate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn parse(s: &str) -> Result<Self, ProjectionError> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(ProjectionError::UnknownProto {
                proto: other.to_string(),
            }),
        }
    }
}

/// One canonical egress rule over the pinned address space.
/// `port_lo..=port_hi` is inclusive; the any-port wildcard is
/// normalized to `(0, 65535)` before a rule is constructed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalRule {
    pub proto: Proto,
    pub net: IpNet,
    pub port_lo: u16,
    pub port_hi: u16,
}

impl CanonicalRule {
    /// Pure membership decision: does this rule admit the probe?
    pub fn permits(&self, proto: &Proto, ip: IpAddr, port: u16) -> bool {
        self.proto == *proto
            && self.net.contains(&ip)
            && self.port_lo <= port
            && port <= self.port_hi
    }
}

/// Projection-time refusals. Every variant is a fail-closed
/// admission error: the plan does not admit with a grant the
/// projections could not agree on.
#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("unknown proto {proto:?} (expected \"tcp\" or \"udp\")")]
    UnknownProto { proto: String },
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-core projection`
Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs crates/mvm-core/src/policy/mod.rs
git commit -m "feat(policy): canonical egress rule atom for the projection seam (plan 184)"
```

---

### Task 2: `CanonicalEgress` — grant set with unconditional mandatory-deny

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    #[test]
    fn canonical_egress_rules_permit_only_matching_probe() {
        let eg = CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Tcp,
            net: net("93.184.216.0/24"),
            port_lo: 443,
            port_hi: 443,
        }]);
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.217.34"), 443));
    }

    #[test]
    fn canonical_egress_empty_rules_is_deny_all() {
        let eg = CanonicalEgress::Rules(vec![]);
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn canonical_egress_unrestricted_permits_ordinary_destinations() {
        let eg = CanonicalEgress::Unrestricted;
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(eg.permits(&Proto::Udp, ip("8.8.8.8"), 53));
    }

    #[test]
    fn mandatory_deny_wins_even_under_unrestricted() {
        // The `open` kill-switch never reaches metadata/loopback —
        // mirrors the gateway-bridge invariant that even an open
        // policy keeps every packet gated by mandatory-deny.
        let eg = CanonicalEgress::Unrestricted;
        for denied in ["169.254.169.254", "127.0.0.1", "100.64.0.1", "::1"] {
            assert!(
                !eg.permits(&Proto::Tcp, ip(denied), 443),
                "{denied} must be denied under unrestricted"
            );
        }
    }

    #[test]
    fn mandatory_deny_wins_even_when_a_rule_matches() {
        // A rule that (somehow) covers a denied address still
        // denies at decision time — belt to the projection-time
        // refusal's suspenders.
        let eg = CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Tcp,
            net: net("0.0.0.0/0"),
            port_lo: 0,
            port_hi: 65535,
        }]);
        assert!(!eg.permits(&Proto::Tcp, ip("169.254.169.254"), 80));
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 80));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-core projection`
Expected: compile error — `CanonicalEgress` not found.

- [ ] **Step 3: Write the implementation**

Add to `projection.rs` (after `CanonicalRule`):

```rust
use crate::policy::network_policy::is_mandatory_deny;

/// The canonical projection of a resolved policy's egress grants.
/// `Unrestricted` is the `egress.mode = "open"` kill-switch made
/// explicit; mandatory-deny still applies to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalEgress {
    Unrestricted,
    Rules(Vec<CanonicalRule>),
}

impl CanonicalEgress {
    /// The single decision function both enforcement layers must
    /// agree with. Mandatory-deny is checked first and is
    /// unconditional — no grant shape can override it.
    pub fn permits(&self, proto: &Proto, ip: IpAddr, port: u16) -> bool {
        if is_mandatory_deny(ip) {
            return false;
        }
        match self {
            Self::Unrestricted => true,
            Self::Rules(rules) => rules.iter().any(|r| r.permits(proto, ip, port)),
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-core projection`
Expected: 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs
git commit -m "feat(policy): CanonicalEgress decision set with unconditional mandatory-deny (plan 184)"
```

---

### Task 3: `canonicalize_effective` — the L4 leg

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module (note the imports the fixtures need):

```rust
    use crate::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use crate::policy::policies::L4RuleSpec;
    use crate::policy::resolver::EffectivePolicy;

    const NOW: &str = "2026-06-11T00:00:00Z";

    fn l4(proto: &str, cidr: &str, lo: u16, hi: u16) -> L4RuleSpec {
        L4RuleSpec {
            proto: proto.to_string(),
            dst_cidr: cidr.to_string(),
            port_lo: lo,
            port_hi: hi,
        }
    }

    fn eff_with_l4(rules: Vec<L4RuleSpec>) -> EffectivePolicy {
        let mut eff = EffectivePolicy::default();
        eff.network.l4 = rules;
        eff
    }

    #[test]
    fn canonicalize_default_policy_is_deny_all() {
        let eff = EffectivePolicy::default();
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert_eq!(eg, CanonicalEgress::Rules(vec![]));
    }

    #[test]
    fn canonicalize_open_mode_is_unrestricted() {
        let mut eff = EffectivePolicy::default();
        eff.egress.mode = Some("open".to_string());
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert_eq!(eg, CanonicalEgress::Unrestricted);
    }

    #[test]
    fn canonicalize_lowers_l4_rules_verbatim() {
        let eff = eff_with_l4(vec![l4("tcp", "93.184.216.0/24", 443, 443)]);
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 80));
    }

    #[test]
    fn canonicalize_normalizes_any_port_wildcard() {
        // (0, 0) is the wire-format any-port wildcard.
        let eff = eff_with_l4(vec![l4("udp", "8.8.8.8/32", 0, 0)]);
        let eg = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(eg.permits(&Proto::Udp, ip("8.8.8.8"), 53));
        assert!(eg.permits(&Proto::Udp, ip("8.8.8.8"), 65535));
    }

    #[test]
    fn canonicalize_refuses_unparseable_cidr() {
        let eff = eff_with_l4(vec![l4("tcp", "not-a-cidr", 443, 443)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::BadCidr { .. }), "got {err:?}");
    }

    #[test]
    fn canonicalize_refuses_unknown_proto() {
        let eff = eff_with_l4(vec![l4("icmp", "8.8.8.8/32", 0, 0)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::UnknownProto { .. }), "got {err:?}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-core projection`
Expected: compile error — `canonicalize_effective`, `ProjectionError::BadCidr` not found.

- [ ] **Step 3: Write the implementation**

Add to `projection.rs`:

```rust
use crate::policy::dns_pin::DnsPinRegistry;
use crate::policy::resolver::EffectivePolicy;

/// Normalize the wire-format any-port wildcard `(0, 0)` to the
/// explicit full range. Any other pair passes through verbatim.
fn normalize_ports(lo: u16, hi: u16) -> (u16, u16) {
    if lo == 0 && hi == 0 { (0, 65535) } else { (lo, hi) }
}

/// Lower a resolved policy + admission-time pin registry into the
/// canonical egress grant set. Pure; fail-closed on every
/// malformed or unpinnable input. `now` is an RFC 3339 UTC
/// timestamp (the caller's clock — tests pass a fixed string),
/// used to refuse expired pins.
pub fn canonicalize_effective(
    eff: &EffectivePolicy,
    pins: &DnsPinRegistry,
    now: &str,
) -> Result<CanonicalEgress, ProjectionError> {
    if eff.egress.mode.as_deref() == Some("open") {
        return Ok(CanonicalEgress::Unrestricted);
    }
    let mut rules = Vec::new();
    for spec in &eff.network.l4 {
        let net: IpNet = spec
            .dst_cidr
            .parse()
            .map_err(|source| ProjectionError::BadCidr {
                cidr: spec.dst_cidr.clone(),
                source,
            })?;
        let (port_lo, port_hi) = normalize_ports(spec.port_lo, spec.port_hi);
        rules.push(CanonicalRule {
            proto: Proto::parse(&spec.proto)?,
            net,
            port_lo,
            port_hi,
        });
    }
    rules.extend(pinned_allow_list_rules(eff, pins, now)?);
    rules.sort();
    rules.dedup();
    Ok(CanonicalEgress::Rules(rules))
}

/// Lower `egress.allow_list` (hostname, port) entries through the
/// pin registry. Filled in by the allow-list task; the L4-only
/// leg returns no rules when the allow-list is empty.
fn pinned_allow_list_rules(
    eff: &EffectivePolicy,
    _pins: &DnsPinRegistry,
    _now: &str,
) -> Result<Vec<CanonicalRule>, ProjectionError> {
    if eff.egress.allow_list.is_empty() {
        return Ok(Vec::new());
    }
    unimplemented!("allow-list pinning lands in the next task of plan 184")
}
```

Extend `ProjectionError`:

```rust
    #[error("unparseable dst_cidr {cidr:?}: {source}")]
    BadCidr {
        cidr: String,
        source: ipnet::AddrParseError,
    },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-core projection`
Expected: 15 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs
git commit -m "feat(policy): canonicalize_effective lowers L4 rules to the canonical grant set (plan 184)"
```

---

### Task 4: allow-list leg — hostnames become pinned host-nets

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    fn pin(dest: &str, ips: &[&str]) -> DnsPin {
        DnsPin::at(
            dest,
            ips.iter().map(|s| ip(s)).collect(),
            "2026-06-10T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )
    }

    fn registry(pins: Vec<DnsPin>) -> DnsPinRegistry {
        let mut reg = DnsPinRegistry::new();
        for p in pins {
            reg.add(p);
        }
        reg
    }

    fn eff_with_allow(list: Vec<(&str, u16)>) -> EffectivePolicy {
        let mut eff = EffectivePolicy::default();
        eff.egress.allow_list = list
            .into_iter()
            .map(|(h, p)| (h.to_string(), p))
            .collect();
        eff
    }

    #[test]
    fn allow_list_host_lowers_to_pinned_host_nets() {
        let eff = eff_with_allow(vec![("api.example.com", 443)]);
        let pins = registry(vec![pin("api.example.com", &["93.184.216.34", "93.184.216.35"])]);
        let eg = canonicalize_effective(&eff, &pins, NOW).unwrap();
        // Both pinned addresses admitted, TCP, exactly port 443.
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.35"), 443));
        // An unpinned address of the "same host" is NOT admitted —
        // the projection enforces pins, not live DNS.
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.36"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 80));
        assert!(!eg.permits(&Proto::Udp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn allow_list_port_zero_is_any_port() {
        let eff = eff_with_allow(vec![("api.example.com", 0)]);
        let pins = registry(vec![pin("api.example.com", &["93.184.216.34"])]);
        let eg = canonicalize_effective(&eff, &pins, NOW).unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 8080));
    }

    #[test]
    fn allow_list_ipv6_pin_lowers_to_slash128() {
        let eff = eff_with_allow(vec![("v6.example.com", 443)]);
        let pins = registry(vec![pin("v6.example.com", &["2001:db8::42"])]);
        let eg = canonicalize_effective(&eff, &pins, NOW).unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("2001:db8::42"), 443));
        assert!(!eg.permits(&Proto::Tcp, ip("2001:db8::43"), 443));
    }

    #[test]
    fn allow_list_host_without_pin_refuses() {
        let eff = eff_with_allow(vec![("unpinned.example.com", 443)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::MissingPin { .. }), "got {err:?}");
    }

    #[test]
    fn allow_list_expired_pin_refuses() {
        let eff = eff_with_allow(vec![("stale.example.com", 443)]);
        let stale = DnsPin::at(
            "stale.example.com",
            vec![ip("93.184.216.34")],
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z", // expired before NOW
        );
        let err = canonicalize_effective(&eff, &registry(vec![stale]), NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::ExpiredPin { .. }), "got {err:?}");
    }

    #[test]
    fn allow_list_empty_pin_set_refuses() {
        let eff = eff_with_allow(vec![("empty.example.com", 443)]);
        let pins = registry(vec![pin("empty.example.com", &[])]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::EmptyPin { .. }), "got {err:?}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-core projection`
Expected: new tests FAIL — `unimplemented!` panic from `pinned_allow_list_rules`, plus missing `MissingPin`/`ExpiredPin`/`EmptyPin` variants (compile error first).

- [ ] **Step 3: Write the implementation**

Replace the `pinned_allow_list_rules` stub:

```rust
/// A pinned IP as a host-length net (`/32` or `/128`), explicit
/// so there is no doubt about prefix length.
fn host_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).expect("/32 is always valid")),
        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).expect("/128 is always valid")),
    }
}

/// Lower `egress.allow_list` (hostname, port) entries through the
/// pin registry. Allow-list destinations are L7/TCP (they feed the
/// CONNECT-shaped egress proxy), so the canonical rules are TCP.
/// Fail-closed: a host without a live pin refuses the whole
/// projection rather than silently dropping the entry.
fn pinned_allow_list_rules(
    eff: &EffectivePolicy,
    pins: &DnsPinRegistry,
    now: &str,
) -> Result<Vec<CanonicalRule>, ProjectionError> {
    let mut rules = Vec::new();
    for (host, port) in &eff.egress.allow_list {
        let pin = pins
            .lookup(host)
            .ok_or_else(|| ProjectionError::MissingPin { host: host.clone() })?;
        if !pin.is_valid_at(now) {
            return Err(ProjectionError::ExpiredPin {
                host: host.clone(),
                expires_at: pin.expires_at.clone(),
            });
        }
        if pin.ips.is_empty() {
            return Err(ProjectionError::EmptyPin { host: host.clone() });
        }
        let (port_lo, port_hi) = normalize_ports(*port, *port);
        for pinned in &pin.ips {
            rules.push(CanonicalRule {
                proto: Proto::Tcp,
                net: host_net(*pinned),
                port_lo,
                port_hi,
            });
        }
    }
    Ok(rules)
}
```

Extend `ProjectionError`:

```rust
    #[error("no admission-time DNS pin for allow-list host {host:?}")]
    MissingPin { host: String },
    #[error("DNS pin for {host:?} expired at {expires_at}")]
    ExpiredPin { host: String, expires_at: String },
    #[error("DNS pin for {host:?} has an empty IP set")]
    EmptyPin { host: String },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-core projection`
Expected: 21 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs
git commit -m "feat(policy): allow-list hosts lower through admission-time DNS pins (plan 184)"
```

---

### Task 5: mandatory-deny refusal at projection time + rebinding fixture

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    #[test]
    fn l4_rule_overlapping_mandatory_deny_refuses() {
        for cidr in ["169.254.0.0/16", "169.254.169.254/32", "127.0.0.0/8", "100.64.0.0/10"] {
            let eff = eff_with_l4(vec![l4("tcp", cidr, 0, 0)]);
            let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
            assert!(
                matches!(err, ProjectionError::MandatoryDenyOverlap { .. }),
                "{cidr}: got {err:?}"
            );
        }
    }

    #[test]
    fn l4_supernet_of_mandatory_deny_refuses() {
        // A /0 covers every deny range — refuse, don't carve.
        let eff = eff_with_l4(vec![l4("tcp", "0.0.0.0/0", 443, 443)]);
        let err = canonicalize_effective(&eff, &DnsPinRegistry::new(), NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::MandatoryDenyOverlap { .. }), "got {err:?}");
    }

    #[test]
    fn rebinding_pin_into_metadata_range_refuses() {
        // The ADR-080 rebinding fixture: a policy-permitted host
        // whose admission-time resolution lands in the cloud
        // metadata range is a refusal, not a pin.
        let eff = eff_with_allow(vec![("rebind.example.com", 443)]);
        let pins = registry(vec![pin("rebind.example.com", &["169.254.169.254"])]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::MandatoryDenyOverlap { .. }), "got {err:?}");
    }

    #[test]
    fn rebinding_pin_into_loopback_v6_refuses() {
        let eff = eff_with_allow(vec![("rebind6.example.com", 443)]);
        let pins = registry(vec![pin("rebind6.example.com", &["::1"])]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::MandatoryDenyOverlap { .. }), "got {err:?}");
    }

    #[test]
    fn mixed_pin_one_bad_ip_refuses_whole_projection() {
        // One good IP + one metadata IP: fail-closed on the whole
        // projection, no partial admit.
        let eff = eff_with_allow(vec![("mixed.example.com", 443)]);
        let pins = registry(vec![pin(
            "mixed.example.com",
            &["93.184.216.34", "169.254.169.254"],
        )]);
        let err = canonicalize_effective(&eff, &pins, NOW).unwrap_err();
        assert!(matches!(err, ProjectionError::MandatoryDenyOverlap { .. }), "got {err:?}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-core projection`
Expected: compile error (`MandatoryDenyOverlap` not found), then after adding the variant alone the new tests FAIL (projection currently admits).

- [ ] **Step 3: Write the implementation**

Add the helper + wire it into both legs:

```rust
use crate::policy::network_policy::mandatory_deny_ranges;

/// True when two CIDRs share any address. For valid CIDRs, two
/// nets overlap iff one contains the other's network address.
fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Refuse any grant net that intersects a mandatory-deny range.
/// Projection-time belt; `CanonicalEgress::permits` keeps the
/// decision-time suspenders.
fn refuse_mandatory_overlap(dest: &str, net: &IpNet) -> Result<(), ProjectionError> {
    for deny in mandatory_deny_ranges() {
        if nets_overlap(&deny, net) {
            return Err(ProjectionError::MandatoryDenyOverlap {
                dest: dest.to_string(),
                range: deny,
            });
        }
    }
    Ok(())
}
```

In `canonicalize_effective`, after parsing each L4 `net` (before pushing the rule):

```rust
        refuse_mandatory_overlap(&spec.dst_cidr, &net)?;
```

In `pinned_allow_list_rules`, inside the `for pinned in &pin.ips` loop (before pushing the rule):

```rust
            let net = host_net(*pinned);
            refuse_mandatory_overlap(host, &net)?;
```

(and use that `net` binding in the pushed rule). Extend `ProjectionError`:

```rust
    #[error("grant for {dest:?} overlaps mandatory-deny range {range}")]
    MandatoryDenyOverlap { dest: String, range: IpNet },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-core projection`
Expected: 26 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs
git commit -m "feat(policy): refuse mandatory-deny overlap at projection time, incl. rebinding pins (plan 184)"
```

---

### Task 6: the WASI projection — hostname-keyed, separately coded

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`

The point of a *second* walk over the same inputs (instead of deriving from
`CanonicalEgress`) is that the consistency witness in Task 8 compares two
independent code paths — drift between them is exactly what it must catch.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    #[test]
    fn wasi_projection_default_policy_denies_everything() {
        let eff = EffectivePolicy::default();
        let w = to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn wasi_projection_pinned_host_allows_only_pinned_ips() {
        let eff = eff_with_allow(vec![("api.example.com", 443)]);
        let pins = registry(vec![pin("api.example.com", &["93.184.216.34"])]);
        let w = to_wasi_grants(&eff, &pins, NOW).unwrap();
        assert!(wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("93.184.216.35"), 443));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 80));
    }

    #[test]
    fn wasi_projection_l4_net_target() {
        let eff = eff_with_l4(vec![l4("udp", "8.8.8.0/24", 53, 53)]);
        let w = to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(wasi_allows(&w, &Proto::Udp, ip("8.8.8.8"), 53));
        assert!(!wasi_allows(&w, &Proto::Udp, ip("8.8.9.8"), 53));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("8.8.8.8"), 53));
    }

    #[test]
    fn wasi_projection_mandatory_deny_unconditional() {
        let mut eff = EffectivePolicy::default();
        eff.egress.mode = Some("open".to_string());
        let w = to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap();
        assert!(matches!(w, WasiEgress::Unrestricted));
        assert!(!wasi_allows(&w, &Proto::Tcp, ip("169.254.169.254"), 443));
        assert!(wasi_allows(&w, &Proto::Tcp, ip("93.184.216.34"), 443));
    }

    #[test]
    fn wasi_projection_refuses_same_inputs_canonical_refuses() {
        // Shared refusal ladder: missing pin and rebinding pin
        // refuse here exactly as in canonicalize_effective.
        let eff = eff_with_allow(vec![("unpinned.example.com", 443)]);
        assert!(matches!(
            to_wasi_grants(&eff, &DnsPinRegistry::new(), NOW).unwrap_err(),
            ProjectionError::MissingPin { .. }
        ));
        let eff = eff_with_allow(vec![("rebind.example.com", 443)]);
        let pins = registry(vec![pin("rebind.example.com", &["169.254.169.254"])]);
        assert!(matches!(
            to_wasi_grants(&eff, &pins, NOW).unwrap_err(),
            ProjectionError::MandatoryDenyOverlap { .. }
        ));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-core projection`
Expected: compile error — `to_wasi_grants`, `wasi_allows`, `WasiEgress` not found.

- [ ] **Step 3: Write the implementation**

Add to `projection.rs`:

```rust
/// One outbound target in the WASI-facing (hostname-keyed) shape.
/// `PinnedHost` is what a `WasiCtx` outbound-host grant becomes
/// once pinned; `Net` carries an L4 CIDR rule that has no
/// hostname. The wasmtime runner plan maps this shape onto the
/// actual `WasiCtxBuilder`; nothing here depends on wasmtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasiTarget {
    PinnedHost { host: String, ips: Vec<IpAddr> },
    Net(IpNet),
}

/// One outbound grant in the WASI-facing shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiOutboundGrant {
    pub target: WasiTarget,
    pub proto: Proto,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// The WASI-facing projection of a resolved policy's egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasiEgress {
    Unrestricted,
    Grants(Vec<WasiOutboundGrant>),
}

/// Project the resolved policy into the WASI-facing shape. A
/// deliberately separate walk from [`canonicalize_effective`] —
/// the cross-projection witness compares the two paths' decisions
/// and exists to catch drift between them. The refusal ladder
/// (bad CIDR, unknown proto, missing/expired/empty pin,
/// mandatory-deny overlap) is intentionally identical.
pub fn to_wasi_grants(
    eff: &EffectivePolicy,
    pins: &DnsPinRegistry,
    now: &str,
) -> Result<WasiEgress, ProjectionError> {
    if eff.egress.mode.as_deref() == Some("open") {
        return Ok(WasiEgress::Unrestricted);
    }
    let mut grants = Vec::new();
    for spec in &eff.network.l4 {
        let net: IpNet = spec
            .dst_cidr
            .parse()
            .map_err(|source| ProjectionError::BadCidr {
                cidr: spec.dst_cidr.clone(),
                source,
            })?;
        refuse_mandatory_overlap(&spec.dst_cidr, &net)?;
        let (port_lo, port_hi) = normalize_ports(spec.port_lo, spec.port_hi);
        grants.push(WasiOutboundGrant {
            target: WasiTarget::Net(net),
            proto: Proto::parse(&spec.proto)?,
            port_lo,
            port_hi,
        });
    }
    for (host, port) in &eff.egress.allow_list {
        let pin = pins
            .lookup(host)
            .ok_or_else(|| ProjectionError::MissingPin { host: host.clone() })?;
        if !pin.is_valid_at(now) {
            return Err(ProjectionError::ExpiredPin {
                host: host.clone(),
                expires_at: pin.expires_at.clone(),
            });
        }
        if pin.ips.is_empty() {
            return Err(ProjectionError::EmptyPin { host: host.clone() });
        }
        for pinned in &pin.ips {
            refuse_mandatory_overlap(host, &host_net(*pinned))?;
        }
        let (port_lo, port_hi) = normalize_ports(*port, *port);
        grants.push(WasiOutboundGrant {
            target: WasiTarget::PinnedHost {
                host: host.clone(),
                ips: pin.ips.clone(),
            },
            proto: Proto::Tcp,
            port_lo,
            port_hi,
        });
    }
    Ok(WasiEgress::Grants(grants))
}

/// The WASI-side decision function. Must agree with
/// [`CanonicalEgress::permits`] for every probe — that agreement
/// is the cross-projection witness.
pub fn wasi_allows(egress: &WasiEgress, proto: &Proto, ip_addr: IpAddr, port: u16) -> bool {
    if is_mandatory_deny(ip_addr) {
        return false;
    }
    match egress {
        WasiEgress::Unrestricted => true,
        WasiEgress::Grants(grants) => grants.iter().any(|g| {
            g.proto == *proto
                && g.port_lo <= port
                && port <= g.port_hi
                && match &g.target {
                    WasiTarget::PinnedHost { ips, .. } => ips.contains(&ip_addr),
                    WasiTarget::Net(net) => net.contains(&ip_addr),
                }
        }),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-core projection`
Expected: 31 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs
git commit -m "feat(policy): WASI-facing egress projection with pinned-host targets (plan 184)"
```

---

### Task 7: `clamp` — intersection-only merge

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    fn rule(proto: Proto, cidr: &str, lo: u16, hi: u16) -> CanonicalRule {
        CanonicalRule { proto, net: net(cidr), port_lo: lo, port_hi: hi }
    }

    #[test]
    fn clamp_request_wider_than_resolved_yields_intersection() {
        // The ADR-080 clamp witness: a trace-authored request can
        // attenuate the resolved grant, never widen it.
        let requested = CanonicalEgress::Rules(vec![
            rule(Proto::Tcp, "93.184.216.34/32", 443, 443), // covered → kept
            rule(Proto::Tcp, "203.0.113.0/24", 0, 65535),   // not granted → dropped
        ]);
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.0/24", 443, 443)]);
        let granted = clamp(&requested, &resolved);
        assert!(granted.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(!granted.permits(&Proto::Tcp, ip("203.0.113.7"), 443));
    }

    #[test]
    fn clamp_unrestricted_request_cannot_widen() {
        let requested = CanonicalEgress::Unrestricted;
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 443, 443)]);
        let granted = clamp(&requested, &resolved);
        assert_eq!(granted, resolved);
    }

    #[test]
    fn clamp_request_can_attenuate_unrestricted() {
        let requested = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 443, 443)]);
        let resolved = CanonicalEgress::Unrestricted;
        let granted = clamp(&requested, &resolved);
        assert_eq!(granted, requested);
    }

    #[test]
    fn clamp_partial_port_overlap_drops_fail_closed() {
        // Conservative intersection: a requested rule only
        // partially covered by the resolved grant is dropped
        // whole, not split.
        let requested = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 80, 8080)]);
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Tcp, "93.184.216.34/32", 443, 443)]);
        let granted = clamp(&requested, &resolved);
        assert_eq!(granted, CanonicalEgress::Rules(vec![]));
    }

    #[test]
    fn clamp_is_never_wider_than_resolved_pointwise() {
        let requested = CanonicalEgress::Rules(vec![
            rule(Proto::Tcp, "10.0.0.0/8", 0, 65535),
            rule(Proto::Udp, "8.8.8.8/32", 53, 53),
        ]);
        let resolved = CanonicalEgress::Rules(vec![rule(Proto::Udp, "8.8.8.0/24", 53, 53)]);
        let granted = clamp(&requested, &resolved);
        for (proto, addr, port) in [
            (Proto::Tcp, "10.1.2.3", 443u16),
            (Proto::Udp, "8.8.8.8", 53),
            (Proto::Udp, "8.8.8.9", 53),
        ] {
            if granted.permits(&proto, ip(addr), port) {
                assert!(
                    resolved.permits(&proto, ip(addr), port),
                    "clamp widened: {proto:?} {addr}:{port}"
                );
            }
        }
        // And the covered request survives.
        assert!(granted.permits(&Proto::Udp, ip("8.8.8.8"), 53));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-core projection`
Expected: compile error — `clamp` not found.

- [ ] **Step 3: Write the implementation**

Add to `projection.rs`:

```rust
/// True when `covering` admits every probe `covered` admits:
/// same proto, supernet-or-equal, port-range superset.
fn covers(covering: &CanonicalRule, covered: &CanonicalRule) -> bool {
    covering.proto == covered.proto
        && covering.net.contains(&covered.net)
        && covering.port_lo <= covered.port_lo
        && covered.port_hi <= covering.port_hi
}

/// Intersection-only merge of a *requested* grant set against the
/// *resolved* (authoritative) one. The request can attenuate,
/// never widen: a requested rule survives only when some resolved
/// rule fully covers it; partial overlaps drop whole (fail-closed,
/// no rule splitting). `Unrestricted` on the request side grants
/// exactly the resolved set.
pub fn clamp(requested: &CanonicalEgress, resolved: &CanonicalEgress) -> CanonicalEgress {
    match (requested, resolved) {
        (CanonicalEgress::Unrestricted, _) => resolved.clone(),
        (CanonicalEgress::Rules(_), CanonicalEgress::Unrestricted) => requested.clone(),
        (CanonicalEgress::Rules(req), CanonicalEgress::Rules(res)) => CanonicalEgress::Rules(
            req.iter()
                .filter(|r| res.iter().any(|s| covers(s, r)))
                .cloned()
                .collect(),
        ),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-core projection`
Expected: 36 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs
git commit -m "feat(policy): clamp — intersection-only merge, requests attenuate never widen (plan 184)"
```

---

### Task 8: the cross-projection consistency property witness

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`

No proptest dep — a fixed-seed xorshift generator keeps the test
deterministic, fast, and dependency-free. Probes are biased toward grant
boundaries (inside each granted net/port, just outside, plus the
mandatory-deny ranges) so the comparison exercises the decision edges, not
just random space.

- [ ] **Step 1: Write the failing test**

Add a sibling test module at the bottom of `projection.rs`:

```rust
#[cfg(test)]
mod property {
    use super::*;
    use crate::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use crate::policy::policies::L4RuleSpec;
    use crate::policy::resolver::EffectivePolicy;
    use std::net::{IpAddr, Ipv4Addr};

    const NOW: &str = "2026-06-11T00:00:00Z";

    /// Deterministic xorshift64 — no rand dep at this layer.
    struct Xs(u64);

    impl Xs {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_v4(rng: &mut Xs) -> Ipv4Addr {
        Ipv4Addr::from(u32::try_from(rng.next() & 0xFFFF_FFFF).unwrap())
    }

    /// One generated policy + pins. L4 rules use random v4 nets;
    /// allow-list hosts get 1–3 pinned IPs each.
    fn generate(rng: &mut Xs) -> (EffectivePolicy, DnsPinRegistry) {
        let mut eff = EffectivePolicy::default();
        let mut pins = DnsPinRegistry::new();
        // ~1 in 16 policies exercise the open kill-switch.
        if rng.below(16) == 0 {
            eff.egress.mode = Some("open".to_string());
            return (eff, pins);
        }
        for _ in 0..rng.below(4) {
            let prefix = 8 + u8::try_from(rng.below(25)).unwrap(); // 8..=32
            let lo = u16::try_from(rng.below(1024)).unwrap();
            let hi = lo.saturating_add(u16::try_from(rng.below(2048)).unwrap());
            eff.network.l4.push(L4RuleSpec {
                proto: if rng.below(2) == 0 { "tcp" } else { "udp" }.to_string(),
                dst_cidr: format!("{}/{prefix}", random_v4(rng)),
                port_lo: lo,
                port_hi: hi,
            });
        }
        for i in 0..rng.below(3) {
            let host = format!("h{i}.example.test");
            let ips: Vec<IpAddr> = (0..1 + rng.below(3))
                .map(|_| IpAddr::V4(random_v4(rng)))
                .collect();
            pins.add(DnsPin::at(
                &host,
                ips,
                "2026-06-10T00:00:00Z",
                "2027-01-01T00:00:00Z",
            ));
            let port = u16::try_from(rng.below(9000)).unwrap(); // 0 = any-port sometimes
            eff.egress.allow_list.push((host, port));
        }
        (eff, pins)
    }

    /// Probes biased to decision edges: for every canonical rule,
    /// an inside hit, a port-boundary miss, and a net miss; plus
    /// the fixed mandatory-deny set and pure-random probes.
    fn probes(rng: &mut Xs, eg: &CanonicalEgress) -> Vec<(Proto, IpAddr, u16)> {
        let mut out: Vec<(Proto, IpAddr, u16)> = vec![
            (Proto::Tcp, "169.254.169.254".parse().unwrap(), 443),
            (Proto::Tcp, "127.0.0.1".parse().unwrap(), 80),
            (Proto::Udp, "100.64.0.1".parse().unwrap(), 53),
            (Proto::Tcp, "::1".parse().unwrap(), 443),
        ];
        if let CanonicalEgress::Rules(rules) = eg {
            for r in rules {
                out.push((r.proto, r.net.network(), r.port_lo)); // inside
                out.push((r.proto, r.net.network(), r.port_hi.wrapping_add(1))); // port edge
                out.push((
                    match r.proto {
                        Proto::Tcp => Proto::Udp,
                        Proto::Udp => Proto::Tcp,
                    },
                    r.net.network(),
                    r.port_lo,
                )); // proto miss
            }
        }
        for _ in 0..32 {
            out.push((
                if rng.below(2) == 0 { Proto::Tcp } else { Proto::Udp },
                IpAddr::V4(random_v4(rng)),
                u16::try_from(rng.below(65536)).unwrap(),
            ));
        }
        out
    }

    /// ADR-080 §8 P5: the cross-projection consistency witness.
    /// For every generated policy, the canonical (CIDR-keyed) and
    /// WASI (hostname-keyed) projections either refuse identically
    /// or decide identically on every probe — and no projection
    /// ever admits a mandatory-deny address.
    #[test]
    fn cross_projection_consistency_property() {
        let mut rng = Xs(0x184_0b5e55ed);
        let mut policies_checked = 0u32;
        let mut probes_checked = 0u32;
        for _ in 0..512 {
            let (eff, pins) = generate(&mut rng);
            let canonical = canonicalize_effective(&eff, &pins, NOW);
            let wasi = to_wasi_grants(&eff, &pins, NOW);
            match (canonical, wasi) {
                (Err(c), Err(w)) => {
                    // Identical refusal ladder: same variant.
                    assert_eq!(
                        std::mem::discriminant(&c),
                        std::mem::discriminant(&w),
                        "refusal drift: canonical={c:?} wasi={w:?}"
                    );
                }
                (Ok(eg), Ok(w)) => {
                    policies_checked += 1;
                    for (proto, addr, port) in probes(&mut rng, &eg) {
                        probes_checked += 1;
                        let c = eg.permits(&proto, addr, port);
                        let ww = wasi_allows(&w, &proto, addr, port);
                        assert_eq!(
                            c, ww,
                            "projection drift on {proto:?} {addr}:{port}\n eff={eff:?}"
                        );
                        if is_mandatory_deny(addr) {
                            assert!(!c, "mandatory-deny admitted: {addr}");
                        }
                    }
                }
                (c, w) => panic!("one projection refused, the other admitted: {c:?} / {w:?}"),
            }
        }
        // Generator sanity: the property must have exercised real
        // grants, not 512 vacuous deny-alls.
        assert!(policies_checked > 200, "only {policies_checked} policies admitted");
        assert!(probes_checked > 5_000, "only {probes_checked} probes checked");
    }

    /// Clamp soundness over the same generator: the granted set
    /// never admits a probe the resolved set denies.
    #[test]
    fn clamp_never_widens_property() {
        let mut rng = Xs(0x184_c1a3b);
        for _ in 0..256 {
            let (req_eff, req_pins) = generate(&mut rng);
            let (res_eff, res_pins) = generate(&mut rng);
            let (Ok(requested), Ok(resolved)) = (
                canonicalize_effective(&req_eff, &req_pins, NOW),
                canonicalize_effective(&res_eff, &res_pins, NOW),
            ) else {
                continue; // refusals covered by the other property
            };
            let granted = clamp(&requested, &resolved);
            for (proto, addr, port) in probes(&mut rng, &granted) {
                if granted.permits(&proto, addr, port) {
                    assert!(
                        resolved.permits(&proto, addr, port),
                        "clamp widened: {proto:?} {addr}:{port}"
                    );
                }
            }
        }
    }
}
```

Note: `is_mandatory_deny` must be imported in scope (it is `use`d at module
level already from Task 2). Generated nets/pins can land in mandatory-deny
ranges by chance — that is the `(Err, Err)` branch doing its job: both
projections must refuse identically.

- [ ] **Step 2: Run the property tests**

Run: `cargo nextest run -p mvm-core projection::property`
Expected: both tests PASS in well under a second. If `cross_projection_consistency_property` fails its generator-sanity floor (`policies_checked > 200`), the generator is producing too many refusals — lower the chance a random net overlaps a deny range by retrying generation, do **not** lower the floor.

- [ ] **Step 3: Run the full module suite**

Run: `cargo nextest run -p mvm-core projection`
Expected: 38 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs
git commit -m "test(policy): cross-projection consistency + clamp-never-widens property witnesses (plan 184)"
```

---

### Task 9: exports, gates, and spec bookkeeping

**Files:**
- Modify: `crates/mvm-core/src/policy/mod.rs`
- Modify: `specs/adrs/080-wasm-preview-promotion-and-capability-policy.md` (§8 table, P5 row)
- Modify: `specs/REFACTOR-STATUS.md`
- Modify: `specs/plans/184-capability-projection-seam.md` (tick boxes)

- [ ] **Step 1: Re-export the public surface**

In `crates/mvm-core/src/policy/mod.rs`, alongside the module's existing re-exports, add:

```rust
pub use projection::{
    CanonicalEgress, CanonicalRule, Proto, ProjectionError, WasiEgress, WasiOutboundGrant,
    WasiTarget, canonicalize_effective, clamp, to_wasi_grants, wasi_allows,
};
```

(Match the file's existing `pub use` style — if it re-exports selectively rather than broadly, follow that pattern and re-export at minimum `canonicalize_effective`, `clamp`, `CanonicalEgress`, `WasiEgress`.)

- [ ] **Step 2: Run the full verification gates**

```bash
cargo fmt --all -- --check          # --all matters; CI checks the whole workspace
cargo nextest run -p mvm-core       # the new module + no regressions in mvm-core
cargo nextest run --workspace       # cross-crate fallout (additive change — expect green)
cargo test --workspace --doc        # nextest skips doctests
cargo clippy --workspace -- -D warnings
cargo run -p xtask -- check-spec-numbers   # plan-184 number collision guard
```

Expected: all green. (Local macOS caveat: `mvm-backend` test binaries can be SIGKILL'd by codesign — if that fires, rerun with `-E 'not package(mvm-backend)'`; it is environmental, not a regression.) If fmt complains, run `rustup run nightly cargo fmt --all` — CI's Lint job uses nightly rustfmt.

- [ ] **Step 3: Update ADR-080 §8 P5 row with the real witness names**

In `specs/adrs/080-wasm-preview-promotion-and-capability-policy.md`, edit the P5 row of the §8 table:

```markdown
| P5 | Projection consistency (§3) | `cross_projection_consistency_property` + `clamp_never_widens_property` + `rebinding_pin_into_metadata_range_refuses` (mvm-core `policy::projection`) — landed by Plan 184. Remaining for P5 close-out: wire `LiveL4Gate`/`PlanFlowPolicy` to consume `CanonicalEgress` (kernel-side), and the `WasiCtxBuilder` mapping (runner plan). |
```

- [ ] **Step 4: Update the rollup + tick this plan's boxes**

- `specs/REFACTOR-STATUS.md`: add a Plan 184 line under the in-flight plans with the workstream state (seam + witnesses landed; enforcement wiring deferred to the kernel-wiring and wasm-runner plans), bump "Last updated".
- This file: tick every completed checkbox in the same commit.

- [ ] **Step 5: Final commit**

```bash
git add crates/mvm-core/src/policy/mod.rs specs/adrs/080-wasm-preview-promotion-and-capability-policy.md specs/REFACTOR-STATUS.md specs/plans/184-capability-projection-seam.md
git commit -m "feat(policy): export projection seam; record P5 witnesses in ADR-080 (plan 184)"
```

---

## Out of scope (deliberately — later plans)

- **Kernel-side consumption**: `LiveL4Gate` / `PlanFlowPolicy` / nftables reading `CanonicalEgress` instead of re-translating `L4RuleSpec` — the wiring half of P5's close-out.
- **`WasiCtxBuilder` mapping**: `WasiEgress` → actual wasmtime context (the wasm-component runner plan; wasmtime is not a dependency of this plan).
- **The live DNS resolver** that populates `DnsPinRegistry` at admission (dns_pin.rs documents this as mvmd/supervisor-side).
- **Tier-0 preview surfacing** of `permits` verdicts (decision-honest preview plan).
- All other ADR-080 §8 rows (P1–P4, P6–P8).

# Plan 190 — Kernel-side egress decision converges on `CanonicalEgress` (ADR-080 P5 close-out) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the kernel leg of ADR-080 P5: make the host-side L4 egress *decision* run through the shared `mvm_core::policy::projection::CanonicalEgress::permits` (the same decision function the WASI projection and the preview tier use) instead of the duplicate `L4Policy::evaluate` — **with zero claim-10 behaviour change**. One decision function, one rule type, two enforcement points that provably agree.

## The decision (and the one rejected)

Wiring the kernel through the projection seam has a fork that touches claim-10 (default-deny egress), so it is stated up front:

- **CHOSEN — lenient kernel lowering, no behaviour change.** A new `canonicalize_l4` lowers `[L4RuleSpec]` to a `CanonicalEgress` and refuses **only** the malformed inputs today's `LiveL4Gate::from_specs` already refuses (bad CIDR, unknown proto, inverted port range) — it does **not** refuse a rule that overlaps a mandatory-deny range. Mandatory-deny is still enforced at runtime two ways: `CanonicalEgress::permits` checks `is_mandatory_deny` first and unconditionally (so a metadata/loopback/CGNAT IP is denied no matter what rule "matches"), and the always-on `MandatoryDenyEgressScan` packet stage is unchanged. Net effect on every packet is byte-identical to today.
- **REJECTED — strict whole-policy-fail-closed.** Routing the kernel through `canonicalize_effective` (which calls `refuse_mandatory_overlap`) would make a *single* mandatory-deny-overlapping rule (e.g. `allow 169.254.0.0/16`) fail the **whole** policy closed to deny-all, killing the *other* (legitimate) rules in the same policy. That is stricter and arguably more honest, but it is a claim-10 behaviour change with surprising blast radius (one typo nukes all egress) and it is unnecessary here: the runtime `permits` mandatory-deny-first check + the `MandatoryDenyEgressScan` backstop already make a metadata grant unreachable. Admission-time refusal of illegal grants stays where it belongs — on the projection/preview path (`canonicalize_effective`), not on the live packet path.

**Architecture:** Add `canonicalize_l4(&[L4RuleSpec]) -> Result<CanonicalEgress, ProjectionError>` to `mvm-core`'s projection module (the existing `canonicalize_effective` L4 loop, minus the mandatory-deny-overlap refusal). In `mvm-hostd`, `L4PolicyScan` holds a `CanonicalEgress` and decides via `CanonicalEgress::permits`; `build_egress_scan` takes `Option<CanonicalEgress>`; the gateway bridge builds it with `canonicalize_l4(&eff.network.l4).unwrap_or_else(|_| CanonicalEgress::Rules(vec![]))` (deny-all on malformed, same fail-closed posture as today's `unwrap_or_else(L4Policy::deny_all())`). The now-duplicate `L4Policy` / `L4Rule` / `L4Decision` / `LiveL4Gate` / `L4SpecError` in `crates/mvm-hostd/src/supervisor/proxy/l4.rs` are deleted; their claim-10 witnesses migrate to `canonicalize_l4` + `CanonicalEgress::permits` equivalents (many already exist as projection property tests). `PlanFlowPolicy` (coarse flow gate), `MandatoryDenyEgressScan`, and `DnsSinkholeScan` are **unchanged** — the heterogeneous-layers principle (ADR-080 §3) is preserved.

**Tech Stack:** Rust; no new dependencies. `CanonicalEgress` / `CanonicalRule` / `Proto` / `canonicalize_effective` ship in `mvm-core::policy::projection` (Plan 188 / PR #801). `cargo nextest`.

**DEPENDENCY:** This plan consumes `CanonicalEgress` + the projection module, which land with **Plan 188 (PR #801)**. Do not start until #801 is merged to `main`; branch this off the post-#801 `main`. Plan number 190 was free at authoring (main holds 182–185; the 184/186/187/188 stack is in flight).

**Existing code this plan builds on (read before starting):**
- `crates/mvm-core/src/policy/projection.rs` — `canonicalize_effective` (the L4 loop to mirror, minus `refuse_mandatory_overlap`), `CanonicalEgress` (`Unrestricted` | `Rules(Vec<CanonicalRule>)`), `CanonicalEgress::permits(&Proto, IpAddr, u16) -> bool` (mandatory-deny checked first), `CanonicalRule`, `Proto` (`Tcp`/`Udp`, `parse`), `ProjectionError` (`BadCidr`/`UnknownProto`/`InvertedPortRange`/…), `normalize_ports`, `refuse_inverted_ports`.
- `crates/mvm-hostd/src/supervisor/proxy/l4.rs` — `LiveL4Gate::from_specs(&[L4RuleSpec]) -> Result<Self, L4SpecError>`, `L4Policy { rules }`, `L4Rule { proto, dst_cidr, port_lo, port_hi }`, `L4Policy::evaluate(Protocol, IpAddr, u16) -> L4Decision`, `L4Policy::deny_all()`. Tests `from_specs_*`, `live_l4_gate_*`, `l4_policy_*` are the claim-10 witnesses.
- `crates/mvm-hostd/src/supervisor/network/stages.rs` — `L4PolicyScan { policy: L4Policy }` + its `ScanStage::scan` (maps `pkt.five_tuple` proto/ip/port → `policy.evaluate`), `build_egress_scan(l4: Option<L4Policy>, dns_allow: Vec<String>) -> Arc<dyn ScanStage>`, `MandatoryDenyEgressScan` (unchanged), `DnsSinkholeScan` (unchanged). Tests `l4_policy_deny_all_drops_every_egress`, `l4_policy_allows_only_matching_proto_ip_port`, `l4_policy_ignores_ingress`, `build_egress_scan_*`, `scan_chain_mandatory_deny_wins_over_a_permissive_policy`.
- `crates/mvm-hostd/src/supervisor/gateway_bridge.rs` (~line 547) — `let l4 = LiveL4Gate::from_specs(&eff.network.l4).map(|g| g.policy).unwrap_or_else(|_| L4Policy::deny_all());` then `build_egress_scan(Some(l4), dns_allow)`. `PlanFlowPolicy::from_effective` (unchanged).

---

### Task 1: `canonicalize_l4` — lenient L4 lowering in mvm-core

**Files:**
- Modify: `crates/mvm-core/src/policy/projection.rs`
- Modify: `crates/mvm-core/src/policy/mod.rs` (re-export `canonicalize_l4`)

- [x] **Step 1: Write failing tests** in the projection `tests` module (reuse the existing `l4`/`ip`/`net` helpers there):

```rust
    #[test]
    fn canonicalize_l4_lowers_rules_like_canonicalize_effective() {
        let specs = vec![l4("tcp", "93.184.216.0/24", 443, 443), l4("udp", "8.8.8.8/32", 0, 0)];
        let eg = canonicalize_l4(&specs).unwrap();
        assert!(eg.permits(&Proto::Tcp, ip("93.184.216.34"), 443));
        assert!(eg.permits(&Proto::Udp, ip("8.8.8.8"), 53)); // (0,0) any-port
        assert!(!eg.permits(&Proto::Tcp, ip("93.184.216.34"), 80));
    }

    #[test]
    fn canonicalize_l4_refuses_bad_cidr_and_unknown_proto_and_inverted_ports() {
        assert!(matches!(canonicalize_l4(&[l4("tcp", "nope", 1, 1)]).unwrap_err(), ProjectionError::BadCidr { .. }));
        assert!(matches!(canonicalize_l4(&[l4("icmp", "8.8.8.8/32", 0, 0)]).unwrap_err(), ProjectionError::UnknownProto { .. }));
        assert!(matches!(canonicalize_l4(&[l4("tcp", "8.8.8.8/32", 443, 80)]).unwrap_err(), ProjectionError::InvertedPortRange { .. }));
    }

    #[test]
    fn canonicalize_l4_does_not_refuse_mandatory_deny_overlap_but_permits_denies_it() {
        // The lenient kernel lowering BUILDS a metadata-overlapping rule
        // (unlike canonicalize_effective, which refuses it), but the
        // decision function still denies the metadata IP — mandatory-deny
        // is checked first in permits().
        let eg = canonicalize_l4(&[l4("tcp", "169.254.0.0/16", 0, 0)]).expect("lenient: builds, no refusal");
        assert!(!eg.permits(&Proto::Tcp, ip("169.254.169.254"), 80), "metadata denied at decision time");
    }

    #[test]
    fn canonicalize_l4_empty_is_deny_all() {
        let eg = canonicalize_l4(&[]).unwrap();
        assert!(!eg.permits(&Proto::Tcp, ip("8.8.8.8"), 53));
        assert_eq!(eg, CanonicalEgress::Rules(vec![]));
    }
```

- [x] **Step 2: Run to verify failure** — `cargo nextest run -p mvm-core projection` (compile error: `canonicalize_l4` not found).

- [x] **Step 3: Implement.** Factor the L4 row→`CanonicalRule` conversion out of `canonicalize_effective` into a shared helper that takes a `refuse_overlap: bool` flag (so the two callers share one loop and can't drift), or add `canonicalize_l4` as a sibling that mirrors the loop minus `refuse_mandatory_overlap`. Preferred (DRY): a private `lower_l4_specs(specs, refuse_overlap) -> Result<Vec<CanonicalRule>, ProjectionError>`; `canonicalize_effective` calls it with `true`, `canonicalize_l4` with `false`:

```rust
/// Lower L4 rule specs to canonical rules. `refuse_overlap` gates the
/// admission-time mandatory-deny refusal: the projection/preview path
/// (canonicalize_effective) passes true; the kernel packet path passes
/// false, because permits() denies mandatory-deny ranges at decision
/// time and the always-on deny scan backstops it.
fn lower_l4_specs(
    specs: &[crate::policy::policies::L4RuleSpec],
    refuse_overlap: bool,
) -> Result<Vec<CanonicalRule>, ProjectionError> {
    let mut rules = Vec::new();
    for spec in specs {
        let net: IpNet = spec.dst_cidr.parse().map_err(|source| ProjectionError::BadCidr {
            cidr: spec.dst_cidr.clone(),
            source,
        })?;
        if refuse_overlap {
            refuse_mandatory_overlap(&spec.dst_cidr, &net)?;
        }
        refuse_inverted_ports(&spec.dst_cidr, spec.port_lo, spec.port_hi)?;
        let (port_lo, port_hi) = normalize_ports(spec.port_lo, spec.port_hi);
        rules.push(CanonicalRule { proto: Proto::parse(&spec.proto)?, net, port_lo, port_hi });
    }
    Ok(rules)
}

/// Lenient L4 lowering for the kernel packet path: malformed-input
/// refusals only (bad CIDR, unknown proto, inverted ports). Does NOT
/// refuse mandatory-deny overlap — see lower_l4_specs / permits().
pub fn canonicalize_l4(
    specs: &[crate::policy::policies::L4RuleSpec],
) -> Result<CanonicalEgress, ProjectionError> {
    let mut rules = lower_l4_specs(specs, false)?;
    rules.sort();
    rules.dedup();
    Ok(CanonicalEgress::Rules(rules))
}
```

Refactor `canonicalize_effective`'s L4 loop to call `lower_l4_specs(&eff.network.l4, true)` (preserving its existing behaviour + the allow-list extension). Re-export `canonicalize_l4` from `policy/mod.rs` alongside the other projection exports.

- [x] **Step 4: Verify** — `cargo nextest run -p mvm-core projection` (all prior projection tests + 4 new green; the cross-projection + clamp property witnesses must still pass — they exercise `canonicalize_effective`, which now routes through `lower_l4_specs(_, true)`).

- [x] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection.rs crates/mvm-core/src/policy/mod.rs
git commit -m "feat(policy): canonicalize_l4 — lenient kernel-path L4 lowering (plan 190)"
```

---

### Task 2: `L4PolicyScan` decides via `CanonicalEgress`

**Files:**
- Modify: `crates/mvm-hostd/src/supervisor/network/stages.rs`

- [x] **Step 1: Adapt the claim-10 witnesses** (write the new shape first; they should keep asserting the SAME behaviour). Change `L4PolicyScan::new` to take a `CanonicalEgress`, and the tests to build one via `canonicalize_l4` or directly. Keep the test NAMES (claim-10 witness continuity): `l4_policy_deny_all_drops_every_egress` (empty `CanonicalEgress::Rules(vec![])`), `l4_policy_allows_only_matching_proto_ip_port`, `l4_policy_ignores_ingress`. Each must assert the identical drop/pass outcomes as today.

- [x] **Step 2: Run** to verify the tests fail to compile (signature changed).

- [x] **Step 3: Implement.** Replace the field + scan body:

```rust
use mvm_core::policy::projection::{CanonicalEgress, Proto as CanonProto};

pub struct L4PolicyScan {
    egress: CanonicalEgress,
}

impl L4PolicyScan {
    pub fn new(egress: CanonicalEgress) -> Self {
        Self { egress }
    }
}

impl ScanStage for L4PolicyScan {
    fn scan(&self, ctx: &PacketCtx<'_>, pkt: &ParsedPacket<'_>) -> ScanOutcome {
        match ctx.direction {
            FlowDirection::Egress => {}
            _ => return ScanOutcome::Pass,
        }
        let proto = match pkt.five_tuple.proto {
            L4Proto::Tcp => CanonProto::Tcp,
            L4Proto::Udp => CanonProto::Udp,
        };
        if self.egress.permits(&proto, pkt.five_tuple.dst_ip, pkt.five_tuple.dst_port) {
            ScanOutcome::Pass
        } else {
            ScanOutcome::Drop { by: self.name() }
        }
    }
}
```

- [x] **Step 4: Verify** — `cargo nextest run -p mvm-hostd network::stages` (the migrated witnesses + `scan_chain_mandatory_deny_wins_over_a_permissive_policy` green).

- [x] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/supervisor/network/stages.rs
git commit -m "refactor(hostd): L4PolicyScan decides via CanonicalEgress::permits (plan 190)"
```

---

### Task 3: `build_egress_scan` + gateway bridge consume `CanonicalEgress`; delete the `L4Policy` duplicate

**Files:**
- Modify: `crates/mvm-hostd/src/supervisor/network/stages.rs` (`build_egress_scan` signature + its tests)
- Modify: `crates/mvm-hostd/src/supervisor/gateway_bridge.rs` (the construction site)
- Delete: the now-unused `L4Policy`/`L4Rule`/`L4Decision`/`LiveL4Gate`/`L4SpecError` in `crates/mvm-hostd/src/supervisor/proxy/l4.rs` (and its module wiring) — **only after** confirming no other consumers via `rg 'L4Policy|LiveL4Gate|L4Rule|L4Decision|L4SpecError' crates/`.

- [x] **Step 1: Adapt `build_egress_scan` tests** (`build_egress_scan_some_chains_policy_under_mandatory_deny` etc.) to pass `Option<CanonicalEgress>`. Keep names + assertions.

- [x] **Step 2: Implement signature change:**

```rust
pub fn build_egress_scan(l4: Option<CanonicalEgress>, dns_allow: Vec<String>) -> Arc<dyn ScanStage> {
    let mut stages: Vec<Arc<dyn ScanStage>> = vec![
        Arc::new(MandatoryDenyEgressScan),
        Arc::new(PlaceholderLeakScan),
    ];
    if let Some(eg) = l4 {
        stages.push(Arc::new(L4PolicyScan::new(eg)));
    }
    if !dns_allow.is_empty() {
        stages.push(Arc::new(DnsSinkholeScan::new(dns_allow)));
    }
    Arc::new(ScanChain::new(stages))
}
```

- [x] **Step 3: Update the gateway bridge** construction (gateway_bridge.rs ~547):

```rust
let l4 = mvm_core::policy::projection::canonicalize_l4(&eff.network.l4)
    .unwrap_or_else(|_| mvm_core::policy::projection::CanonicalEgress::Rules(Vec::new()));
```

(deny-all on malformed = empty `Rules`, mirroring today's `unwrap_or_else(L4Policy::deny_all())`). Pass `Some(l4)` to `build_egress_scan`. The `dns_allow` derivation and `PlanFlowPolicy::from_effective(&eff)` lines are **unchanged**.

- [x] **Step 4: Delete the duplicate.** Confirm `rg 'LiveL4Gate|L4Policy|L4Rule|L4Decision|L4SpecError' crates/` shows only the l4.rs definitions + their own tests remain, then remove them (and the `proxy/l4.rs` module decl if the file becomes empty, or trim it to whatever non-L4 content it holds — read it first). Migrate any still-valuable `from_specs_refuses_bad_cidr` / `from_specs_refuses_unknown_protocol` assertions to the `canonicalize_l4` tests in Task 1 if not already covered (they are: `canonicalize_l4_refuses_bad_cidr_and_unknown_proto_and_inverted_ports`).

- [x] **Step 5: Verify** — `cargo nextest run -p mvm-hostd` (all green; especially the claim-10 witnesses) and `rg 'LiveL4Gate|L4Policy' crates/` returns nothing (or only unrelated names).

- [x] **Step 6: Commit**

```bash
git add crates/mvm-hostd/src/supervisor
git commit -m "refactor(hostd): gateway bridge builds egress scan from CanonicalEgress; delete L4Policy duplicate (plan 190)"
```

---

### Task 4: equivalence witness + gates + spec bookkeeping

**Files:**
- Modify: `crates/mvm-hostd/src/supervisor/network/stages.rs` (add an equivalence test)
- Modify: `specs/adrs/080-wasm-preview-promotion-and-capability-policy.md` (§8 P5 row — note the kernel leg landed)
- Modify: `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`
- Modify: `specs/plans/190-kernel-canonical-egress.md` (tick boxes)

- [x] **Step 1: No-behaviour-change equivalence test.** Add a test that builds the same policy two ways and asserts identical packet verdicts across a probe set — the canonical proof that the refactor changed nothing observable. Construct a few `L4RuleSpec`s, lower via `canonicalize_l4`, and assert `permits` agrees with a hand-written oracle (proto/CIDR/port membership + mandatory-deny-first) over: an in-rule hit, an out-of-rule miss, a port-edge miss, a proto miss, and each mandatory-deny range. (This is the kernel-side analogue of the projection cross-consistency witness.)

- [x] **Step 2: full gates** (per [[feedback_ci_gate_list_completeness]] — match CI exactly):

```bash
cargo fmt --all -- --check || rustup run nightly cargo fmt --all
cargo run -p xtask -- check-no-spec-refs-in-comments
cargo run -p xtask -- check-spec-numbers
RUSTFLAGS="-D warnings" cargo build --workspace --all-targets 2>&1 | tail -5
cargo nextest run --workspace 2>&1 | tail -6   # claim-10 witnesses are the regression net
cargo test --workspace --doc 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | tail -5
```
(Environmental caveats: mvm-backend codesign SIGKILL; embedded-binary ELF test under skip-embed.)

- [x] **Step 3: ADR-080 §8 P5 row** — append that the kernel leg landed: `Kernel-side close-out (Plan 190): canonicalize_l4 (lenient — no mandatory-deny-overlap refusal, runtime permits()+MandatoryDenyEgressScan enforce it) feeds L4PolicyScan via CanonicalEgress::permits; L4Policy duplicate deleted; claim-10 witnesses migrated, no behaviour change. Remaining: WASI-context mapping (runner plan).`

- [x] **Step 4: REFACTOR-STATUS + SPRINT** — record Plan 190 (kernel leg landed, no claim-10 behaviour change); bump "Last updated". In SPRINT.md, note it under the relevant in-flight section.

- [x] **Step 5: tick boxes; commit; PR off main.**

```bash
git add crates/ specs/
git commit -m "test(hostd): kernel egress equivalence witness; record plan 190 in ADR-080 P5 (plan 190)"
```

---

## Out of scope (deliberately)

- **The WASI-context mapping** (`WasiEgress` → wasmtime `WasiCtxBuilder`) — the other P5 consumer; its own plan, gated on a wasmtime dep.
- **The allow-list / DNS-pin leg of CanonicalEgress on the kernel** — `DnsPinRegistry` is not populated host-side (resolver lives in mvmd). The kernel keeps `DnsSinkholeScan` (hostname-string gating) until host-side pin resolution lands. This plan wires only the **L4 CIDR** leg.
- **`PlanFlowPolicy` (coarse flow gate)** — left as `from_effective(&eff)`; it is the independent coarse layer and is deliberately not routed through the projection (ADR-080 §3 heterogeneity).
- **Firecracker nftables path** — uses `install_default_deny`, not the gateway-bridge scan chain; out of scope.

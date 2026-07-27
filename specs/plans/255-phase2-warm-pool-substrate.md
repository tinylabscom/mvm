# Plan 255 Phase 2 — Warm-pool claim substrate (Firecracker-first) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `spawn_standby` / `claim_standby` on the `WorkloadRunner` so a warm claim forks a clean parent into a fresh, signed, admitted child gated identically to a cold boot, and enable the `standby_pool` capability for Firecracker only.

**Architecture:** Three layers — the `WorkloadRunner` owns authority + guards (new `spawn_standby`/`claim_standby`, a shared `ClaimGuards` sequence, and a never-promote rule); the FC driver owns VMM spawn/fork (clean-parent boot + `FcForkRestorer`); `SupervisorStandbyPool` owns bookkeeping. The Phase-1 `materialize_child_from_parent` is the CoW substrate. The parent seam is tier-agnostic (checkpoint-backed now; Plan 265 upgrades restore to live-memory).

**Tech Stack:** Rust workspace; `mvm-runtime` (`workload_runner`, `standby_pool`, `firecracker`, `warm_snapshot`); `mvm-core` (`plan`, `crypto::vmgenid`); `mvm-protocol` (`protocol::vm_backend` standby types); cucumber-rs BDD (`crates/mvm-conformance`).

Design note: `specs/notes/2026-07-27-plan-255-phase2-warm-pool-substrate-design.md` (the source of truth for the claim data-flow and the security surfaces — read it before starting).

## Global Constraints

- Vsock is the sole guest↔host and egress boundary; no NIC/host-socket data plane.
- One guest = one workload; a warm parent is a factory, never a workload.
- The guest never sees secrets; substitution stays host-side.
- A warm claim is gated at least as strictly as a cold boot — never less. Cold boot and warm claim call the *same* `ClaimGuards` code; divergence must be unrepresentable.
- Fork/restore fails closed: an un-audited, tampered, mismatched, replayed, or expired parent/plan refuses before any boot, endpoint, or persisted child side effect.
- Rust best-practices are binding: typed enums over stringly, builders for many-field, small single-purpose functions, exhaustive matches, `≤500`-line functions, and NEVER `#[allow(clippy::...)]`.
- No spec/PR/issue references in code comments or `.feature`/step files (`check-no-spec-refs` bans `Plan N`, `ADR-\d+`, `#NNNN`, `W\d.`). Phrase the concept.
- No competitor proper nouns anywhere. No AI-tool attribution in commits.
- Do not add or modify any `.feature` file the `feat/plan255-fast-start` branch is introducing (restore / no-NIC / SLO / attach-reverify witnesses belong to Plan 265). No witness overlap.
- `check-claim-catalog` must stay green with no catalog edits (this reinforces claims 8/3/1 on the warm path; Plan 265 registers the new numbered witnesses).
- Error convention: `anyhow` in `mvm-runtime`; a `thiserror` `ClaimRefusal` enum carries the distinct fail-closed reasons so tests can match them.

### Per-phase verification gates (run before every commit that closes a task)

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo nextest run --workspace` + `cargo test --workspace --doc`
- touched cucumber scenarios green via `just bdd`
- `cargo run -p xtask -- check-claim-catalog`, `check-cli-runtime-surface`, `check-core-runtime-free`
- `git commit` without `-q` (a local hook false-matches `-q`).

---

## File Structure

- Create `crates/mvm-runtime/src/workload_runner/claim.rs` — the claim types (`ClaimRefusal`, `ClaimOutcome`), the pure `bind_plan_to_parent` gate, and the `ClaimGuards` builder. One responsibility: the guarded claim vocabulary shared by cold boot and warm claim.
- Modify `crates/mvm-runtime/src/workload_runner/runner.rs` — implement `spawn_standby` / `claim_standby`; route cold boot through `ClaimGuards`; refuse a workload `run` on a parent `VmId`.
- Modify `crates/mvm-runtime/src/workload_runner/mod.rs` — declare `mod claim;`.
- Modify `crates/mvm-runtime/src/driver/fc.rs` — flip `standby_pool` to `true` in the FC driver's `capabilities()`.
- Modify `crates/mvm-runtime/src/firecracker.rs` — expose the clean-parent spawn + reuse `FcForkRestorer` behind the driver's `spawn_standby`/`claim_standby` delegation (as needed).
- Modify `crates/mvm-cli/src/exec.rs` / `crates/mvm-cli/src/commands/pool.rs` — allow `try_warm_claim` to route through the now-enabled FC capability.
- Create `features/suites/s6_admission_audit/warm_claim_fresh_identity.feature` + `crates/mvm-conformance/tests/steps/warm_claim.rs` (+ `mod warm_claim;` in `steps/mod.rs`) — the one hermetic BDD witness.

---

## Task 1: Claim refusal + outcome types

**Files:**
- Create: `crates/mvm-runtime/src/workload_runner/claim.rs`
- Modify: `crates/mvm-runtime/src/workload_runner/mod.rs` (add `mod claim;`)
- Test: unit tests in `claim.rs`

**Interfaces:**
- Produces: `pub enum ClaimRefusal` (thiserror) with variants `ParentNotClaimable`, `ParentUnaudited`, `ParentTampered`, `PlanExpired`, `PlanReplayed`, `PlanParentMismatch { expected: String, got: String }`, `ParentPromotionRefused`; `pub enum ClaimOutcome { Claimed(VmId), Refused(ClaimRefusal) }`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_reasons_are_distinct_and_described() {
        let m = ClaimRefusal::PlanParentMismatch { expected: "sha256:aa".into(), got: "sha256:bb".into() };
        assert!(m.to_string().contains("sha256:aa"));
        assert!(m.to_string().contains("sha256:bb"));
        // Distinct variants must not compare equal.
        assert_ne!(
            ClaimRefusal::ParentUnaudited.to_string(),
            ClaimRefusal::ParentTampered.to_string()
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-runtime workload_runner::claim -- refusal_reasons`
Expected: FAIL — `claim` module / `ClaimRefusal` does not exist.

- [ ] **Step 3: Write minimal implementation**

```rust
use crate::vm::name_registry::VmId; // adapt the import path to the actual VmId location

#[derive(Debug, thiserror::Error)]
pub enum ClaimRefusal {
    #[error("parent is not in a claimable state")]
    ParentNotClaimable,
    #[error("parent has no signed audit entry; refusing to fork an un-audited parent")]
    ParentUnaudited,
    #[error("parent record drifted from its sealed content; refusing a tampered parent")]
    ParentTampered,
    #[error("child plan is outside its validity window")]
    PlanExpired,
    #[error("child plan nonce was already seen; refusing a replayed claim")]
    PlanReplayed,
    #[error("plan image digest {expected} does not match parent rootfs digest {got}")]
    PlanParentMismatch { expected: String, got: String },
    #[error("refusing to run a workload directly on a warm parent")]
    ParentPromotionRefused,
}

#[derive(Debug)]
pub enum ClaimOutcome {
    Claimed(VmId),
    Refused(ClaimRefusal),
}
```

Add `mod claim;` to `workload_runner/mod.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-runtime workload_runner::claim -- refusal_reasons`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/workload_runner/claim.rs crates/mvm-runtime/src/workload_runner/mod.rs
git commit -m "feat(runtime): claim refusal + outcome types for the warm-pool claim path"
```

---

## Task 2: Plan↔parent binding gate (surface 1)

Bind the admitted plan's image digest to the verified parent's actual rootfs, so the audit-recorded plan always describes exactly what boots.

**Files:**
- Modify: `crates/mvm-runtime/src/workload_runner/claim.rs`
- Test: unit tests in `claim.rs`

**Interfaces:**
- Consumes: `mvm_core::checkpoint::{CheckpointMeta, ContentBlob}` (a `CheckpointMeta` has `content: Vec<ContentBlob>`, each `ContentBlob { name: String, sha256: String }`); `mvm_core::plan::ExecutionPlan` (`plan.image.sha256` is the 64-hex rootfs digest).
- Produces: `pub fn parent_rootfs_digest(meta: &CheckpointMeta) -> Result<&str, ClaimRefusal>`; `pub fn bind_plan_to_parent(plan_image_sha256: &str, meta: &CheckpointMeta) -> Result<(), ClaimRefusal>`.

The parent's rootfs digest is the `ContentBlob` named `rootfs.ext4` — `verify_content` (run earlier in the claim) already proved that blob's sha256 equals the file on disk, so comparing against it transitively binds the plan to the bytes that boot. Note `plan.image.sha256` is bare 64-hex; the blob sha256 is also bare hex — compare directly (do not prefix with `sha256:`).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn bind_accepts_matching_and_rejects_mismatched_rootfs() {
    let meta = fake_meta_with_rootfs("aa".repeat(32)); // 64-hex helper below
    // matching
    assert!(bind_plan_to_parent(&"aa".repeat(32), &meta).is_ok());
    // mismatch → PlanParentMismatch
    let err = bind_plan_to_parent(&"bb".repeat(32), &meta).unwrap_err();
    assert!(matches!(err, ClaimRefusal::PlanParentMismatch { .. }));
}

#[test]
fn parent_without_rootfs_blob_refuses() {
    let meta = fake_meta_without_rootfs();
    assert!(matches!(
        bind_plan_to_parent(&"aa".repeat(32), &meta),
        Err(ClaimRefusal::PlanParentMismatch { .. })
    ));
}
```

Add small `fake_meta_with_rootfs(hex: String)` / `fake_meta_without_rootfs()` helpers in the test module that build a `CheckpointMeta` via its builder with (and without) a `ContentBlob { name: "rootfs.ext4".into(), sha256: hex }`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-runtime workload_runner::claim -- bind_`
Expected: FAIL — `bind_plan_to_parent` / `parent_rootfs_digest` not defined.

- [ ] **Step 3: Write minimal implementation**

```rust
use mvm_core::checkpoint::CheckpointMeta;

const ROOTFS_BLOB_NAME: &str = "rootfs.ext4";

pub fn parent_rootfs_digest(meta: &CheckpointMeta) -> Result<&str, ClaimRefusal> {
    meta.content
        .iter()
        .find(|b| b.name == ROOTFS_BLOB_NAME)
        .map(|b| b.sha256.as_str())
        .ok_or_else(|| ClaimRefusal::PlanParentMismatch {
            expected: String::new(),
            got: String::from("<parent carries no rootfs.ext4 blob>"),
        })
}

pub fn bind_plan_to_parent(plan_image_sha256: &str, meta: &CheckpointMeta) -> Result<(), ClaimRefusal> {
    let parent = parent_rootfs_digest(meta)?;
    if parent == plan_image_sha256 {
        Ok(())
    } else {
        Err(ClaimRefusal::PlanParentMismatch {
            expected: plan_image_sha256.to_string(),
            got: parent.to_string(),
        })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-runtime workload_runner::claim -- bind_ parent_without`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/workload_runner/claim.rs
git commit -m "feat(runtime): bind admitted plan image digest to the verified parent rootfs"
```

---

## Task 3: `ClaimGuards` — the runner-side shared host steps (endpoint + overlay gate)

REVISED SCOPE (a first attempt found the original scope invalid): the runner does
NOT host-apply admission, verity, or confinement — those live at their own layers
(the CLI mints/admits the plan and inherits verity; the supervisor re-verifies at
attach; guest init confines the forked child by construction — see the design
note "Where each guard runs"). The only genuinely runner-side, host-side steps a
warm claim shares with cold boot are the per-child substitution-endpoint spawn and
the overlay-contract admission gate. Factor exactly those two into a `ClaimGuards`
both cold boot and warm claim call. Do NOT invent a host-side confinement path.

**Files:**
- Modify: `crates/mvm-runtime/src/workload_runner/claim.rs` (define `ClaimGuards`)
- Modify: `crates/mvm-runtime/src/workload_runner/runner.rs` (route the cold-boot start path's endpoint spawn + overlay-contract gate through `ClaimGuards`)
- Test: unit test in `claim.rs`; the existing runner cold-boot tests must stay green.

**Interfaces:**
- Consumes: the runner's existing per-VM substitution-endpoint spawn (the implementer identified `EndpointSpawner::spawn`) and the overlay-contract gate (`admit_runtime_overlay_contract`), both already invoked on the cold-boot start path (`VmBackend::start` → `start_workload`). Read `runner.rs` for the exact call sites and signatures; move them, do not reimplement.
- Produces: `pub struct ClaimGuards<'a> { /* the endpoint spawner + overlay-contract inputs the runner threads */ }` with `pub fn admit_overlay_contract(&self, cfg: &VmStartConfig) -> anyhow::Result<()>` and `pub fn spawn_endpoint(&self, vm: &VmId, /* real params */) -> anyhow::Result<EndpointHandle>`. (Adapt exact names/params to `runner.rs`.)

- [ ] **Step 1: Write the failing test** — endpoint isolation + overlay-gate parity (no confinement).

```rust
#[test]
fn claim_guards_spawn_endpoint_is_private_to_the_given_vm() {
    // ClaimGuards::spawn_endpoint keys the substitution endpoint on the vm id it
    // is given (0700, private), never a shared/parent socket.
    let guards = ClaimGuards::for_test();
    let ep = guards.spawn_endpoint(&vm_id("child-a"), /* real params */).expect("spawn");
    assert!(endpoint_socket_is_private_to(&ep, &vm_id("child-a"))); // mode 0700, path keyed on child-a
}

#[test]
fn claim_guards_overlay_contract_matches_cold_boot() {
    // The overlay-contract gate accepts a valid overlay config and rejects an
    // invalid one — identical to what the cold-boot start path enforced.
    let guards = ClaimGuards::for_test();
    assert!(guards.admit_overlay_contract(&valid_overlay_cfg()).is_ok());
    assert!(guards.admit_overlay_contract(&invalid_overlay_cfg()).is_err());
}
```

(`for_test` builds a `ClaimGuards` over test doubles; the `*_overlay_cfg` helpers build a `VmStartConfig` the real gate accepts/rejects, mirroring the cold-boot gate's existing tests.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-runtime workload_runner::claim -- claim_guards`
Expected: FAIL — `ClaimGuards` not defined.

- [ ] **Step 3: Write minimal implementation**

Define `ClaimGuards` holding what the cold-boot start fn threads for these two steps (the endpoint spawner + the overlay-contract inputs). Move the cold-boot start fn's `EndpointSpawner::spawn` call and its `admit_runtime_overlay_contract` call into `ClaimGuards::spawn_endpoint` / `admit_overlay_contract`, and have the cold-boot start fn call them. Behavior-preserving — the cold path does exactly what it did, just through `ClaimGuards`. Do NOT add any confinement/admission/verity logic here.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-runtime workload_runner::claim -- claim_guards` then `cargo test -p mvm-runtime` (all cold-boot tests still pass).
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/workload_runner/claim.rs crates/mvm-runtime/src/workload_runner/runner.rs
git commit -m "refactor(runtime): factor runner-side endpoint spawn + overlay-contract gate into ClaimGuards"
```

---

## Task 4: `spawn_standby` on the `WorkloadRunner` (clean pre-workload parent)

**Files:**
- Modify: `crates/mvm-runtime/src/workload_runner/runner.rs` (impl `spawn_standby`)
- Modify: `crates/mvm-runtime/src/firecracker.rs` / `crates/mvm-runtime/src/driver/fc.rs` (driver-level clean-parent boot + capture)
- Test: unit tests in `runner.rs` with the mock backend.

**Interfaces:**
- Consumes: `StandbySpec` (`crates/mvm-protocol/src/protocol/vm_backend.rs`), `SupervisorStandbyPool::record` (`crates/mvm-runtime/src/standby_pool.rs`).
- Produces: `impl WorkloadRunner { fn spawn_standby(&self, spec: &StandbySpec) -> Result<StandbyHandle, StandbyError> }` overriding the fail-closed trait default; records an `Idle` parent carrying no workload plan and no substitution endpoint.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn spawn_standby_records_pre_workload_parent_with_no_secrets_endpoint() {
    let runner = WorkloadRunner::for_test(MockBackend::with_standby());
    let spec = standby_spec_for_test(); // no entrypoint, no secret bindings
    let handle = runner.spawn_standby(&spec).expect("spawn");
    let recorded = runner.pool().list().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(matches!(recorded[0].state, StandbyState::Idle));
    // A factory carries no workload authority and no secrets endpoint.
    assert!(recorded[0].plan_json.is_none());
    assert!(!substitution_endpoint_exists(&handle.vm_id()));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-runtime workload_runner -- spawn_standby_records`
Expected: FAIL — `spawn_standby` hits the `Unsupported` default.

- [ ] **Step 3: Write minimal implementation**

Implement `spawn_standby` on `WorkloadRunner`: validate the spec carries no workload plan / no secret bindings (a factory), delegate the VMM boot-to-ready + capture to the driver (FC boots a clean parent to the agent-up ready point and captures a checkpoint; it must not run any entrypoint), then `pool.record(...)` as `Idle`. Do not spawn a substitution endpoint.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-runtime workload_runner -- spawn_standby_records`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/workload_runner/runner.rs crates/mvm-runtime/src/firecracker.rs crates/mvm-runtime/src/driver/fc.rs
git commit -m "feat(runtime): spawn_standby boots a clean pre-workload parent through the runner"
```

---

## Task 5: `claim_standby` on the `WorkloadRunner` (guarded claim, positive path)

**Files:**
- Modify: `crates/mvm-runtime/src/workload_runner/runner.rs` (impl `claim_standby`)
- Test: unit tests in `runner.rs` with the mock backend.

**Interfaces:**
- Consumes: Task 1-3 (`ClaimRefusal`, `bind_plan_to_parent`, `ClaimGuards`); `SupervisorStandbyPool::{select_idle_compatible, mark_claimed}`; `acquire_registry_lock` (`crates/mvm-runtime/src/vm/name_registry.rs`); `mvm_runtime::warm_snapshot::materialize_child_from_parent`; `mvm_runtime::checkpoint::{verify_content, verify_lineage}`; `FcForkRestorer::restore_fork` (`crates/mvm-runtime/src/firecracker.rs:436`); `mvm_core::crypto::vmgenid::fresh_generation_token`. The `StandbyClaim` carries the already-admitted child plan (CLI-minted via `admit_plan_for_boot`) and a `VmStartConfig` whose verity fields the CLI already populated (`populate_fork_rootfs_verity`) — the runner consumes these, it does not mint the plan or derive verity.
- Produces: `impl WorkloadRunner { fn claim_standby(&self, handle: &StandbyHandle, claim: &StandbyClaim) -> Result<VmId, StandbyError> }` executing the design's 11-step guarded flow.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn claim_produces_fresh_identity_and_isolated_endpoint() {
    let env = ClaimTestEnv::with_audited_parent(); // records a clean parent + a matching signed child plan
    let child = env.runner.claim_standby(&env.handle, &env.claim).expect("claim");

    // fresh identity: differs from the parent on every identity axis
    assert_ne!(child, env.parent_vm_id);
    assert_ne!(env.child_nonce(), env.parent_nonce());
    assert_ne!(env.child_genid_token(), env.parent_genid_token());

    // surface 5: the child has its own 0700 endpoint; the parent still has none
    assert!(substitution_endpoint_is_private(&child)); // keyed on child VmId, mode 0700
    assert!(!substitution_endpoint_exists(&env.parent_vm_id));

    // the runner-side overlay-contract gate ran (host-side, same as cold boot)
    assert!(env.overlay_contract_admitted());

    // surface 3: the fresh VMGenID is delivered before any workload randomness consumer runs
    assert!(env.genid_delivered_before_workload());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-runtime workload_runner -- claim_produces_fresh_identity`
Expected: FAIL — `claim_standby` hits the `Unsupported` default.

- [ ] **Step 3: Write minimal implementation**

Implement `claim_standby` in the order from the design note "Where each guard runs" + "Claim data-flow" (read them). The runner owns only the runner-side, host-side steps; admission (claim 8) and verity (claim 3) are already done by the CLI caller and arrive in the claim, and confinement (claim 1) is guest-inherited via the forked rootfs.
(1) under `acquire_registry_lock`, `select_idle_compatible` + `mark_claimed` atomically; assert `Idle`/`Parked` else `ClaimRefusal::ParentNotClaimable`; `verify_content` + `verify_lineage` (map failures to `ParentTampered` / `ParentUnaudited`).
(2) parse the already-admitted child plan carried in `claim` (minted by the CLI via `admit_plan_for_boot`; re-verified by the supervisor at attach — the runner does NOT re-admit). If the plan is absent when claim 8 is required, refuse.
(3) `materialize_child_from_parent(...)` into the child dir.
(4) `bind_plan_to_parent(plan.image.sha256, &parent_meta)?` (→ `PlanParentMismatch`).
(5) the child `VmStartConfig` arrives with `verity_path`/`roothash` already populated by the CLI caller (`populate_fork_rootfs_verity`); the runner consumes them, it does not derive them.
(6) identity-scrub: fresh `VmId` (registry-unique), fresh `fresh_generation_token`, ensure delivery ordering precedes any workload randomness consumer.
(7) `FcForkRestorer::restore_fork(child_vm_name, child_dir)`.
(8) `ClaimGuards::spawn_endpoint` (child-keyed, 0700) + `ClaimGuards::admit_overlay_contract`.
(9) confinement is guest-init-inherited via the forked rootfs (parent snapshot is post-init) — nothing to apply host-side; do not add a host-side confinement path.
(10) emit `plan.launched` + the fork lineage event.
(11) `replenish_after_launch`.
Nothing in 3-11 runs until 1-2 and step 4 pass.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-runtime workload_runner -- claim_produces_fresh_identity`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/workload_runner/runner.rs
git commit -m "feat(runtime): claim_standby forks a clean parent into a fresh admitted child"
```

---

## Task 6: Fail-closed witnesses + never-promote guard (surfaces 1, 6, 7, 8)

**Files:**
- Modify: `crates/mvm-runtime/src/workload_runner/runner.rs` (never-promote guard on the workload `run` entry)
- Test: unit tests in `runner.rs`.

**Interfaces:**
- Consumes: Task 5's `claim_standby`; the runner's workload `run` entry.
- Produces: the `run` entry refuses a `VmId` registered as a standby parent (`ClaimRefusal::ParentPromotionRefused`).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn claim_refuses_plan_parent_image_mismatch() {
    let env = ClaimTestEnv::with_audited_parent().with_plan_image("cc".repeat(32));
    let dst_before = env.child_dir_exists();
    let err = env.runner.claim_standby(&env.handle, &env.claim).unwrap_err();
    assert!(err_is_refusal(&err, ClaimRefusal::PlanParentMismatch { .. }));
    assert!(!dst_before && !env.child_dir_exists()); // no side effect
}

#[test]
fn claim_refuses_unaudited_and_tampered_parent() {
    for env in [ClaimTestEnv::with_unaudited_parent(), ClaimTestEnv::with_tampered_parent()] {
        assert!(env.runner.claim_standby(&env.handle, &env.claim).is_err());
        assert!(!env.child_dir_exists());
        assert!(!substitution_endpoint_exists(&env.would_be_child_id()));
    }
}

#[test]
fn claim_refuses_expired_and_replayed_plan() {
    let expired = ClaimTestEnv::with_audited_parent().with_expired_plan();
    assert!(expired.runner.claim_standby(&expired.handle, &expired.claim).is_err());
    let env = ClaimTestEnv::with_audited_parent();
    env.runner.claim_standby(&env.handle, &env.claim).expect("first ok");
    // replay the same signed claim → nonce ledger refuses
    assert!(env.runner.claim_standby(&env.handle, &env.claim).is_err());
}

#[test]
fn concurrent_claims_do_not_double_claim_one_parent() {
    let env = ClaimTestEnv::with_audited_parent();
    let outcomes = env.race_two_claims_on_the_same_parent(); // spawns two threads
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
}

#[test]
fn running_a_workload_on_a_parent_is_refused() {
    let env = ClaimTestEnv::with_audited_parent();
    assert!(err_is_refusal(
        &env.runner.run_workload(&env.parent_vm_id, workload_for_test()).unwrap_err(),
        ClaimRefusal::ParentPromotionRefused
    ));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p mvm-runtime workload_runner -- claim_refuses concurrent_claims running_a_workload`
Expected: FAIL — never-promote guard absent; assert refusals not yet wired.

- [ ] **Step 3: Write minimal implementation**

Add the never-promote guard: the runner's workload `run` entry looks up the `VmId` in the pool; if it is a registered standby parent, refuse with `ClaimRefusal::ParentPromotionRefused` before doing anything. Confirm the fail-closed refusals from Task 5 leave no child dir / endpoint (they should already; add cleanup on the error path if a partial dir is created).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p mvm-runtime workload_runner -- claim_refuses concurrent_claims running_a_workload`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/workload_runner/runner.rs
git commit -m "feat(runtime): fail-closed claim witnesses + never-promote-a-parent guard"
```

---

## Task 7: Enable the `standby_pool` capability for Firecracker

**Files:**
- Modify: `crates/mvm-runtime/src/driver/fc.rs` (capabilities `standby_pool = true`)
- Modify: `crates/mvm-cli/src/exec.rs` / `crates/mvm-cli/src/commands/pool.rs` (let `try_warm_claim` route through the runner)
- Test: unit tests in `driver/fc.rs` + a `try_warm_claim` routing test.

**Interfaces:**
- Consumes: Task 4-6 (`spawn_standby`/`claim_standby`); `VmCapabilities`.
- Produces: FC driver `capabilities().standby_pool == true`; every other driver stays `false`; `try_warm_claim` reaches `claim_standby` on FC.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn only_fc_driver_advertises_standby_pool() {
    assert!(fc_driver_capabilities().standby_pool);
    assert!(!libkrun_driver_capabilities().standby_pool);
    assert!(!hvf_driver_capabilities().standby_pool);
    assert!(!qemu_backend_capabilities().standby_pool);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-runtime -- only_fc_driver_advertises_standby_pool`
Expected: FAIL — FC driver reports `standby_pool = false` today.

- [ ] **Step 3: Write minimal implementation**

In the FC driver's `capabilities()`, set `standby_pool = true` (leave `snapshot_capability` as Plan 265's concern). In `try_warm_claim`, allow the FC path now that the capability is advertised (the existing eligibility checks stay). Do not touch the libkrun/hvf/qemu drivers.

- [ ] **Step 4: Run test to verify it passes + full suite**

Run: `cargo test -p mvm-runtime -- only_fc_driver_advertises_standby_pool` then `cargo nextest run --workspace`
Expected: PASS; the existing `default_warm_start_fails_closed`-style tests for the other backends still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/driver/fc.rs crates/mvm-cli/src/exec.rs crates/mvm-cli/src/commands/pool.rs
git commit -m "feat(runtime): advertise standby_pool for Firecracker and route warm claims through the runner"
```

---

## Task 8: Hermetic BDD witness — warm claim fresh identity + replay refused

**Files:**
- Create: `features/suites/s6_admission_audit/warm_claim_fresh_identity.feature`
- Create: `crates/mvm-conformance/tests/steps/warm_claim.rs`
- Modify: `crates/mvm-conformance/tests/steps/mod.rs` (`mod warm_claim;`), `crates/mvm-conformance/tests/world.rs` (fields as needed)
- Test: `just bdd`.

**Interfaces:**
- Consumes: the runner `claim_standby` seam + the mock backend (no live VM).

- [ ] **Step 1: Write the failing scenario**

```gherkin
Feature: Warm-claim admission
  A warm claim forks a clean parent into a fresh, admitted child and refuses a replay.

  Scenario: a warm claim admits a fresh identity and refuses a replayed claim
    Given a clean warm parent recorded in the pool
    When the parent is claimed with a fresh signed plan
    Then the claim emits a launched audit entry with a fresh nonce
    And re-submitting the identical claim is refused
```

- [ ] **Step 2: Run to verify it fails**

Run: `just bdd`
Expected: FAIL — steps for the `warm_claim` scenario are undefined.

- [ ] **Step 3: Implement the step module**

In `steps/warm_claim.rs`, drive the runner `claim_standby` seam with the mock backend: the `Given` records a clean parent; the `When` claims with a fresh signed plan; the `Then`s assert a `plan.launched` entry with a fresh nonce and that a second identical claim is refused. Add `mod warm_claim;` to `steps/mod.rs`; add any `CliWorld` fields (`Option`, `None`-default). No `@live` tag.

- [ ] **Step 4: Run to verify it passes**

Run: `just bdd`
Expected: PASS (the new scenario + the whole suite).

- [ ] **Step 5: Commit**

```bash
git add features/suites/s6_admission_audit/warm_claim_fresh_identity.feature crates/mvm-conformance/tests/steps/warm_claim.rs crates/mvm-conformance/tests/steps/mod.rs crates/mvm-conformance/tests/world.rs
git commit -m "test(conformance): hermetic warm-claim fresh-identity + replay-refused witness"
```

---

## Task 9: Tick the plan checkboxes + design-note cross-reference

**Files:**
- Modify: `specs/plans/255-vsock-first-snapshot-egress-adoption.md` (tick the Phase 2 items this slice satisfies; leave slice-two items unticked)
- Modify: `specs/SPRINT.md` (note Phase 2 slice one landed)

- [ ] **Step 1:** Tick the Plan 255 Phase 2 checkboxes covered by this slice: paused-parent pool keyed by template (via the standby pool + FC spawn), `fork_from_parent` (via `claim_standby`), the fresh-signed-`ExecutionPlan`-per-fork item (claim 8), the verity-inherit item (claim 3), and the hard-guard item. Leave post-resume-hygiene refinement and the sub-second-launch acceptance (Plan 265) unticked with a one-line note.
- [ ] **Step 2:** Update `specs/SPRINT.md` under the warm-start bullets.
- [ ] **Step 3: Commit**

```bash
git add specs/plans/255-vsock-first-snapshot-egress-adoption.md specs/SPRINT.md
git commit -m "docs(plan-255): tick Phase 2 slice-one checkboxes (warm-pool claim substrate)"
```

---

## Self-review (author checklist — completed)

- **Spec coverage:** each of the design's 8 security surfaces maps to a task/witness — surface 1 → Task 2/6, surface 2 → Task 4, surface 3 → Task 5, surface 4 → Task 3/5, surface 5 → Task 4/5, surface 6 → Task 5/6, surface 7 → Task 6, surface 8 → Task 6. `spawn_standby`/`claim_standby`/capability → Tasks 4/5/7; never-promote → Task 6; BDD → Task 8; checkbox hygiene → Task 9.
- **Type consistency:** `ClaimRefusal`, `ClaimOutcome`, `bind_plan_to_parent`, `parent_rootfs_digest`, `ClaimGuards` are defined in Task 1-3 and reused by name in Task 5-6.
- **Adaptation note for implementers:** signatures marked "adapt" are contracts derived from the current interfaces; read the named file and match the real names — the reviewer gates on the test passing and the reuse being correct, not on verbatim signatures.

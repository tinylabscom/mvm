# Design — Plan 255 Phase 2 substrate: admission-safe warm-pool claim (Firecracker-first)

**Status:** Design (approved for planning)
**Date:** 2026-07-27
**Owner:** mvm
**Scope:** Plan 255 Phase 2 substrate, first slice = the claim/fork path only.

## Goal

Turn the dormant warm-pool scaffolding into a working, admission-safe warm
claim on the selectable runner path, Firecracker first. A claim forks a paused
clean parent into a fresh, signed, admitted child that is gated identically to a
cold boot. This is the substrate Plan 265 depends on for its per-backend fast
restore; it does not do the fast-restore engineering itself.

## Relationship to existing work

- **Plan 255 Phase 2** owns this: the paused-parent warm pool and fork identity
  hygiene (backend-agnostic authority + guard machinery).
- **Plan 265** (fast-start SLO / sequencing) owns per-backend fast+safe restore:
  the vsock-safe restore re-enable, no-NIC-on-restore invariant, page-cache
  priming, density/same-page-merge, SLO gates, and the restore security
  witnesses. Its foundation is in flight on branch `feat/plan255-fast-start`
  (draft PR). This design deliberately does not overlap those files or witnesses.
- **Phase 1 (merged)** supplies the content-addressed, lineage-anchored clone
  primitive (`mvm_runtime::warm_snapshot::materialize_child_from_parent`,
  `mvm_fs::snapshot_store`), which the claim path uses as its CoW substrate.

The interface between the two: this substrate defines the guarded claim path and
a backend claim seam; Plan 265 makes the seam's restore live-memory and fast.

## Invariants (inherited, non-negotiable)

1. Vsock is the sole guest↔host and egress boundary.
2. One guest = one workload; a warm parent is a factory, never a workload.
3. The guest never sees secrets; substitution stays host-side.
4. Fork/restore never bypasses admission: a claimed child re-admits a bound,
   validity-windowed signed `ExecutionPlan` (claim 8) and keeps its dm-verity
   roothash binding on block+ext4 (claim 3). Reusing a parent's authority fails
   closed.
5. A warm claim is gated at least as strictly as a cold boot — never less.

## Why the pool is fenced off today (the problem)

The `WorkloadRunner` forces `standby_pool = false` / `snapshot_capability =
Unsupported` for every selectable backend because the raw `spawn_standby` /
`claim_standby` implementations (present on the low-level libkrun backend) do not
route through the runner's admission and endpoint guards. The substrate's job is
to implement those two operations on the `WorkloadRunner` so they run the
identical guarded sequence a cold boot runs, then enable the capability for
Firecracker.

## Architecture

Three layers, each with one responsibility:

- **`WorkloadRunner`** — authority and guards. Owns `spawn_standby` /
  `claim_standby` (new), the shared cold-boot guard sequence, and the
  never-promote-a-parent rule. Knows nothing VMM-specific.
- **Driver / backend (FC first)** — VMM spawn and fork. Boots a clean parent to
  ready and forks a parent into a child directory. Knows nothing about admission.
- **`SupervisorStandbyPool`** (exists) — bookkeeping: record / select-idle /
  mark-claimed / reap-stale.

The `standby_pool` capability flips true only for the FC driver in this slice;
every other backend keeps the fail-closed default.

### Tier-agnostic parent seam

The claim path is agnostic to whether a warm parent is a resident paused VM or a
pre-captured checkpoint — that is a driver detail behind the standby handle. This
slice backs the FC parent with the existing checkpoint fork (disk restore via
`FcForkRestorer` + the Phase-1 clone). Plan 265 upgrades the same seam to
live-memory restore; the resident-paused density model arrives with it, not here.

## Claim data-flow (guarded, fail-closed)

`claim_standby(handle, claim)` runs this order; nothing clones or boots until
every gate passes:

1. **Parent state + lineage gate.** Parent must be `Idle`/`Parked` (not already
   claimed); its checkpoint must pass `verify_content` + `verify_lineage`
   (un-audited or tampered parent refuses). Runs before any clone.
2. **Re-admit the child plan (claim 8).** The child's signed `ExecutionPlan`
   (minted fresh at the CLI with a fresh nonce and the child's own `vm_name`) is
   re-verified at attach through the existing `prelaunch` path: `verify_plan` →
   `verify_plan_id` → `check_window` (G4) → nonce-ledger `check_and_insert`
   (replay). This is the shared cold-boot admission, not a parallel copy.
3. **Materialize child rootfs.** `materialize_child_from_parent` — self-binding,
   lineage-anchored CoW clone from the verified parent's own content.
4. **Verity inherit (claim 3).** Resolve `verity_path`/`roothash` from the cloned
   rootfs sidecars into the child `VmStartConfig`; the sidecars ride the clone.
5. **Identity-scrub.** Fresh registry-unique `VmId`, the plan's fresh nonce, a
   fresh VMGenID token delivered on resume (forces guest CSPRNG reseed + session
   drop), and the child's own substitution-endpoint socket. CID stays 3 — the
   child is its own FC VMM (one guest per VMM), so no per-instance CID is needed.
6. **Driver fork.** `FcForkRestorer` boots a fresh FC VMM from the parent into
   the child dir. Plan 265 replaces this with fast live-memory restore behind the
   same seam.
7. **Endpoint + gateway.** Spawn the per-VM host-side substitution endpoint +
   gateway; secrets stay host-side.
8. **Re-apply confinement.** Seccomp + jailer + per-service uid, from the same
   helper cold boot uses.
9. **Audit + bookkeeping.** Emit `plan.launched` on the child's chain;
   `mark_claimed`; `replenish_after_launch` refills a fresh parent.

If any gate in 1-2 (and the clone in 3) fails, the claim refuses before any boot,
endpoint, or child directory side effect — mirroring the Phase-1 clone discipline
and the cold-boot admission order.

## Never-promote-a-parent guard

Made unrepresentable, not merely checked:

- A standby parent carries no admitted workload plan by construction.
- The standby handle exposes only `claim` (which yields a fresh child `VmId`),
  never a workload `run`.
- The runner's workload entry refuses a `VmId` that is registered as a standby
  parent.

Steps 2 and 8 execute the exact guard code a cold boot uses, via a single shared
`ClaimGuards` builder, so a warm claim can never diverge to a weaker posture.

## Best-practice shape

- A `ClaimGuards` builder carrying the shared admission + verity + endpoint +
  confinement steps, called by both cold boot and warm claim — divergence is
  unrepresentable.
- `StandbyState` (exists) drives the state machine; a `ClaimOutcome` enum for
  results; typed fail-closed error enums (thiserror in mvm-core, anyhow in
  mvm-runtime, per crate convention).
- Many small single-purpose functions, each unit-testable with fakes; exhaustive
  matches on `StandbyState` and backend; no `#[allow(clippy::...)]`; no spec/PR
  references in code comments.

## Reuse map (build on, do not reinvent)

- `WorkloadRunner` (`crates/mvm-runtime/src/workload_runner/runner.rs`) — add
  `spawn_standby` / `claim_standby`; reuse its substitution-endpoint spawn and
  confinement helpers (factor the cold-boot sequence into `ClaimGuards`).
- Standby types + pool: `StandbySpec` / `StandbyClaim` / `StandbyHandle` /
  `StandbyState` (`crates/mvm-protocol/src/protocol/vm_backend.rs`),
  `SupervisorStandbyPool` (`crates/mvm-runtime/src/standby_pool.rs`),
  `try_warm_claim` / `replenish_after_launch` (`crates/mvm-cli/src/commands/pool.rs`,
  wired in `crates/mvm-cli/src/exec.rs`).
- Admission: `admit_plan_for_boot` (CLI mint), the `prelaunch` attach re-verify,
  `NonceStore` / `check_window` (`crates/mvm-core/src/plan/validity.rs`).
- Clone: `materialize_child_from_parent` (`crates/mvm-runtime/src/warm_snapshot.rs`).
- Verity inherit: `populate_fork_rootfs_verity` /
  `probe_verity_sidecar`; the guest sidecar propagation on clone.
- Fork VMM op: `FcForkRestorer` (`crates/mvm-runtime/src/firecracker.rs`).
- Identity: `fresh_generation_token` (`crates/mvm-core/src/crypto/vmgenid.rs`),
  the name registry.

## Testing

Unit (mock backend + fakes, no live VM):

- Fresh identity: child nonce + VMGenID token + `VmId` all differ from the
  parent; a replayed child plan is refused by the nonce ledger.
- Fail-closed matrix: un-audited parent, drift-tampered parent, expired child
  plan, replayed nonce — each asserts no child directory, no boot, no endpoint.
- Never-promote guard: running a workload directly on a parent handle is refused.
- Confinement parity: a claimed child carries the same seccomp profile + uid as a
  cold boot (assert against the shared `ClaimGuards` output).
- Capability: `standby_pool` is true only for the FC driver; other drivers keep
  the fail-closed default.

BDD (hermetic): one `s6_admission_audit` scenario — a warm claim emits
`plan.admitted` / `plan.launched` with a fresh nonce and refuses a replayed
claim, driven through the runner seam with the mock backend. The real FC fork is
a `@live` add-on.

Coordination: this substrate lands only the runner-seam units + that one
admission-audit scenario. It does not add or modify any `.feature` file the
fast-start branch is introducing (restore / no-NIC / SLO / attach-reverify
witnesses belong to Plan 265). `check-claim-catalog` stays green with no catalog
edits — this reinforces claims 8 and 3 on the warm path; Plan 265 registers the
new witnesses.

## Verification gates

- `cargo fmt --all -- --check` (nightly rustfmt, per CI Lint)
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo nextest run --workspace` + `cargo test --workspace --doc`
- touched cucumber scenarios green via `just bdd`
- `cargo run -p xtask -- check-claim-catalog` green (no claim regressed)
- `cargo run -p xtask -- check-cli-runtime-surface` green (CLI stays behind `mvm-client`)
- `cargo run -p xtask -- check-core-runtime-free` green
- Linux target cross-check (`just check-linux`) clean under `-D warnings`

## Scope boundaries

In this slice:

- `spawn_standby` / `claim_standby` on the `WorkloadRunner`, FC-only capability
  flip, the shared `ClaimGuards`, identity-scrub, the never-promote guard, and
  the Phase-1 clone beneath, with the unit + one hermetic BDD witness.

Deferred to Plan 255 Phase 2 slice two:

- Pool lifecycle polish beyond what exists: spawn/maintain/evict tuning by TTL /
  memory budget, `mvmctl pool` UX, replenish policy refinement.

Owned by Plan 265 (not here):

- Live-memory fast restore, no-NIC-on-restore invariant, page-cache priming,
  same-page-merge confinement, density, SLO gates, and the restore security
  witnesses.

Out of scope entirely:

- HVF and libkrun claim paths (later backends behind the same seam); fleet-level
  pool sizing (mvmd); any NIC/host-socket data plane.

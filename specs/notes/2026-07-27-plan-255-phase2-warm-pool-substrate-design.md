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

## Parent cleanliness contract

The pool's safety rests on the parent being a factory captured strictly before
any workload runs. A warm parent snapshot must be taken:

- before the entrypoint or any workload code executes;
- before any secret material exists in the guest — secrets are host-side
  substitution only, so the guest never holds them, and the parent must have made
  no substitution call;
- before any tenant- or instance-specific state is written.

A parent is one image's clean ready point (agent up, read-only rootfs primed) and
nothing more. If "ready" ever advances past this line, every child inherits the
residue — memory, filesystem, and open state. This precondition is what the
cross-fork-residue and shared-entropy mitigations below rely on.

## Where each guard runs (layering)

The guards are not all at the runner — they are enforced at their existing
layers, and the warm claim reuses each in place (the same shape the FC
checkpoint-fork already uses):

- **Admission (claim 8)** — the CLI caller (`try_warm_claim`) mints the child's
  fresh signed `ExecutionPlan` via `admit_plan_for_boot`; the supervisor
  (`mvm-hostd`) re-verifies it at attach. The runner receives an already-admitted
  plan. (The runner cannot re-verify itself: the re-verify code lives in
  `mvm-hostd`, which depends on `mvm-runtime`.)
- **Verity inherit (claim 3)** — CLI-side, via `populate_fork_rootfs_verity` on
  the cloned child rootfs; the runner only consumes the resulting
  `VmStartConfig.verity_path`/`roothash`.
- **Confinement (claim 1)** — applied by guest init (setpriv uid 901 + seccomp
  `standard`) and inherited into the forked child by construction: the parent
  snapshot is taken at the post-init ready point (parent-cleanliness contract),
  so the child carries the same confinement a cold boot's init applies. There is
  no host-side confinement to re-derive on the runner.
- **Runner (`claim_standby`, taking a `ClaimContext`)** — owns only the genuinely
  runner-side, host-side steps: the atomic parent select + lineage gate, the CoW
  materialize, the plan↔parent bind, identity-scrub, the VMM fork, the per-child
  substitution endpoint, and the overlay-contract gate. The pool, checkpoint/
  snapshot stores, and audit anchor are injected via `ClaimContext` (they are not
  reachable from the runner's cold-boot fields; the signed anchor loads the host
  key, which lives above `mvm-runtime`).
- **CLI caller** — after `claim_standby` returns, emits the signed audit
  (`plan.launched` + the fork lineage event) via the `AuditEmitter` and replenishes
  the pool. The `AuditEmitter` lives above `mvm-runtime`, so the runner cannot emit
  it; this is the same layer the existing checkpoint-fork path emits from.

## Claim data-flow (guarded, fail-closed)

`claim_standby(handle, claim)` runs this order; nothing clones or boots until
every gate passes. Steps are annotated with the layer that owns them:

1. **Parent state + lineage gate.** Parent must be `Idle`/`Parked`, selected and
   marked claimed atomically under the name-registry lock (no double-claim); its
   checkpoint must pass `verify_content` + `verify_lineage` (un-audited or
   tampered parent refuses). Runs before any clone.
2. **Admit the child plan (claim 8) [CLI + supervisor].** The CLI caller mints
   the child's fresh signed `ExecutionPlan` (fresh nonce, child `vm_name`) via
   `admit_plan_for_boot`; the supervisor re-verifies it at attach (`verify_plan` →
   `check_window` (G4) → nonce `check_and_insert`). This reuses the exact cold-boot
   admission at its real layer; the runner receives the admitted plan in the claim.
3. **Materialize child rootfs.** `materialize_child_from_parent` — self-binding,
   lineage-anchored CoW clone from the verified parent's own content.
4. **Bind the plan to the parent (claim 8 integrity).** Verify the admitted
   plan's bound image digest equals the materialized parent rootfs
   content-address. A mismatch refuses — the audit-recorded plan must describe
   exactly what boots, so a claim can never pair a plan with a different parent's
   rootfs. This is the warm-pool analog of the Phase-1 self-binding clone, applied
   to authority.
5. **Verity inherit (claim 3) [CLI].** The CLI caller resolves
   `verity_path`/`roothash` from the cloned rootfs sidecars into the child
   `VmStartConfig` via `populate_fork_rootfs_verity`; the sidecars ride the clone.
   The runner consumes these fields; it does not derive them.
6. **Identity-scrub.** Fresh registry-unique `VmId`, the plan's fresh nonce, and a
   fresh VMGenID token. The token must be delivered and acted on (guest CSPRNG
   reseed + session drop) before any guest randomness consumer runs — otherwise
   forks share the parent's RNG state. The clean-parent contract bounds the
   consumers to init + the agent; Plan 265 owns the reseed mechanics, this
   substrate owns the trigger and the ordering. CID stays 3 — the child is its own
   FC VMM (one guest per VMM), so no per-instance CID is needed.
7. **Driver fork.** `FcForkRestorer` boots a fresh FC VMM from the parent into the
   child dir. Plan 265 replaces this with fast live-memory restore behind the same
   seam.
8. **Per-child endpoint + gateway.** Spawn the child's own substitution endpoint,
   keyed on the fresh `VmId`, socket mode 0700, never reusing a sibling's; the
   factory parent has no substitution endpoint at all. Secrets stay host-side.
9. **Confinement inherited (claim 1) [guest init].** Confinement is applied by
   guest init (setpriv uid 901 + seccomp `standard`) and inherited into the child
   by construction — the parent snapshot is post-init (parent-cleanliness
   contract), so the child carries the same confinement a cold boot's init
   applies. There is no host-side re-derivation on the runner. The runner only
   enforces the overlay-contract gate host-side, identical to cold boot.
10. **Audit + provenance [CLI caller].** After `claim_standby` returns, the CLI
    caller emits `plan.launched` on the child's chain and the fork lineage event
    recording the parent (via the `AuditEmitter`, which lives above `mvm-runtime`),
    so a claimed child's provenance (which parent + fresh plan) is verifiable — no
    less auditable than a cold boot, and the same layer the checkpoint-fork path
    emits from.
11. **Bookkeeping [CLI caller].** The caller replenishes a fresh parent
    (`replenish_after_launch` / `WarmLease::release`); the parent was marked
    claimed atomically in step 1.

If any gate in steps 1-4 fails, the claim refuses before any boot, endpoint, or
persisted child side effect — mirroring the Phase-1 clone discipline and the
cold-boot admission order.

## Never-promote-a-parent guard

Made unrepresentable, not merely checked:

- A standby parent carries no admitted workload plan by construction
  (`StandbySpec`/`StandbyHandle` have no plan/secret field).
- The standby handle exposes only `claim` (which yields a fresh child `VmId`),
  never a workload `run`.
- The runner's workload `start` path never consults the standby pool, and
  parents (`~/.mvm/pool/`) and workloads (`~/.mvm/vms/`) live in disjoint
  namespaces — so there is no code path that runs an existing parent's `VmId` as
  a workload. The guarantee is therefore structural (verified, no runtime guard
  needed) and is scoped to *this* fork substrate; the older single-use
  `LibkrunBackend::claim_standby` (which reuses a standby's own id and removes it
  from the pool on claim) is a separate predecessor model, not covered here.

A warm claim can never diverge to a weaker posture because each guard reuses the
cold-boot mechanism at its own layer: the same `admit_plan_for_boot` admission
(CLI), the same `populate_fork_rootfs_verity` (CLI), the same guest-init
confinement (inherited via the post-init parent snapshot), and — for the
genuinely runner-side host steps — a single shared `ClaimGuards` covering the
per-child substitution endpoint and the overlay-contract gate.

## Security surfaces → mitigation → witness

Each surface this claim path opens or widens, with the witness that covers it.

| # | Surface | Mitigation | Witness (unit unless noted) |
|---|---------|-----------|------------------------------|
| 1 | Plan/parent confusion — audit records image X, guest boots parent image Y | Fail-closed bind: admitted plan image digest == materialized parent rootfs content-address (claim-flow step 4) | `claim_refuses_plan_parent_image_mismatch` |
| 2 | Cross-fork residue from a dirty parent | Parent cleanliness contract: snapshot strictly pre-workload / pre-secret / pre-tenant | `parent_snapshot_is_pre_workload`; satisfies Plan 265 fork-no-residue |
| 3 | Shared CSPRNG state across forks | Fresh VMGenID delivered + acted on before any randomness consumer; clean parent bounds consumers to init+agent | `fork_delivers_fresh_genid_before_workload` (trigger + ordering); Plan 265 owns reseed |
| 4 | Weaker confinement on a forked child | Confinement is guest-init-applied and inherited via the post-init parent snapshot; the parent-cleanliness contract guarantees the snapshot is post-confinement, so the child carries the same uid 901 + seccomp `standard` as a cold boot | folds into surface 2 (`parent_snapshot_is_pre_workload` — i.e. post-init ready point) + the existing claim-1 guest witnesses |
| 5 | Cross-workload secrets endpoint access | Per-child endpoint keyed on fresh `VmId`, 0700, no reuse; factory parent has none | `child_endpoint_isolated_parent_has_none` |
| 6 | Un-audited / tampered parent forked | Phase-1 `verify_content` + `verify_lineage` gate before clone | `claim_refuses_unaudited_and_tampered_parent` |
| 7 | Replayed claim / stale plan | prelaunch re-verify: `check_window` + nonce ledger | `claim_refuses_expired_and_replayed_plan` |
| 8 | Double-claim race on one parent | Atomic select + mark-claimed under the registry lock | `concurrent_claims_do_not_double_claim` |

## Best-practice shape

- A `ClaimGuards` builder carrying the genuinely runner-side, host-side shared
  steps — the per-child substitution-endpoint spawn and the overlay-contract gate
  — called by both cold boot and warm claim. Admission (CLI/supervisor), verity
  (CLI), and confinement (guest init) are reused at their own layers, not
  re-implemented in the runner.
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
- Verity inherit: `populate_fork_rootfs_verity` / `probe_verity_sidecar`; the
  guest sidecar propagation on clone.
- Fork VMM op: `FcForkRestorer` (`crates/mvm-runtime/src/firecracker.rs`).
- Identity: `fresh_generation_token` (`crates/mvm-core/src/crypto/vmgenid.rs`),
  the name registry.
- Concurrency: `acquire_registry_lock` (`crates/mvm-runtime/src/vm/name_registry.rs`).

## Testing

Unit (mock backend + fakes, no live VM) — one focused test per security surface
plus the identity and capability paths:

- Fresh identity: child nonce + VMGenID token + `VmId` all differ from the parent.
- Surface 1: a claim whose plan image digest differs from the parent rootfs
  content-address refuses (`claim_refuses_plan_parent_image_mismatch`).
- Surface 2: the parent snapshot is taken at the pre-workload ready point
  (`parent_snapshot_is_pre_workload`).
- Surface 3: the fork delivers a fresh VMGenID before any workload randomness
  consumer runs (`fork_delivers_fresh_genid_before_workload`).
- Surface 4: confinement is guest-init-inherited, not host-re-derived — covered by
  surface 2 (the parent snapshot is post-init) plus the existing claim-1 guest
  witnesses; no host-side confinement-parity test is written (there is no host-side
  cold-boot confinement to match). The runner's host-side shared leaf is instead
  the overlay-contract gate, asserted alongside the endpoint isolation.
- Surface 5: the child endpoint is keyed on its fresh `VmId`, 0700, and the parent
  has none (`child_endpoint_isolated_parent_has_none`).
- Surface 6: un-audited and drift-tampered parents refuse, with no child dir/boot
  (`claim_refuses_unaudited_and_tampered_parent`).
- Surface 7: expired plan and replayed nonce refuse
  (`claim_refuses_expired_and_replayed_plan`).
- Surface 8: two concurrent claims never double-claim one parent
  (`concurrent_claims_do_not_double_claim`).
- Never-promote guard: running a workload directly on a parent handle refuses.
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
edits — this reinforces claims 8, 3, and 1 on the warm path; Plan 265 registers
the new numbered witnesses.

## Tracked risks (beyond the witnessed surfaces)

- **Nonce-ledger persistence.** The replay ledger is in-memory and resets on
  restart — a pre-existing property shared with cold boot, not worsened here, but
  noted because a pool spans many claims over a long-lived process. A persistent
  replay store is broader hardening, out of scope for this slice.
- **Parent freshness / revocation.** A warm parent can be staler than a fresh cold
  boot: an image revoked (e.g., a CVE found) after the parent was spawned is still
  served until its pool TTL. The lineage gate catches on-disk tampering but not
  policy revocation. TTL-bounded; tighter re-check-at-claim is a policy concern
  shared with Plan 265, not this slice.

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
  flip, the shared `ClaimGuards`, the plan/parent bind, identity-scrub, the
  never-promote guard, and the Phase-1 clone beneath, with the unit witnesses
  above and one hermetic BDD scenario.

Deferred to Plan 255 Phase 2 slice two:

- Pool lifecycle polish beyond what exists: spawn/maintain/evict tuning by TTL /
  memory budget, `mvmctl pool` UX, replenish policy refinement, a persistent
  replay store.

Owned by Plan 265 (not here):

- Live-memory fast restore, no-NIC-on-restore invariant, page-cache priming, the
  reseed mechanics, same-page-merge confinement, density, SLO gates, and the
  restore security witnesses.

Out of scope entirely:

- HVF and libkrun claim paths (later backends behind the same seam); fleet-level
  pool sizing (mvmd); any NIC/host-socket data plane.

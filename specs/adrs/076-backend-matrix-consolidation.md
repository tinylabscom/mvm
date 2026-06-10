# ADR-076 — Backend matrix consolidation (8 → 4) and AVF convergence

**Status:** accepted 2026-06-10. Implemented by
`specs/plans/177-backend-consolidation.md`. **Amends ADR-056** (Vz is no
longer opt-in — it becomes the macOS-26 default and absorbs
`AppleContainerBackend`) and **ADR-002** (the per-backend tier matrix loses
four rows — the matrix edit lands with Plan 177). Cross-refs: ADR-001
(multi-backend execution), ADR-013 (libkrun pivot), ADR-014 (single
`VmBackend` trait), ADR-066 (target architecture), ADR-073 (warm-snapshot
prior-art boundary).

## Context

`AnyBackend` (`crates/mvm-backend/src/backend.rs`) dispatches **eight**
`VmBackend` impls plus a mock: libkrun, firecracker, vz, apple_container,
docker, cloud_hypervisor, qemu, microvm_nix. Each is a module + trait impl
+ `from_hypervisor`/`auto_select`/`from_pid_files`/`tier`/`all()` wiring + a
`doctor` row + CI lanes. The matrix grew opportunistically; coupling and use
do not justify its width:

- `docker` (~450 LOC, Tier-3 "fallback") contradicts the project invariant
  "no Docker on the runtime path" (ADR-001). It is reachable only as an
  auto-select fallback and `doctor`/`ps` rows.
- `cloud_hypervisor` (~484 LOC, ~13 refs) is a second Tier-1-hardened
  Linux-KVM backend beside Firecracker with no auto-select path. Firecracker
  is the canonical Linux workload VMM (ADR-001); CH doubles hardened-tier
  maintenance for ~zero current use.
- `qemu` (~1,011 LOC) and `microvm_nix` (~299 LOC) are *both* Tier-2,
  dev/test-only, never auto-selected — two backends for "run locally without
  KVM."
- `vz` and `apple_container` are **both** Apple Virtualization.framework via
  `objc2` — neither uses Apple's Containerization framework (the
  `apple_container` name is a misnomer; the provider header reads "macOS
  Virtualization.framework VM lifecycle using objc2-virtualization", and its
  "Containerization / Swift-FFI / stub" doc header describes a design never
  built). They differ only in **process model**: `VzBackend` runs a per-VM
  supervisor (`mvm-vz-supervisor`, Rust objc2 since ADR-056's 2026-06-08
  addendum), `AppleContainerBackend` runs `VZVirtualMachine` **in-process**
  (raw `!Send` pointers). The in-process path reports `snapshots: false` and
  stubs pause/resume; the supervisor path implements real snapshot/restore
  (`saveMachineStateTo`/`restoreMachineStateFrom`) and pause/resume.

The cost is paid in the two pains driving the wider feature-reduction
effort: **cognitive load** (a change touches eight dispatch surfaces) and
**maintenance** (every backend is a CI lane and a refactor tax).

## Decision

Reduce the matrix to **four** backends (+mock): **libkrun, firecracker, vz,
qemu**.

1. **Delete `docker`.** Removes a runtime-path Docker affordance that should
   not exist, and a dead Tier-3 fallback.
2. **Delete `cloud_hypervisor`.** Firecracker is the sole Tier-1 Linux VMM.
3. **Fold `microvm_nix` into `qemu`.** Keep `QemuBackend` (the real TCG
   dev/test impl); delete `MicrovmNixBackend`; migrate `from_build_output`
   onto `QemuBackend`, porting any microvm.nix-specific config field.
4. **Converge AVF on the supervisor model.** Keep `VzBackend` (per-VM Rust
   objc2 supervisor, snapshot/restore, pause/resume); delete the in-process
   `providers/apple_container` path and `AppleContainerBackend`; expose one
   honestly-named `vz` AVF backend and make it the **macOS-26 auto-default**
   (reversing ADR-056's "opt-in only / libkrun stays the macOS default" for
   the macOS-26 tier). Port the in-process path's unique behaviors
   (admission-gate ordering, CoW per-instance rootfs clone, `runtime_meta`
   recording) onto `VzBackend`. Reattach the macOS-26 dev console over the
   supervisor's vsock via a **shared libkrun+vz console transport** (the
   pattern libkrun already uses) — a dedup, not a new mechanism. Drop the
   `apple-container` CLI input (no backcompat).

### Why the supervisor model wins the AVF convergence

- **Capability.** The supervisor path owns snapshot/restore — the
  warm-start / checkpoint / fork foundation (ADR-073, Plan 153). Keeping the
  in-process path as the survivor would amputate it.
- **Isolation.** One process per VM matches `LibkrunBackend`'s contract
  (uniform host architecture = less cognitive load), contains crashes,
  isolates the `!Send` `VZVirtualMachine` hazard, and gives each VM a
  sandboxable process boundary — load-bearing for the untrusted-workload
  posture (ADR-002, ADR-066 §"process isolation ≠ crate count").
- **Prior art.** The best-regarded external Rust AVF driver tools are
  themselves daemon-mediated (CLI → runtime daemon over UDS → AVF). The
  supervisor model *is* that architecture; mvm runs one supervisor per VM
  rather than one daemon for all, a deliberate isolation choice for the
  threat model.

The one real cost is the console reattach, which doubles as a libkrun+vz
console dedup. No capability is sacrificed.

## Sequencing

The AVF convergence is **gated** on the in-flight Plan 152 VZ-supervisor
work (`feat/plan-152-wsb-rust-vz-supervisor`,
`feat/plan-152-fix-vz-save-pause`) merging to `main` — it rewrites the
surface this decision edits. The three non-AVF cuts (docker,
cloud_hypervisor, microvm_nix→qemu) carry no VZ dependency and land first.
Plan 177 encodes this as Phase 1 (cuts) → Phase 2 (gated AVF).

## Security posture

No claim regresses. The deleted backends carried no unique claim coverage
(`docker` is Tier-3 and never workload-bearing; `cloud_hypervisor`'s Tier-1
claim-3 path was "in flight", unshipped; `microvm_nix` folds into `qemu`,
unchanged Tier-2 dev/test). The surviving `vz` keeps ADR-056's per-claim
table and the claim-15 capture-only / sealed-console invariants
(`prod_console_attachment_has_no_input`, `console_refused_on_sealed_image`)
through the shared console transport.

## Alternatives considered

- **Keep all eight, document better.** Rejected — documentation does not pay
  the per-backend CI and refactor tax; the pains are A (cognitive) and B
  (maintenance), which only deletion addresses.
- **Converge AVF on the in-process model** (delete `VzBackend`, avoid the
  console reattach). Rejected — sacrifices snapshot/restore, pause/resume,
  crash isolation, and the warm-start future to save a bounded one-time
  task. Trades a permanent capability for convenience.
- **Keep `cloud_hypervisor` for future VFIO/GPU passthrough.** Deferred, not
  kept — when a workload genuinely needs VFIO, re-add a backend then (YAGNI).
  The ADR-002 matrix note about CH's VFIO niche is removed with the row.

## Out of scope

- The DX-parity follow-on (surface `save`/`restore`, cached fast-boot
  default, base pinning) — its own plan after Plan 177 lands.
- mvmd's backend-enum adoption (cross-repo).
- Re-adding any deleted backend (a future need writes its own ADR).

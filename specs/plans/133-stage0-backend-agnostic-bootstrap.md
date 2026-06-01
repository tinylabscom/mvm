# Plan 133 — Backend-agnostic Stage 0 bootstrap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Stage 0 bootstrap (the from-source build of the steady-state builder VM) dispatch through the `BuilderVm` trait instead of a libkrun-inherent method, then add the deferred Vz and Firecracker Stage 0 implementations so the bootstrap honours the builder-backend selection on every platform.

**Architecture:** ADR-068. `run_stage0` lives on `BuilderVm` (next to `run_build`) with a fail-closed default; the `mvm-cli` orchestration holds `&dyn BuilderVm`. libkrun is the only impl today; Vz and Firecracker are sequenced here. The deeper `VmBackendForBuilder` orchestration port (Plan 97) is the substrate these impls should reuse rather than copy.

**Tech Stack:** `mvm-build` (`builder_vm.rs` trait, `libkrun_builder.rs`, `vz_builder.rs`), `mvm-cli` Stage 0 orchestration (`commands/env/apple_container.rs`), the `mvm-vz-supervisor` (Vz) and Firecracker bridge. No new third-party crates.

**Prereqs:** ADR-068 (accepted). Plan 97's `VmBackendForBuilder` seam exists; the libkrun orchestration port onto it is a soft prereq for the Vz Stage 0 task (reuse, don't duplicate).

**Why a dedicated plan:** the trait promotion is small and shipped immediately, but the Vz/Firecracker Stage 0 impls are real, separately-schedulable work that each need a working second VMM path and their own boot/panic-detection wiring — they don't belong inside an unrelated feature plan.

---

## Phase A — promote Stage 0 to the trait (shipped)

### Task A1: `run_stage0` on `BuilderVm`

- [x] **Step 1:** Add `run_stage0(&self, guest_root_dir, entry_path, workspace_dir, artifact_out, host_bin_dir)` to the `BuilderVm` trait with a fail-closed default returning `BuilderVmError::VmmUnavailable { requested: "stage0-bootstrap", .. }` that names libkrun + ADR-068.
- [x] **Step 2:** Move libkrun's inherent `run_stage0` body to a private `run_stage0_impl(BuilderVmImage, ..)`; override the trait method on `LibkrunBuilderVm` to adapt `(root_dir, entry)` → `BuilderVmImage::RootDir` and call it.
- [x] **Step 3:** Dispatch `run_stage0_root_dir` (mvm-cli) through `&dyn BuilderVm`, binding `LibkrunBuilderVm` concretely (not the Plan 98 selector) so macOS-26+ keeps bootstrapping via libkrun. Drop the now-unused `BuilderVmImage` imports.
- [x] **Step 4:** Test the default gap (Stub inherits a fail-closed, recovery-naming error). Build + clippy + fmt clean; no behavior change for libkrun.

## Phase B — Vz Stage 0 (deferred)

### Task B1: Vz-backed Alpine bootstrap

- [ ] **Step 1:** Implement `run_stage0` on `VzBuilderVm` (`vz_builder.rs`), driving the Alpine `RootDir` guest through the `mvm-vz-supervisor` with the same `/work` (ro), `/out` (rw), `/mvm-bins` (ro) virtio-fs shares libkrun uses. Reuse the Plan 97 `VmBackendForBuilder` spawn primitive rather than copying the libkrun supervisor glue.
- [ ] **Step 2:** Port the kernel-panic detection / clean-exit contract to the Vz console path (Vz exit semantics differ from libkrun's `krun_start_enter`).
- [ ] **Step 3:** Route Stage 0 through the Plan 98 libkrun/Vz builder-backend selector once both backends implement `run_stage0`; macOS-26+ then bootstraps under Vz by default. Update ADR-068 §"Backend gaps".
- [ ] **Step 4:** Tests: Vz Stage 0 produces byte-valid `vmlinux` + `rootfs.ext4` that pass `verify_stage0_rootfs_has_init`; selector picks Vz on macOS-26+ and libkrun elsewhere.

## Phase C — Firecracker Stage 0 (deferred)

### Task C1: Firecracker-backed bootstrap on Linux contributor hosts

- [ ] **Step 1:** Decide the Firecracker Stage 0 I/O model — Firecracker has no virtio-fs; the Alpine root + `/work`/`/out`/`/mvm-bins` shares need a block-device or vsock-fs equivalent. Document the chosen mechanism before implementing.
- [ ] **Step 2:** Implement `run_stage0` for the Firecracker backend (or document that Linux hosts keep using the libkrun-backed bootstrap and Firecracker Stage 0 is intentionally not pursued — whichever the §Step-1 analysis concludes, recorded in ADR-068).
- [ ] **Step 3:** Tests mirroring Phase B, gated to Linux/KVM.

---

## Success criteria

- [x] Stage 0 dispatch names no concrete VMM in the `mvm-cli` orchestration call path.
- [x] A backend without a Stage 0 impl fails closed with a recovery hint (no silent no-op, no `todo!()`).
- [x] libkrun Stage 0 behaviour + artifact digests unchanged.
- [ ] At least one additional backend (Vz) implements `run_stage0` and is selected by default where it is the build backend.

# ADR 068 - Stage 0 dispatches through the `BuilderVm` trait (backend-agnostic bootstrap seam)

**Status**: Accepted
**Date**: 2026-06-01
**Cross-refs**: ADR-013 (libkrun pivot — host never needs Nix), ADR-046 (builder VM via libkrun, the canonical builder-VM ADR), ADR-065 (single builder/dev image, embedded host binaries), ADR-066 §1 (name by role, front with a trait, hide impls), ADR-002 (security posture — dev-tier builder VM). Planning input: Plan 91 (Alpine-minirootfs Stage 0), Plan 97 (`VmBackendForBuilder` hypervisor-agnostic seam), Plan 98 (libkrun/Vz builder-backend selection).

## Context

"Stage 0" is the from-source bootstrap that produces the steady-state builder VM (`vmlinux` + `rootfs.ext4`) on a contributor host with no host Nix and no prebuilt artifacts (ADR-046). The live path (Plan 91) boots an Alpine minirootfs guest under libkrun whose `/init` runs `apk add nix`, builds `nix/images/builder-vm/flake.nix`, and writes the artifacts to `/out`.

The build path (`run_build`) and the per-VM spawn primitive (`VmBackendForBuilder`, Plan 97) are already fronted by traits with libkrun + Vz impls. **Stage 0 was the exception:** `run_stage0` lived as a libkrun-*inherent* method on `LibkrunBuilderVm`, and the orchestration in `mvm-cli` called `LibkrunBuilderVm::default().run_stage0(...)` directly. That hard-wires the bootstrap to one VMM and violates ADR-066 §1 ("name by role, front with a trait, hide impls"). It also reads as a hack: the very first thing the tool does on a fresh host is welded to libkrun, even though macOS 26+ Apple Silicon defaults to the Vz builder backend (Plan 98) for every *subsequent* build.

## Decision

**`run_stage0` moves onto the `BuilderVm` trait.** The orchestration dispatches Stage 0 through `&dyn BuilderVm`, the same seam `run_build` uses. The signature is backend-agnostic — `(guest_root_dir, entry_path, workspace_dir, artifact_out, host_bin_dir)`, all `&Path`/`&str`, no libkrun types. The libkrun impl adapts those to its `BuilderVmImage::RootDir` internally.

```
BuilderVm (mvm-build/src/builder_vm.rs)
  fn run_build(..)                 -> existing
  fn run_stage0(root, entry, ..)   -> NEW; default = fail-closed gap
  fn cleanup(..)                   -> existing

impl BuilderVm for LibkrunBuilderVm  -> overrides run_stage0 (the only impl today)
impl BuilderVm for VzBuilderVm       -> inherits the default gap
impl BuilderVm for StubBuilderVm     -> inherits the default gap
```

### Backend gaps

The default `run_stage0` is a **fail-closed gap, not a silent no-op and not a `todo!()` panic**: it returns `BuilderVmError::VmmUnavailable { requested: "stage0-bootstrap", reason }` naming the supported backend (libkrun) and this ADR. Stage 0 is implemented for **libkrun only** today.

- **Vz Stage 0** — deferred. Vz is the macOS-26+ default for *builds* (Plan 98), but the Alpine-bootstrap Stage 0 has no Vz impl yet. The orchestration therefore binds libkrun concretely for Stage 0 (it does **not** route through the Plan 98 libkrun/Vz selector), so macOS-26+ hosts still bootstrap via libkrun and then run builds under Vz. Tracked in Plan 133.
- **Firecracker Stage 0** — deferred. Firecracker is the Linux runtime path; on Linux contributor hosts Stage 0 runs the same libkrun-backed bootstrap. mvmd drives Firecracker+jailer independently and does not consume this seam. Tracked in Plan 133.

Routing Stage 0 through the Plan 98 selector is **out of scope** until a second backend implements `run_stage0`; doing it now would regress macOS-26+ hosts to the gap error. The seam exists so that wiring is a localized change (one impl + flip the dispatch) when a Vz/Firecracker Stage 0 lands, with no change to the `mvm-cli` orchestration.

### Why this and not the deeper `VmBackendForBuilder` port

Plan 97 already landed `VmBackendForBuilder` — the lower-level spawn primitive (`run_attached_with_mounts` + `console_log_path`) — with the intent that a future `BuilderVmRuntime` helper lifts ~850 lines of orchestration (cmd.sh emission, `/job/result` parsing, panic detection, `NixStoreImageLock`) out of `LibkrunBuilderVm` so Vz reuses it. That port is the larger effort. This ADR is the *complementary, smaller* move: `run_stage0` belongs on the high-level `BuilderVm` driver next to `run_build`, and promoting it is a contained change that delivers the backend-agnostic Stage 0 dispatch immediately without blocking on the full port.

## Consequences

- The `mvm-cli` Stage 0 orchestration no longer names a concrete VMM in its call path — it holds `&dyn BuilderVm`. Adding a backend is an impl, never an orchestration edit (ADR-066 §1).
- No behavior change today: libkrun remains the sole Stage 0 backend; the artifact bytes and the `.mvm-artifacts.sha256` / `.mvm-provenance.json` sidecars are unchanged.
- A backend that forgets to implement Stage 0 fails loudly with a recovery hint, not silently.
- Security posture unchanged: Stage 0 is the dev-tier builder VM (ADR-002 out-of-scope for the hardened workload claims); this is a structural refactor of the dispatch, not of the trust model.

## Status of work

Libkrun dispatch + the fail-closed default + tests landed with this ADR. Vz and Firecracker Stage 0 impls are sequenced in Plan 133.

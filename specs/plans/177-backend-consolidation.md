# Plan 177 — Backend consolidation (8 → 4) (Implementation Plan)

> **Numbering:** 177 is the next free plan number (`origin/main` holds plans
> through 175; 176 = comment-ref sweep). `check-spec-numbers` rejects
> duplicates — confirm still-free at merge.

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax.
>
> **Decision source:** [ADR-076](../adrs/076-backend-matrix-consolidation.md)
> (amends ADR-056 + ADR-002).

**Goal:** Reduce the VM-backend matrix from 8 impls (+mock) to 4 — libkrun,
firecracker, vz, one dev/test (qemu) — by deleting two unused backends,
folding two dev/test backends into one, and converging the two parallel
Apple Virtualization.framework paths onto a single supervisor-model `vz`.

**Architecture:** `AnyBackend` is the dispatch enum in
`crates/mvm-backend/src/backend.rs`; each backend is a module + `VmBackend`
impl, wired through `from_hypervisor`, `auto_select`, `from_pid_files`,
`tier`, and the `all()` test vector. Removal = drop the module, its enum
variant, every match arm, the `doctor` row, and the CI lane. The AVF
convergence keeps `VzBackend` (per-VM supervisor, snapshot/restore) and
deletes the in-process `providers/apple_container` duplicate.

**Tech Stack:** Rust, clap, `VmBackend` trait, objc2-virtualization (vz),
the `mvm-vz-supervisor` / `mvm-libkrun-supervisor` per-VM host bins.

---

## Guardrails (every task)

- Never regress the 16 security claims or their command/audit paths.
- No SSH; no Docker on the runtime path (deleting `docker` reinforces this).
- **Keep the `VmBackend` trait** — backends are impls, not the only path
  (`feedback_no_vmm_lockin_keep_backend_trait`).
- **Verify who-calls before deleting** any backend: `rg` the type name
  across `crates/`, `src/`, and confirm mvmd doesn't consume it via the
  `mvmctl::backend` facade.
- `mvm-backend` test bins can SIGKILL on this macOS host
  (`reference_mvm_backend_test_binary_macos_codesign_sigkill`) — scope
  nextest to the crate under test; lean on Linux CI for `mvm-backend`.
- CI fmt is nightly: `rustup run nightly cargo fmt --all` before each commit.
- Per-task: `cargo clippy -p <crate> --all-targets -- -D warnings` clean.
- No `Co-Authored-By: Claude` trailer.

## File Structure

Deleted:
- `crates/mvm-backend/src/docker.rs`
- `crates/mvm-backend/src/cloud_hypervisor.rs`
- `crates/mvm-backend/src/microvm_nix.rs`
- `crates/mvm-backend/src/providers/apple_container/` (Phase 2)
- `crates/mvm-backend/src/apple_container.rs` (Phase 2)

Modified:
- `crates/mvm-backend/src/lib.rs` — drop `mod` decls.
- `crates/mvm-backend/src/backend.rs` — drop variants, match arms,
  `from_hypervisor`/`auto_select`/`from_pid_files`/`tier`/`all()` entries.
- `crates/mvm-cli/src/doctor.rs` — drop the deleted backends' rows.
- `.github/workflows/{ci,ci-full,architecture}.yml` — drop dead lanes.

---

## Phase 1 — Cheap deletions (no VZ dependency; START NOW)

### Task 1: Delete the `docker` backend
**Files:** delete `crates/mvm-backend/src/docker.rs`; modify
`crates/mvm-backend/src/lib.rs`, `backend.rs`, `crates/mvm-cli/src/doctor.rs`.

- [ ] **Step 1 — who-calls audit.** Run `rg -n 'DockerBackend|"docker"|has_docker|Docker\b' crates/ src/` and confirm every hit is in `mvm-backend`/`doctor`/tests (no mvmd-facing or runtime-path dependency). Record the hit list in the commit body.
- [ ] **Step 2 — write the failing assertion.** In `backend.rs` tests, change the `from_hypervisor("docker")` test to assert it now falls through to the default (`Firecracker`), and drop `Docker` from the `all()`/`tier` Tier-3 test vectors. Run `cargo nextest run -p mvm-backend from_hypervisor` → expect FAIL (still returns `Docker`).
- [ ] **Step 3 — remove the backend.** Delete `docker.rs`; remove `pub mod docker;` (`lib.rs:52`), `use crate::docker::DockerBackend;` (`backend.rs:15`), the `Docker(DockerBackend)` variant, the `"docker" =>` arm (`from_hypervisor`), the `has_docker()` fallback branch in `auto_select` (`backend.rs:447-452`), the `Docker` arms in `from_pid_files`/`tier`/`inner`/`all()`, and the `doctor.rs` docker rows (`~993-1000`).
- [ ] **Step 4 — green.** `cargo nextest run -p mvm-backend` PASS; `cargo clippy -p mvm-backend -p mvm-cli --all-targets -- -D warnings` clean.
- [ ] **Step 5 — commit.** `git commit -m "refactor(backend): remove unused docker backend"`

### Task 2: Delete the `cloud_hypervisor` backend
**Files:** delete `crates/mvm-backend/src/cloud_hypervisor.rs`; modify `lib.rs`, `backend.rs`, `doctor.rs`.

- [ ] **Step 1 — who-calls audit.** `rg -n 'CloudHypervisorBackend|cloud.?hypervisor|CloudHypervisor|"ch"|"clh"' crates/ src/`. Confirm no auto-select / mvmd path. Note: it shares `BackendTier::Tier1` with Firecracker (`backend.rs:521`) — Firecracker remains the sole Tier-1.
- [ ] **Step 2 — failing assertion.** Change the `from_hypervisor("cloud-hypervisor")` test to assert default-fallback; drop `CloudHypervisor` from the Tier-1 test vector. `cargo nextest run -p mvm-backend` → FAIL.
- [ ] **Step 3 — remove.** Delete the module; remove `pub mod cloud_hypervisor;` (`lib.rs:50`), the `use`, the `CloudHypervisor(...)` variant, the `"cloud-hypervisor" | "cloud_hypervisor" | "ch" | "clh" =>` arm (`backend.rs:395-396`), the `tier()` Tier-1 arm (`backend.rs:521`), `inner`/`all()` entries, and the `doctor.rs` cloud-hypervisor row (`~421`).
- [ ] **Step 4 — green.** nextest + clippy as Task 1.
- [ ] **Step 5 — commit.** `git commit -m "refactor(backend): remove unused cloud_hypervisor backend"`

### Task 3: Fold `microvm_nix` into `qemu`
**Files:** delete `crates/mvm-backend/src/microvm_nix.rs`; modify `lib.rs`, `backend.rs`.

- [ ] **Step 1 — map the consumers.** `rg -n 'MicrovmNix|microvm_nix|from_build_output' crates/ src/`. The `from_build_output` path (`backend.rs:377`) and `pub use microvm_nix::{MicrovmNixBackend, MicrovmNixConfig};` (`backend.rs:24`) are the load-bearing seams. Confirm `QemuBackend` covers the same "no-KVM dev/test" role (it's the real TCG impl, Tier-2, `--hypervisor qemu`).
- [ ] **Step 2 — failing assertion.** Add/extend a test asserting `from_build_output(<microvm-nix-shaped output>)` now yields `Qemu`, and that `MicrovmNix` is no longer a variant. `cargo nextest run -p mvm-backend` → FAIL (won't compile / wrong variant).
- [ ] **Step 3 — migrate + remove.** Repoint `from_build_output`'s MicrovmNix arm to `Qemu(QemuBackend)`; delete `microvm_nix.rs`, `pub mod microvm_nix;` (`lib.rs:58`), the `pub use microvm_nix::...` re-export, the `MicrovmNix(...)` variant, and its `is_microvm_nix`-style/`tier`/`inner`/`all()` arms (`backend.rs:336,377,536,550`). Keep `QemuConfig` carrying any microvm.nix-specific field that `from_build_output` actually set (port it onto `QemuConfig`, don't drop behavior).
- [ ] **Step 4 — green.** `cargo nextest run -p mvm-backend`; `cargo nextest run -p mvm-cli`; clippy clean. Confirm `--hypervisor qemu` still resolves and `kvm_available()` gating (`backend.rs:155`) is intact.
- [ ] **Step 5 — commit.** `git commit -m "refactor(backend): fold microvm_nix into qemu dev/test backend"`

### Task 4: Prune dead CI lanes + doctor support map
**Files:** `.github/workflows/{ci,ci-full,architecture}.yml`; `crates/mvm-cli/src/doctor.rs` tests.

- [ ] **Step 1 — find lanes.** `rg -n 'docker|cloud-hypervisor|cloud_hypervisor|microvm.nix' .github/workflows/`. List each job/step that exercises a removed backend.
- [ ] **Step 2 — remove lanes** that only test removed backends; for shared lanes, drop just the removed-backend matrix entries. Update the `doctor` support-map test (`doctor.rs:~2586` asserts `support.get("cloud-hypervisor")`) to drop deleted keys.
- [ ] **Step 3 — green.** `rustup run nightly cargo fmt --all`; `cargo nextest run -p mvm-cli`; sanity-grep that no workflow references a deleted backend.
- [ ] **Step 4 — commit.** `git commit -m "ci: drop lanes for removed backends"`

### Task 5: Phase 1 verification
- [ ] `rg -n 'DockerBackend|CloudHypervisorBackend|MicrovmNixBackend' crates/ src/` returns nothing.
- [ ] `just ci` green (fmt, nextest, doctests, clippy, `check-claim-catalog`, `check-spec-numbers`, `check-adr-coverage`).
- [ ] `mvmctl doctor` lists exactly: libkrun, firecracker, vz, apple-container, qemu, mock (apple-container still present — collapses in Phase 2).
- [ ] Tick the Phase 1 boxes in `specs/REFACTOR-STATUS.md`; bump "Last updated".

---

## Phase 2 — AVF convergence (GATED — do not start until both land on `main`)

> **STATUS (2026-06-12): the convergence LANDED in #806.** Tasks 6-9 plus
> Task 10's docs are done: the `apple_container` backend + `providers/` are
> deleted, `AnyBackend` resolves macOS-26 to `Vz`, CoW per-instance rootfs is
> ported (#789), `mvmctl dev` + `up -d` run on the detached vz supervisor
> (`VzPersistentBuilderVm`, no launchd), `has_apple_containers`→
> `is_vz_default_tier`, every `"apple-container"` selector collapsed to vz,
> CLAUDE.md + ADR-002 tier matrix updated. **Not yet ticked DONE:** the live
> macOS-26 vz `dev up`/`up` hardware smoke (host-gated) and the cosmetic
> rename slice (the env module file `apple_container.rs`, `AppleContainerEnv`,
> `MicrovmBackend::AppleContainer`, and the objc2 `mvm_apple_container_*` cdecl
> symbols still carry the old name — functional path is already vz).

> **GATE:** `feat/plan-152-wsb-rust-vz-supervisor` (Plan 152 WS-B, native
> objc2 VZ supervisor) **and** `feat/plan-152-fix-vz-save-pause` must be
> merged to `main` first. They rewrite the VZ supervisor surface this phase
> edits. **First task below re-reads that surface against merged `main`** —
> the code references here are from pre-merge `main` and WILL move.

### Task 6: Re-baseline against merged 152 work
- [ ] Rebase this branch on `main` after the gate clears.
- [ ] Re-read `crates/mvm-backend/src/vz.rs`, `crates/mvm-vm-host` VZ
      supervisor bin, and `crates/mvm-backend/src/providers/apple_container/`
      (`mod.rs` + `macos.rs`). Re-confirm: (a) `VzBackend` still owns
      snapshot/restore + pause/resume; (b) what `AppleContainerBackend`
      uniquely does that `VzBackend` does not (admission gate ordering, CoW
      rootfs clone via `prepare_instance_rootfs`, `runtime_meta` recording);
      (c) the console attach point. Write the delta as a checklist comment
      on this task before editing.

### Task 7: Port AppleContainerBackend-unique behavior onto VzBackend
**Files:** `crates/mvm-backend/src/vz.rs`; reference `apple_container.rs`.

- [ ] **Step 1 — failing test.** Add a `VzBackend::start` test asserting the macOS-26 admission behaviors the in-process path had: refuses a pre-`/mvm/runtime` rootfs (`admit_overlay_aware`), CoW-clones to a per-instance rootfs, and records `runtime_meta` from the source sidecar. FAIL initially.
- [ ] **Step 2 — port.** Move the unique logic (admission gate ordering, `prepare_instance_rootfs` CoW clone, `runtime_meta::record_from_rootfs`) into the `VzBackend::start` path, reusing the existing helpers (don't fork copies). Whatever is shared host substrate goes through `base`.
- [ ] **Step 3 — green.** `cargo nextest run -p mvm-backend -E 'test(vz)'` (scope to avoid the SIGKILL bin); clippy clean.
- [ ] **Step 4 — commit.** `git commit -m "feat(backend): port apple_container admission+CoW onto VzBackend"`

### Task 8: Shared libkrun+vz console transport
**Files:** new shared console-attach in `crates/mvm-backend/src/base/` (or the existing libkrun console module if that's the established home); modify `vz.rs`, `console.rs` callers.

- [ ] **Step 1 — locate the reuse target.** Find libkrun's console-over-supervisor-vsock (`open_console_capture` / `LibkrunTransport` per `reference_libkrun_workload_boot_verify_and_empty_console`). Confirm the shape: host attaches to the per-VM supervisor's vsock console socket, write-only capture for sealed prod (claim 15), read/write for dev.
- [ ] **Step 2 — failing test.** Add a test that `mvmctl console` against a vz-supervised dev VM attaches over the supervisor socket (mirror libkrun's existing console test). FAIL.
- [ ] **Step 3 — generalize.** Extract libkrun's console attach into a backend-shared helper parameterized by the supervisor's console socket path; wire both libkrun and vz to it. Preserve claim-15: prod console is write-only, no host input fd (`prod_console_attachment_has_no_input`).
- [ ] **Step 4 — green.** `cargo nextest run -p mvm-backend -E 'test(console)'`; re-run `prod_console_attachment_has_no_input` + `console_refused_on_sealed_image`. clippy clean.
- [ ] **Step 5 — commit.** `git commit -m "refactor(backend): shared libkrun+vz supervisor console transport"`

### Task 9: Delete the in-process AVF duplicate + collapse the alias
**Files:** delete `crates/mvm-backend/src/providers/apple_container/`, `crates/mvm-backend/src/apple_container.rs`; modify `lib.rs`, `backend.rs`, `doctor.rs`, CLI alias.

- [ ] **Step 1 — who-calls audit.** `rg -n 'AppleContainerBackend|providers::apple_container|apple-container|has_apple_containers' crates/ src/`. Confirm Task 7/8 covered every unique behavior and that nothing else (dev env path, mvmd facade) needs the in-process type.
- [ ] **Step 2 — failing assertion.** Change tests: `from_hypervisor("apple-container")` and `from_hypervisor("vz")` BOTH resolve to `Vz(VzBackend)`; `auto_select` on macOS-26 returns `Vz`. FAIL initially.
- [ ] **Step 3 — remove + repoint.** In `from_hypervisor`, map `"apple-container"` → `Vz(VzBackend)` (kept as a deprecated-input alias only, or dropped per no-backcompat — pick drop unless a current caller needs it; record the choice). Repoint `auto_select`'s `has_apple_containers()` branch (`backend.rs:438-439`) to `Vz(VzBackend)`. Delete the `AppleContainer` variant, the module + provider dir, the `pub mod`s, and the `doctor` apple-container row.
- [ ] **Step 4 — green.** `cargo nextest run -p mvm-backend -p mvm-cli` (scoped); clippy clean. On this Mac, hardware-verify a macOS-26 `mvmctl up` boots on the unified `vz` default (`project_dev_host_runs_builder_via_vz`; isolate with `MVM_CACHE_DIR`/`MVM_DATA_DIR`).
- [ ] **Step 5 — commit.** `git commit -m "refactor(backend): converge AVF on supervisor vz; drop in-process apple_container"`

### Task 10: Phase 2 verification + docs
- [ ] `rg -n 'AppleContainerBackend|providers/apple_container' crates/ src/` returns nothing.
- [ ] `just ci` green; hardware `mvmctl up`/`dev` smoke on macOS-26 `vz` default passes.
- [ ] Update `CLAUDE.md` ("Apple Container is the macOS 26+ backend" → one `vz` AVF backend) and `specs/adrs/002` per-backend tier matrix (remove docker/cloud_hypervisor/microvm_nix/apple-container rows).
- [ ] Tick Phase 2 boxes in `specs/REFACTOR-STATUS.md`; bump "Last updated".

---

## Self-review / success criteria
- [ ] 8 backends (+mock) → 4 (libkrun, firecracker, vz, qemu) + mock.
- [ ] One AVF code path (`VzBackend`, supervisor model), honestly named.
- [ ] snapshot/restore + pause/resume retained; macOS-26 console works over
      the shared supervisor transport; claim-15 prod console invariants hold.
- [ ] No capability regressions; no security-claim regressions; `just ci`
      green at the end of each phase.
- [ ] Phase 2 was not started until the Plan 152 gate cleared.

## deferred follow-ups
- [ ] DX-parity workstream (surface `save`/`restore`, cached fast-boot
      default, `--json` coverage, base pinning) — its own plan after this
      lands. See design note §"DX-parity follow-on".

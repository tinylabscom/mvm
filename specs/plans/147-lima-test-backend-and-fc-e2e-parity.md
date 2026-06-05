# Plan 147 — Lima test-env backend + Linux/Firecracker core_demo E2E parity (deferred)

> **Status: DEFERRED — revisit during/after the rearchitecture refactor.**
> Captured to de-orphan three deferred bullets from Plan 120 (core demo) that
> no plan currently owns. Sequence after the rearchitecture (Plans 117/121) and
> the active builder-VM/backend churn settle — coordinate to avoid collisions.
>
> **Complemented by Plan 152 WS-D (2026-06-05): native nested-virt `/dev/kvm`.**
> On **M3+ / macOS 26**, Plan 152's Rust VZ supervisor can expose `/dev/kvm`
> inside a VZ guest natively (`setNestedVirtualizationEnabled`), giving
> Firecracker-on-macOS with no Lima dependency. That does **not** retire
> this plan: Lima stays the **portable / CI** `/dev/kvm` provider (GitHub
> runners, Intel, older macOS, M1/M2). Design the `MVM_E2E_BACKEND`-style
> selector (bullet 2 below) so both register as providers and capability
> detection prefers nested-virt where available, falling back to Lima.

## Context

Plan 120 (the core demo: `dev up → compile → up → agent invoke`) closed green on
**macOS/libkrun** — and was re-proven there for both Python and TypeScript
(`core_demo_e2e` pins `MVM_BUILDER_BACKEND=libkrun` + `MVM_LIBKRUN_SUPERVISOR_PATH`
on macOS). Three follow-ups were deferred as bullets with **no owning plan**:

1. **Lima test/dev-tier `VmBackend`.** ADR-066 §177 records the *decision* (Lima
   is re-addable via the `VmBackend` trait as a test/dev-only, **prod-refused**
   backend — like the Docker tier — giving a virtual `/dev/kvm` for the
   Firecracker E2E that can't run on the builder VM or GitHub-hosted runners),
   but it is **"not built in this rewrite"** and no plan owns the build.
2. **Linux/Firecracker parity for the core_demo E2E.** Today the E2E only runs
   the libkrun path; there is no `MVM_E2E_BACKEND` selector (it's named in
   Plan 120's prose but **not implemented** anywhere in code/tests).
3. **The `default-microvm` admit blocker.** The no-`--flake` default image is
   download-only and sidecar-less, so `mvm_build::builder_vm::admit_overlay_aware`
   (called from every backend — `backend.rs:137`, `libkrun.rs:197`, `vz.rs:210`)
   refuses it; its build flake `nix/images/default-tenant/` is **missing from
   main**. Blocks the bench baseline.

(1) and (2) are one coupled effort — Lima is the vehicle that lets the Firecracker
core_demo E2E run in CI/test. (3) is adjacent and folded in here.

**Hard constraint (memory + ADR-066 + AGENTS.md):** Lima is **test-env only** —
never a build/eval/prod/runtime path, no `--lima` flag, prod admission must refuse
it via an admission-visible `BackendSecurityProfile`. This plan must not reopen
Lima as a general backend.

## Workstream A — Lima test/dev-tier `VmBackend`

- [ ] Implement a `LimaBackend` (or equivalent) `VmBackend`
  (`crates/mvm-core/src/protocol/vm_backend.rs` seam) that drives a Lima VM to
  expose a virtual `/dev/kvm` for Firecracker. Carry a **test/dev-only,
  prod-refused** `BackendSecurityProfile` (mirror the Docker fallback tier).
- [ ] `AnyBackend` variant + `from_hypervisor` (`crates/mvm-backend/src/backend.rs`),
  **but `auto_select()` MUST never return it** (opt-in only, like wasm-sandbox in
  Plan 144). Gate selection behind an explicit test env var (WS-B), not a prod flag.
- [ ] Update ADR-066 §177 and AGENTS.md from "not built" → "built for test env,"
  preserving the never-builds/never-evals/prod-refused constraints.
- [ ] Tests: `from_hypervisor` resolves Lima only under the test selector; a prod
  admission attempt is refused with a clear typed error; `auto_select` never picks it.

## Workstream B — Linux/Firecracker core_demo E2E parity

- [ ] Introduce the `MVM_E2E_BACKEND` selector (named in Plan 120's prose, not yet
  real) so `crates/mvm-cli/tests/core_demo_e2e.rs` can target Firecracker over the
  Lima `/dev/kvm` in addition to today's macOS/libkrun path. Keep it `MVM_E2E_SMOKE`-
  gated and hardened against freezing (the existing watchdog/bounded-subprocess).
- [ ] A CI lane (Linux runner) that runs `core_demo_e2e` on Firecracker via the
  Lima test backend — the Linux half of the regression guard libkrun already covers.
- [ ] Confirm the same `dev up → compile → up → agent invoke → result` spine passes
  for Python (and TypeScript) on Firecracker, matching the macOS/libkrun result.

## Workstream C — `default-microvm` admit blocker

- [ ] Ship `nix/images/default-tenant/` (the missing build flake) so the no-`--flake`
  default image is built with the overlay sidecars `admit_overlay_aware` requires —
  OR carve a documented, admission-visible admit path for the sidecar-less default
  image. Decide which; don't silently weaken `admit_overlay_aware`.
- [ ] Unblocks the bench baseline (Plans 118/119) that needs a bootable default image.
- [ ] Test: `mvmctl up` with no `--flake` boots the default image through the
  admitted path (or fails with a clear, documented message if intentionally unsupported).

## Sequencing & risk

- Deferred; lands after Plans 117/121 (rearchitecture, crate freeze) and once the
  builder-VM/backend area stops churning (`slim-builder-kernel`, `kernel-build`,
  `builder-vm-repro`).
- WS-A/WS-B are coupled; WS-C is independent and could land first.
- Lima strictly test-env — re-read the constraint above before touching backend selection.

## References
- ADR-066 §177 — the Lima test/dev-tier `VmBackend` decision ("not built").
- `specs/plans/120-core-demo.md` — the deferred follow-ups this plan de-orphans.
- `crates/mvm-cli/tests/core_demo_e2e.rs` — the regression guard (libkrun-pinned today).
- `crates/mvm-core/src/protocol/vm_backend.rs`, `crates/mvm-backend/src/backend.rs` — the backend seam.
- `mvm_build::builder_vm::admit_overlay_aware` — the sidecar/overlay admission check that refuses the default image.
- AGENTS.md — Lima test-env-only constraint.

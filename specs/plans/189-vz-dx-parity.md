# Plan 189 — VZ DX parity (post-convergence follow-on) (Implementation Plan)

> **Numbering:** 189 is the next free plan number (`origin/main` holds plans
> through 185 + 188; 186/187/188 are claimed by merged/open PRs).
> `check-spec-numbers` rejects duplicates — confirm 189 still-free at merge.
> (Drafted as 182, bumped to 188, then to 189 as concurrent sessions landed
> 182/184/185/188 — the numbering space churned during this PR.)

> **For agentic workers:** Use `superpowers:subagent-driven-development` or
> `superpowers:executing-plans`. Steps use checkbox (`- [ ]`) syntax. This is a
> scoping stub — each workstream below needs a who-calls audit + failing-test
> step fleshed out before implementation, in the plan-doc style of Plan 177.

> **Decision source:** [ADR-076](../adrs/076-backend-matrix-consolidation.md)
> §"Out of scope" deferred this as "the DX-parity follow-on … its own plan
> after Plan 177 lands." Plan 177 landed 2026-06-12.

> **Status: 🟡 in progress.** Spun out of [Plan 177](./177-backend-consolidation.md)
> §"deferred follow-ups". WS-3 first slice landed: `dev status --json`.

**Goal:** Bring the converged single `vz` Apple-Virtualization.framework path to
DX parity with the reference embeddable-sandbox SDK — the table-stakes floor
beneath the security spine (per `specs/research/embeddable-sandbox-sdk-dx-gap-analysis.md`).
The convergence (Plan 177) unified the backend; this surfaces the supervisor's
existing primitives as ergonomic, scriptable user-facing verbs.

**Relationship to [Plan 159](./159-vz-inspired-macos-dx.md):** 159 owns the
broader VZ-DX feature clone (warm pool WS-1, checkpoint/fork WS-2 — both merged).
**182 owns only the additive parity slice ADR-076 named** and cross-references
159 for the underlying primitives; where 159 (or Plan 140 snapshot
productionization / Plan 148 fork-fanout) already owns a primitive, the
workstream here is the CLI/UX layer on top, not a reimplementation.

**Tech Stack:** Rust, clap, the `VmBackend` snapshot/restore + pause/resume
surface, `mvm-vz-supervisor`, `VzPersistentBuilderVm`.

---

## WS-1: Surface `save` / `restore`

The supervisor already implements `saveMachineStateToURL` / `restoreMachineState`
(`VzBackend::snapshot_capability` → `SaveRestore` on macOS 14+; the SAVE
pause→save→resume fix is in). Expose it as first-class verbs rather than an
internal primitive.

- [ ] who-calls audit: confirm the snapshot/restore entrypoints + which
      verbs (`mvmctl vm save/restore`? `mvmctl checkpoint`?) the existing
      surface already has vs. needs (overlaps Plan 159 WS-2 checkpoint/fork —
      reuse, don't fork).
- [ ] honest capability gating: `save`/`restore` refuse cleanly on a backend
      whose `snapshot_capability()` is `Unsupported` (Linux/older macOS), with
      the tier surfaced via `doctor`.
- [ ] acceptance: round-trip a vz VM through save → stop → restore on macOS-26
      hardware; state preserved.

## WS-2: Cached fast-boot default

The dev-image fingerprint fast-path exists (`ensure_dev_image` skips the builder
VM on a fingerprint match). Make cached fast-boot the *default* posture across
the vz boot surface, not just the dev image.

- [ ] who-calls audit: enumerate every vz boot entry (`dev up`, `up`,
      `VzPersistentBuilderVm`) and where each does/doesn't honor a cached
      artifact fast-path.
- [ ] make fingerprint-match fast-boot the default; loud, observable cache
      decision when it misses (reuse the existing `cache decision` reason-code).
- [ ] acceptance: a warm `dev up` on macOS-26 skips the builder VM and reaches
      guest-agent-ready in the fast-path budget.

## WS-3: `--json` coverage

Machine-readable output for the vz lifecycle verbs so the surface is scriptable
(mirrors Plan 168's `--json` work on the bootstrap/download verbs).

**Inventory (audit done):** the shared emitter is `crate::json_out::{emit_json,
to_json_string}` (pretty, newline-terminated, no envelope). `dev cache inspect`
already has `--json` and sets the privacy floor — cache fields report
`present`/`missing`/`cached`, never a local artifact path or digest. Dev/vz
lifecycle verbs lacking `--json`: `dev status` (done below), `dev up`,
`dev down`, and the snapshot/checkpoint verbs (those route through Plan 159
WS-2 / Plan 140 — add `--json` there, don't fork).

- [x] **`dev status --json`** — versioned (`schema_version: 1`), privacy-safe
      `DevStatusJson { backend, vm_name?, state, guest_kernel?, dev_image?,
      builder_cache? }`. `guest_kernel` is the running guest's probed `uname -r`
      (skipped when the VM is down), deliberately distinct from
      `dev_image.kernel` (present/missing of the cached image's kernel
      artifact). Wired through all four dispatch arms (vz / libkrun /
      linux-native / unsupported) via a pure `build_dev_status_json[_vmless]`
      builder; serde + privacy + CLI-parse tests; manually verified on
      macOS-26. Reuses the cache-inspect JSON sub-structs.
- [x] **`dev down --json`** — `DevLifecycleJson { schema_version, backend,
      action, outcome, reset? }`; `outcome` is `stopped`/`not-running`, `reset`
      appears only when `--reset` actually dropped the Nix-store overlay. The
      down handlers now return `was_running` (presentation moved to the
      dispatch); serde + CLI-parse tests; verified on macOS-26.
- [ ] `dev up --json` — emit `{action: "up", outcome: started/already-running}`
      after boot; implies `--no-shell` (the default path is interactive). Its
      own slice (the up path is heavier + branches through build/boot/shell).
- [ ] snapshot/checkpoint `--json` — add to the Plan 159/140 verbs in place
      (don't duplicate the primitive); WS-1 (`save`/`restore`) lands its own.
- [ ] linux-native richer `--json` — today it collapses to a single `state`
      (`ready`/`not-ready`/`no-kvm`); surface the kvm/firecracker/assets detail
      as a typed shape if a Linux consumer needs it.
- [ ] acceptance: every vz lifecycle verb has a documented `--json` form with
      a stable schema + test.

## WS-4: Base pinning

Pin a vz VM to a named base image / revision so a `dev up` / fork reproducibly
starts from a known closure (the DX the reference SDK offers via image refs).

- [ ] design: how a base ref is named, stored, and resolved (reuse the
      artifact-model / template machinery — Plan 134 / template verbs — don't
      add a parallel registry).
- [ ] wire base-ref resolution into the vz boot path; fail closed on an
      unknown/unbuilt base.
- [ ] acceptance: `dev up`/fork from a pinned base reproducibly yields the same
      rootfs fingerprint.

---

## Self-review / success criteria
- [ ] `save`/`restore` are first-class verbs, honestly gated by backend tier.
- [ ] Cached fast-boot is the default; cache decisions are observable.
- [ ] Every vz lifecycle verb has a stable `--json` form.
- [ ] Base pinning reuses the existing artifact/template machinery (no parallel
      registry).
- [ ] No security-claim regressions; no duplication of Plan 159/140/148
      primitives — only the DX/UX layer on top.

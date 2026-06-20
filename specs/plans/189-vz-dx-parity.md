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
> §"deferred follow-ups". WS-3 lifecycle/checkpoint verbs landed:
> `dev status/down/up --json` and `vm checkpoint`/`vm snapshot` JSON coverage.
> WS-1 first-class `vm save` / `vm restore` aliases landed; live acceptance
> remains hardware-gated.
>
> **Priority update 2026-06-15:** Plan 200 owns the new beginner-facing
> `mvmctl machine` lifecycle. This plan should stay limited to VZ-specific
> parity and scriptability (`--json`, save/restore capability surfacing, base
> pinning). Do not add a parallel beginner lifecycle surface here.

**Goal:** Bring the converged single `vz` Apple-Virtualization.framework path to
DX parity with the reference embeddable-sandbox SDK — the table-stakes floor
beneath the security spine (per `specs/research/embeddable-sandbox-sdk-dx-gap-analysis.md`).
The convergence (Plan 177) unified the backend; this surfaces the supervisor's
existing primitives as ergonomic, scriptable user-facing verbs.

**Relationship to [Plan 159](./159-vz-inspired-macos-dx.md):** 159 owns the
broader VZ-DX feature clone (warm pool WS-1, checkpoint/fork WS-2 — both merged).
**Plan 189 owns only the additive parity slice ADR-076 named** and cross-references
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

- [x] who-calls audit: existing Vz save/restore lives under
      `mvmctl vm checkpoint create --class vm-full` and
      `mvmctl vm checkpoint restore`; Plan 189 should expose ergonomic
      `mvmctl vm save` / `mvmctl vm restore` aliases over that primitive, not
      fork a parallel supervisor path.
- [x] honest capability gating: `save`/`restore` check the Vz
      `snapshot_capability()` tier and refuse before checkpoint mutation unless
      the host reports `save-restore`; doctor already surfaces the same tier.
      Parser tests pin both aliases, audit coverage classifies them as
      `CheckpointCreated` / `CheckpointRestored`, and lifecycle convergence
      runs on entry.
- [ ] acceptance: round-trip a vz VM through save → stop → restore on macOS-26
      hardware; state preserved.

## WS-2: Cached fast-boot default

The dev-image fingerprint fast-path exists (`ensure_dev_image` skips the builder
VM on a fingerprint match). Make cached fast-boot the *default* posture across
the vz boot surface, not just the dev image.

- [x] **who-calls audit** — enumerated every vz boot entry; each already honors
      a fast-path or is cache-hit-only:
      - `dev up` → dev-image (`ensure_dev_image`): fingerprint fast-path
        ("Fix A") for the source checkout + version-keyed cache for the
        published prebuilt. ✅
      - `dev up` → builder-VM bootstrap (`resolve_builder_vm_bootstrap_action`
        → `UseCached`): fingerprint fast-path. Plan 195 removed the
        whole-`Cargo.lock` churn that made this miss on most runs. ✅
      - `dev up` → persistent dev VM (`VzPersistentBuilderVm`): reuse-if-alive
        via PID-liveness → `already-running` (the running-VM-reuse dimension,
        adjacent to the Plan 118 warm pool). ✅
      - `mvmctl up` (workload): cache-hit-only (`driver = None`) — never spawns
        the builder VM; deps-volume + runtime-overlay resolution are pure cache
        reads that fall back to a legacy boot on a cold cache. ✅
      Finding: **the surface is already fast-boot-default**; the gap this
      workstream was written against (only the dev image had the fast-path)
      was closed by prior incremental work, and Plan 195 made the builder-VM
      leg reliably *hit*.
- [x] **observable cache decision** — the dev-image and builder-VM legs already
      log the `cache decision` reason-code via `ui::progress`, and a dev-image
      hit logs a success line. No entry rebuilds silently.
- [ ] acceptance: a warm `dev up` on macOS-26 skips the builder VM and reaches
      guest-agent-ready in the fast-path budget. **Converges with the Plan 195
      live validation** (a warm `dev up` hitting the cache) — run both in one
      pass on a quiet box. Only remaining WS-2 item; no new implementation
      required.

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
- [x] **`dev up --json`** — `DevLifecycleJson { schema_version, backend,
      action: "up", outcome, reset: false }`; `outcome` is
      `started`/`already-running` (vz/libkrun) or `host-native` (linux-KVM,
      where the host *is* the dev env). `--json` is non-interactive: it forces
      chrome to stderr, suppresses the shell, and `conflicts_with = "shell"`.
      The up handlers now return the outcome string (presentation moved to the
      dispatch, mirroring `dev down`); serde + CLI-parse + conflict tests;
      verified on macOS-26 via the Plan 177 cold-build smoke.
- [x] snapshot/checkpoint `--json` — added in place to the Plan 159/140
      surfaces without duplicating the primitive: `vm checkpoint restore/rm/fork
      --json` now emit schema-versioned mutation results, and `vm snapshot rm
      --json` mirrors the existing `snapshot ls --json`. `checkpoint create`,
      `checkpoint ls`, and `checkpoint diff` already had JSON coverage. Parser
      tests pin every new flag; CLI reference corrected from stale top-level
      `mvmctl checkpoint` examples to the grouped `mvmctl vm checkpoint` /
      `mvmctl vm snapshot` surface.
- [x] structured-stdout hardening — entry convergence and dev-VM hints now run
      after the dispatcher has routed `[mvm]` chrome to stderr for
      structured-stdout commands (`ls --json`, `dev * --json`, `run --json`,
      `up --up-json`, and grouped Vz save/restore/snapshot JSON). Regression:
      `mvmctl ls --all --json` can no longer print the non-interactive
      `dev shell` hint on stdout before the JSON array.
- [x] Vz `dev shell` data-channel reachability — the persistent Vz dev VM now
      exposes a bounded console data-port range (`20001..20128`) in addition
      to the guest-agent port, matching `ConsoleOpen`'s
      `CONSOLE_PORT_BASE + session_id` contract. The Vz `dev shell` path keeps
      the actual attach error context instead of rewriting every console
      failure as "owned by another process."
- [ ] linux-native richer `--json` — today it collapses to a single `state`
      (`ready`/`not-ready`/`no-kvm`); surface the kvm/firecracker/assets detail
      as a typed shape if a Linux consumer needs it.
- [ ] acceptance: every vz lifecycle verb has a documented `--json` form with
      a stable schema + test. Checkpoint/snapshot JSON and docs are covered;
      linux-native richer detail remains open.

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

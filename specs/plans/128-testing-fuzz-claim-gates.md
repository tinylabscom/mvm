# Plan 128 — Testing pyramid + fuzz parity + build the missing claim gates

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "all 14 claims stay CI-gated" *true* — it isn't today. Rebuild the testing pyramid (fast-default host/mock tier + gated-slow live-KVM/E2E tier, drop none), re-home the fuzz targets after the crate moves, **build the gates that are missing or broken** (claim 4's script, the claim 12/13 gate, plus the new gates 124/126/127/130 defer here), and re-verify the §8 claim→gate map end to end.

**Architecture:** This is the plan that wires every deferred CI gate. ADR-066 §8 (verified 2026-05-31) found the hard truth: claim 4's `scripts/check-prod-agent-no-exec.sh` is **missing/untracked** yet called by `security.yml`+`Justfile` (latent — `security.yml` runs on release tags only, so PR CI looks green); claims 12 & 13 have **no gate at all** (the cited tests + the three `check-handler-*` lints + `fuzz_service_call` don't exist); claims 8/9/10 ride the generic `ci.yml::test` with no dedicated job. The testing tiers use `MockBackend`/`ExampleBackend` (ADR-045) for the hermetic fast path and `MVM_E2E_SMOKE`-gated live lanes for the slow path.

**Tech Stack:** `cargo nextest`, `cargo-fuzz`, the `xtask` lints, `.github/workflows/{ci,security}.yml`, the `MockBackend`. No new third-party crates.

**Prereqs:** all of 120–127 + 129/130 (this plan gates their behavior). Run it **last** in Stage D — it's the verification that the rewrite preserved every claim.

**Numbering note:** ADR-066 §8 says "the testing-pyramid plan (127)" in two spots — stale (127 is metering; **128** is this plan). Fix those refs in the same commit.

---

## Phase A — the testing pyramid (two tiers, drop none)

### Task A1: fast-default tier (host unit + hermetic `MockBackend`)

- [ ] **Step 1:** Audit the workspace tests; confirm the default `cargo nextest run --workspace` is **hermetic** — no VM boot, no network, no host Nix. Anything that needs a real backend uses `MockBackend`/`ExampleBackend` (ADR-045).
- [ ] **Step 2:** Move any accidentally-live default test behind the gate (Task A2) or onto `MockBackend`. The fast tier must be green on a laptop with no libkrun. Commit.

### Task A2: gated-slow tier (live-KVM + E2E)

- [ ] **Step 1:** Standardize the gate: `MVM_E2E_SMOKE=1` for libkrun/macOS lanes (120's `core_demo_e2e`, 123's warm-start, 127's `bench`), and a Linux/KVM lane (the Lima test-backend, ADR-066 §"Lima") for Firecracker E2E. One env convention, documented.
- [ ] **Step 2:** Wire the slow lanes as **manual/opt-in CI jobs** (they need real VMs); the fast tier is the required PR check. Commit.

## Phase B — fuzz parity (re-home + the new targets)

### Task B1: re-home after the crate moves

121 updated the fuzz `working-directory` strings for the moved crates; this confirms coverage didn't drop and the harnesses still build.

- [ ] **Step 1:** Confirm each fuzz target builds + runs a smoke iteration in its new home: `mvm-libkrun/fuzz`→`deps/libkrun-sys`, `mvm-vz/fuzz`→`mvm-backend`, `mvm-firecracker-bridge/fuzz`→`mvm-vm-host`; `mvm-guest`/`mvm-oci` stay. `security.yml` working-dirs match.
- [ ] **Step 2:** The hand-rolled vsock codec (124 A2) replaced `serde_json` — **assert the `GuestRequest`/`AuthenticatedFrame` fuzz targets now exercise the new codec** (claim 5 must keep covering the parser, not a dead serde path). Commit.

## Phase C — build the missing / broken gates

### Task C1: restore claim 4 — `check-prod-agent-no-exec.sh`

- [ ] **Step 1:** Failing state — `security.yml` + `Justfile` call `scripts/check-prod-agent-no-exec.sh` which is **not tracked**. Write it: build the agent without `dev-shell`, assert the `mvm_guest_agent::do_exec` symbol is absent (the W4.3 check). A test fixture with `do_exec` present must trip it.
- [ ] **Step 2:** Track the script; run it on **every PR** (move it off the release-tag-only lane so the gate isn't latent). Commit.

### Task C2: build the claim 12/13 gate (against 129's reality)

The §8 note said "build against the `host.audit.v1` reality (the dropped `host.secrets.v1`)" — but **129 re-established secrets** via host-side egress substitution. So the gate asserts **129's** invariants, not the old broker handler.

- [ ] **Step 1:** Failing tests — (claim 12) a broker/service call is denied unless bound to a signed `ExecutionPlan.services` binding; (claim 13 / 129) no raw secret value reaches the guest, substitution fires only for bound destinations, and **the audit chain carries no secret bytes**. These are 129's leak-gate tests; this plan wires them as a dedicated CI job.
- [ ] **Step 2:** Implement the `xtask`/test gate + the `ci.yml` job. If the three `check-handler-*` lints (cited in CLAUDE.md but absent) are still wanted, build them here against the real handler registry; otherwise drop the CLAUDE.md over-claim. Commit.

### Task C3: wire the gates the other plans deferred here

- [x] **Step 1:** `check-guest-agent-in-all-images` (124 B2) → `ci.yml` (live in the Lint job).
- [x] **Step 2:** the SDK **no-drift** check (124 D1) → `ci.yml`. Wired as `cargo run -p xtask -- check-stubs` in the Lint job of both `ci.yml` + `ci-full.yml` (the command is `check-stubs`, not the old `gen-sdk` name; it now covers both the workload-IR and host↔guest-protocol *type* stubs after 124 D1.2a). The Lint job gained `astral-sh/setup-uv` + `actions/setup-node` so `uvx`/`npx` are available. Cross-platform determinism verified before landing: `check-stubs` is byte-clean on Linux (node18/py3.11) against the macOS-committed stubs (node22/py3.12) — the pinned generator versions, not the host toolchain, fix the output. The *method-surface* no-drift (124 D1.2 Step 2's `gen-sdk`) folds into the same gate once that generator lands.
- [x] **Step 3:** `check-forbidden-deps` extended for the pruned deps (126 D1) → `ci.yml` (live in the Lint job).
- [ ] **Step 4:** the `xtask budget` job (127 C1) → `ci.yml` as **informational** (warns, never fails — ADR-066 §7).
- [ ] **Step 5:** the docs-drift gate (130) → `ci.yml`. Commit each as it lands.

### Task C4: config fail-closed — `deny_unknown_fields` on file-loaded config types (folds in plan 121's hardening follow-up)

Surfaced during plan 121's B4 config-envelope descope: 5 types are deserialized from on-disk files **without** `#[serde(deny_unknown_fields)]`, so a typo'd key is silently dropped instead of failing loud — `MvmConfig` (`~/.mvm/config.toml`), `Manifest` (`mvm.toml`), `ArtifactManifest` (`manifest.json`), `VmNameRegistry` + nested `VmRegistration` (`vm-names.json`). (Claim 5 / W4.1 enforces this on host↔guest *wire* types; these are local config/manifest files — the same fail-closed principle, one tier in.)

- [ ] **Step 1:** Per-type judgement, **not** a blanket sweep — `MvmConfig::load` is deliberately fail-*open* (returns defaults on any error), so adding `deny_unknown_fields` there would make a typo silently fall to defaults (arguably worse). Decide per type whether to tighten the *type* or harden the *loader* (warn-on-unknown-key + forward-compat check); apply the attribute where it's the right call.
- [ ] **Step 2:** Lock it — an `xtask check-config-deny-unknown-fields` (or focused test) asserting the agreed file-loaded config set carries the attribute; dropping it from one trips the gate. Wire into `ci.yml`. Commit.

## Phase D — re-verify the §8 claim→gate map

### Task D1: all 14 claims, each with a live gate

- [ ] **Step 1:** Walk the ADR-066 §8 table row by row; for each claim, point to the **passing** gate (job + assertion). Fix the stale "127"→"128" refs. The previously-aspirational rows (4, 12, 13) now point to C1/C2.
- [ ] **Step 2:** Add `xtask check-doc-claims` coverage so a claim without a live gate **fails the build** (no more "looks green because the lane is release-only"). Update the security-model section of `CLAUDE.md` to the verified reality. Commit.

## Acceptance

- [ ] Fast-default `cargo nextest run --workspace` is hermetic + green with no libkrun; slow lanes are `MVM_E2E_SMOKE`/KVM-gated, opt-in.
- [ ] Every fuzz target builds + smokes in its post-121 home; the vsock fuzz targets exercise the new hand-rolled codec.
- [ ] `check-prod-agent-no-exec.sh` exists, is tracked, runs on every PR (claim 4 un-latented); the claim 12/13 gate exists and asserts 129's invariants.
- [ ] `check-guest-agent-in-all-images`, the SDK no-drift check, the extended `check-forbidden-deps`, the budget job, and the docs-drift gate are all wired into `ci.yml`.
- [ ] Every row of the §8 claim→gate map points to a passing gate; `check-doc-claims` fails on a gateless claim; the stale "127" refs fixed; `CLAUDE.md` security section matches reality.
- [ ] `cargo test --workspace` + clippy + fmt green; no new dependency.

### deferred follow-ups

- [ ] Reproducibility double-build (W5.3) parity if it regressed during the moves.
- [ ] Upstream fuzz coverage notes for the C/Go gateway parsers (libkrun/passt/gvproxy) — tracked in ADR-055, not built here.

## Self-review

- **Spec coverage (brief 128):** two-tier pyramid (Phase A), fuzz re-homing (Phase B), restore claim 4 + build claims 12/13 (Phase C1/C2), wire the deferred gates (C3), re-verify the §8 map (Phase D). All present.
- **Honesty:** this plan's premise is the §8 finding that the "14 claims gated" statement is currently false; it makes it true and adds `check-doc-claims` so it can't silently lapse again. Claim 12/13 gates target 129's real design, not the dropped broker handler.
- **Sequencing:** runs last in Stage D — it verifies the others; it does not invent behavior, it gates behavior they built.
- **Voice:** comments mark the non-obvious (why the slow tier is opt-in, why the claim-4 lane must move off release-tag-only, why the fuzz target must follow the codec), not the mechanics.

# Plan 156 — Binary size reduction

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Shrink the shipped `mvmctl` binary — the artifact users download — and lock a size budget so it stays small. This is the size counterpart to 126's dependency-*count* cut: 126 removes whole crates from the closure (the primary size driver), 156 measures the resulting binary, tunes the release profile for size, trims features inside the crates that stay, and gates regressions. Every step records a measured size delta (`ls -l` / `cargo bloat`) — no asserted numbers.

**Architecture:** Measure, tune, trim, gate — mirrors 126's discipline. The headline target is `mvmctl` (it embeds the cross-compiled musl host-vm binaries `mvm-host-vm-init` + `mvm-egress-proxy` as baked-in data, so their weight already counts toward it). The per-VM subprocess binaries (`mvm-libkrun-supervisor`, `mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`, `mvm-vz-drainer`, `mvm-firecracker-bridge`) get a measured baseline row but do not drive profile decisions.

**Tech Stack:** `cargo bloat` (installed), `ls -l` / `size`, the root `[profile.release]` table, a new `xtask check-binary-size` gate (sibling to `check-forbidden-deps`).

**Prereqs:** None hard, but **126 is the primary size driver** — sequence 156 to re-measure after each 126 task (B1–B4, C1) lands. Coordinates with 127 (the dashboard reads `binary-size-baseline.md` alongside `dep-baseline.md`) and 128 (CI gate wiring).

**Grounded findings (measured 2026-06-03):**
- Root `[profile.release]` is **already size-conscious except `opt-level`**: `lto = true` (fat LTO), `codegen-units = 1`, `strip = true` (== `strip = "symbols"`) are all maxed. The one remaining profile lever is `opt-level = 3` → `"s"`/`"z"`.
- **`panic = "abort"` is off the table for the shared profile.** `crates/mvm-supervisor/src/gateway_bridge.rs` isolates panicking audit observers via `catch_unwind` so siblings continue and chain-signing isn't disrupted (Plan 113 / ADR-064); `mvm-libkrun-supervisor` + `mvm-vz-drainer` mains rely on the bridge's `catch_unwind → exit(1)` fail-closed path. Cargo's `panic` setting is profile-wide (unlike `opt-level`, it has no per-package override), and those subprocess binaries share the workspace `[profile.release]`. A blanket `panic=abort` would break a security-isolation mechanism — record the investigation, do not flip it.
- The embedded musl binaries build via `cargo zigbuild --release` (`crates/mvm-cli/build.rs`), so they **inherit** any change to the root `[profile.release]` for free; they show up as baked data inside `mvmctl`, not in `cargo bloat`'s crate table — measure them via their own musl release artifacts.

---

## Phase A — baseline + method

### Task A1: one measurement method, written down

- [ ] **Step 1:** Define the canonical commands. File size = `ls -l target/release/mvmctl` (bytes, the headline) + `size target/release/mvmctl` (section breakdown). Crate attribution = `cargo bloat --release --bin mvmctl --crates`; function-level = `cargo bloat --release --bin mvmctl -n 50`. Embedded musl pair = `ls -l target/aarch64-unknown-linux-musl/release/{mvm-host-vm-init,mvm-egress-proxy}` (they are baked into `mvmctl` as data; `cargo bloat` won't attribute them). Build with the *current* profile (`opt-level=3`, `lto=true`, `codegen-units=1`, `strip=true`) and record that the baseline is taken under it.
- [ ] **Step 2:** Add a baseline row per secondary binary: `cargo bloat --release --bin <name> --crates` for `mvm-libkrun-supervisor`, `mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`, `mvm-vz-drainer`, `mvm-firecracker-bridge`.
- [ ] **Step 3:** Commit `docs/investigations/binary-size-baseline.md` with the method + the numbers (sibling to 126's `dep-baseline.md`; 127's dashboard reads both). Every later task appends its delta.

## Phase B — release-profile tuning (evidence-driven)

### Task B1: `opt-level` size sweep

The only un-maxed profile lever.

- [ ] **Step 1:** Measure `mvmctl` file size under `opt-level = "s"` and `opt-level = "z"` (one at a time, root `[profile.release]`), each against the A1 baseline. For each, also record a `cargo test --workspace` pass + wall-clock delta — `mvmctl` is an orchestration CLI so a runtime regression is acceptable, but record it rather than assume it.
- [ ] **Step 2:** Pick the winner from the data and set it in `[profile.release]`. Note the embedded musl pair shrinks too (inherits the profile) — re-measure both. Append the delta. Commit.

### Task B2: record the `panic = "abort"` investigation

- [ ] **Step 1:** Document the rejection in `binary-size-baseline.md`: cite `crates/mvm-supervisor/src/gateway_bridge.rs` observer isolation + the supervisor/drainer `catch_unwind → exit(1)` fail-closed path (Plan 113 / ADR-064), and the profile-wide-`panic` constraint. No code change — this task is the recorded evidence that the lever was considered and consciously declined, so a later contributor doesn't re-litigate it.
- [ ] **Step 2:** Confirm `lto = true`, `codegen-units = 1`, `strip = true` are already size-optimal in the baseline doc (so they're not mistaken for un-pulled levers). Commit.

## Phase C — feature & monomorphization trim

Driven by `cargo bloat --crates` — coordinates with 126 (126 removes whole deps; 156 trims features *inside* the deps that stay, so the wins aren't double-counted).

### Task C1: workspace `tokio` feature union

- [ ] **Step 1:** The workspace `tokio` carries the full set (`fs, io-util, macros, net, process, rt, rt-multi-thread, signal, sync, time`). Enumerate which features are actually reached across the workspace (grep the tokio surface used per crate) and narrow the workspace declaration to that union. Failing test — `cargo build --workspace` + `cargo test --workspace` stay green with the narrowed set. Re-measure `mvmctl`. Commit the delta.

### Task C2: `regex` / `clap` / serde-stack feature audit

- [ ] **Step 1:** From the A1 `cargo bloat --crates` output, take the top non-126 contributors (likely `regex`, `clap`, the serde/hyper stack). For each, check whether a lighter feature set or `default-features = false` covers the actual use (e.g. `regex` without Unicode tables if the patterns are ASCII; `clap` already on `derive` only). Failing test — the affected command/parse paths still pass. Re-measure. Commit each non-zero delta.

## Phase D — size budget + CI gate

### Task D1: the size gate

- [ ] **Step 1:** After A–C, record the final `mvmctl` size and set a budget = that size + a small headroom (e.g. +5%), written in `binary-size-baseline.md`. Add `xtask check-binary-size`: build `mvmctl` in release, `ls -l` the artifact, fail if it exceeds the committed budget. Failing test — bumping the budget down below current size trips the gate.
- [ ] **Step 2:** Wire the gate into `ci.yml` (with 128), sibling to `check-forbidden-deps`. The headline reduction in `binary-size-baseline.md` is `(B1 + C1 + C2)` on top of 126's whole-crate cuts. Commit.

## Acceptance

- [ ] `binary-size-baseline.md` records the method + the baseline + each task's delta (measured, never asserted), and a per-binary row for the secondary subprocess binaries.
- [ ] `[profile.release]` `opt-level` set from the B1 data; `lto`/`codegen-units`/`strip` confirmed already-maxed; the `panic=abort` rejection recorded with the `catch_unwind` evidence.
- [ ] `tokio` narrowed to its used feature union; `regex`/`clap`/serde-stack feature audit applied where it pays.
- [ ] `check-binary-size` trips if `mvmctl` exceeds the budget; wired into CI.
- [ ] `cargo test --workspace` + clippy + fmt green; the embedded musl pair re-measured under the new profile.

### deferred follow-ups

- [ ] Per-VM subprocess binaries (the secondary set) get their own size budgets in a follow-up if their baseline rows show drift worth gating — out of scope here (headline is `mvmctl`).
- [ ] If 126's `sigstore` relocation lands, the single largest `mvmctl` size drop comes for free — note it in `binary-size-baseline.md` as a 126-attributed delta, not a 156 one.

## Self-review

- **Spec coverage:** baseline+method (A), profile tuning (B1) + the recorded `panic=abort` rejection (B2), feature trim (C1/C2), size budget gate (D1).
- **Honesty:** every reduction is measured (`ls -l` / `cargo bloat` delta in `binary-size-baseline.md`), never asserted. The profile is *already* size-optimal except `opt-level` — stated so we don't claim credit for levers already pulled (`lto`/`codegen-units`/`strip`).
- **Division of labor:** 126 removes whole deps (the primary size driver); 156 measures the binary, tunes the profile, and trims features inside kept deps. The `sigstore` win is attributed to 126, not 156, so it isn't double-counted.
- **Safety:** `panic=abort` is investigated-and-rejected, not silently skipped — the `gateway_bridge.rs` observer isolation (ADR-064) is a security mechanism that depends on unwinding, and the supervisor binaries share the workspace profile.
- **Voice:** notes mark the non-obvious (why panic=abort is rejected, why the embedded musl pair inherits the profile for free, why lto/strip are already maxed), not the mechanics.

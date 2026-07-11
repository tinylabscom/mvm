# Install-time Dev-Image Prefetch (SP2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the first `mvmctl dev up` after install instant by prefetching the dev-shell image during `mvmctl bootstrap` (which `install.sh` already runs), closing the gap where `bootstrap` warms the builder VM but not the dev image.

**Architecture:** SP2 of Plan 213 ("instant first-use"). The design note called this a `prepare` phase, but `mvmctl prepare` already exists as read-only diagnosis — so instead of a new imperative verb, we extend the existing action-oriented `bootstrap` (its module doc already says it "pre-acquires the builder VM image so the first `mvmctl dev up` is fast"). We add a second prefetch step for the dev-shell image, reusing `ensure_dev_image()`. Warm-snapshot capture and seeded-closure import (SP3) are left as clean seams, not built. Design: `specs/notes/instant-first-use-pack-design.md`.

**Tech Stack:** Rust (edition 2024), `mvm-cli`; POSIX `sh` (`install.sh`).

## Global Constraints

- Edition 2024; no `#[allow(clippy::too_many_arguments)]`; no spec/plan/PR/ADR refs in code comments; no `Co-Authored-By` trailer.
- Prefetch steps must be **non-fatal** (a failure warns and defers to first `dev up`, matching the existing builder-image prefetch posture) and **idempotent** (cache/fingerprint-gated).
- Do NOT add a new `prepare` verb or change the read-only contract of the existing `mvmctl prepare` (`vm/prepare.rs`).
- Leave the warm-snapshot seam (`env/bootstrap.rs`, right after the builder image is ready) and the seed-closure seam (builder-pack materialization) untouched and open.
- Verification gate: `cargo fmt --all -- --check`, `cargo clippy -p mvm-cli --all-targets -- -D warnings`, `cargo nextest run -p mvm-cli`, and `sh -n install.sh`.
- Work in worktree `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-sp2-prepare` (branch `feat/plan-213-sp2-prepare`, stacked on SP1). If SP1 (#1631) merges to main first, rebase this branch onto main before opening the PR.

## File Structure

- `crates/mvm-cli/src/commands/env/bootstrap.rs` — **modify** `bootstrap_environment()` to add a dev-image prefetch step + an opt-out helper.
- `crates/mvm-cli/src/commands/vm/prepare.rs` — **modify**: refresh the now-stale doc comment (the content-addressed pack cache SP1 shipped exists now).
- `install.sh` — **modify**: remove the dead `mvm-vz-supervisor` hostbin entry; refresh the prefetch messaging.

---

## Task 1: Prefetch the dev-shell image in `bootstrap_environment`

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/bootstrap.rs`
- Test: inline `#[cfg(test)]` in that file

**Interfaces:**
- Consumes: `super::dev_vz::image_ops::ensure_dev_image() -> Result<(String, String)>` (already `pub(in crate::commands)`; returns the resolved `(vmlinux, rootfs)` paths, cache-gated — a fast no-op when present, a download on a release install, a Layer-2 Nix build on a source checkout).
- Produces: a pure helper `dev_image_prefetch_enabled(skip_env: Option<&str>) -> bool`.

- [ ] **Step 1: Write the failing test** — in `bootstrap.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::dev_image_prefetch_enabled;

    #[test]
    fn dev_image_prefetch_on_by_default_off_with_flag() {
        assert!(dev_image_prefetch_enabled(None));
        assert!(dev_image_prefetch_enabled(Some("0")));
        assert!(!dev_image_prefetch_enabled(Some("1")));
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-cli --lib dev_image_prefetch 2>&1 | tail -5` → `dev_image_prefetch_enabled` not defined.

- [ ] **Step 3: Implement.** Add the pure helper and wire the prefetch into `bootstrap_environment` after `bootstrap_builder_vm_image()?`:

```rust
/// Whether to prefetch the dev-shell image during bootstrap. On by default so
/// the first `dev up` is instant; opt out with `MVM_SKIP_DEV_IMAGE_PREFETCH=1`
/// (bandwidth-limited or headless installs).
fn dev_image_prefetch_enabled(skip_env: Option<&str>) -> bool {
    !matches!(skip_env, Some("1"))
}
```

In `bootstrap_environment`, after the builder-image line, before the final `ui::success`:

```rust
    // Also pre-acquire the dev-shell image so the first `mvmctl dev up` doesn't
    // pay a download/build on the hot path. Non-fatal + cache-gated, mirroring
    // the builder-image prefetch above.
    if dev_image_prefetch_enabled(std::env::var("MVM_SKIP_DEV_IMAGE_PREFETCH").ok().as_deref()) {
        match super::dev_vz::image_ops::ensure_dev_image() {
            Ok(_) => ui::success("Dev image ready."),
            Err(e) => ui::warn(&format!(
                "dev-image prefetch failed ({e}); the first 'dev up' will fetch it. Skip with MVM_SKIP_DEV_IMAGE_PREFETCH=1."
            )),
        }
    }
```

Confirm the exact path/visibility of `ensure_dev_image` first with `rg -n 'fn ensure_dev_image' crates/mvm-cli/src`; adapt the module path (`super::dev_vz::image_ops::ensure_dev_image` vs another) and the `ui::warn`/`ui::success` helper names to what exists. If `ensure_dev_image` needs setup context not available here (e.g. it assumes a running dispatcher), STOP and report rather than forcing it.

- [ ] **Step 4: Run to verify it passes** — `cargo test -p mvm-cli --lib dev_image_prefetch 2>&1 | tail -5` → PASS; `cargo build -p mvm-cli` clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-sp2-prepare
git add crates/mvm-cli/src/commands/env/bootstrap.rs
git commit -m "feat(bootstrap): prefetch the dev-shell image so first dev up is instant"
```

---

## Task 2: install.sh — drop the dead vz hostbin + refresh messaging

**Files:**
- Modify: `install.sh`

- [ ] **Step 1: Remove the dead `mvm-vz-supervisor` entry** from the hostbin loop (`install.sh:143`): the `for hostbin in mvm-bridge mvm-vz-supervisor mvm-hvf-supervisor mvm-libkrun-supervisor mvm-substitution-endpoint; do` line drops `mvm-vz-supervisor` (that bin was deleted; the `[ -f ]` guard makes it a silent no-op today, but it should go).

- [ ] **Step 2: Refresh the prefetch messaging** so it reflects that `bootstrap` now warms the dev image too. Update the two user-facing strings in the `MVM_SKIP_BUILDER_PREFETCH` block (`install.sh:180`, `:187`) from "builder VM image" to "builder VM + dev images" (keep them terse; the `MVM_SKIP_BUILDER_PREFETCH` knob still gates the whole `mvmctl bootstrap` call, and `MVM_SKIP_DEV_IMAGE_PREFETCH` is the finer knob documented in `mvmctl bootstrap`'s own output).

- [ ] **Step 3: Verify** — `sh -n install.sh` (parses clean); `rg -n 'mvm-vz-supervisor' install.sh` returns nothing.

- [ ] **Step 4: Commit**

```bash
git add install.sh
git commit -m "chore(install): drop dead mvm-vz-supervisor; note dev-image prefetch"
```

---

## Task 3: Refresh the stale `vm/prepare.rs` doc

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/prepare.rs`

- [ ] **Step 1: Update the module doc** (`prepare.rs:1-9`). The clause "needs the content-addressed pack download cache and a builder-side prepare path, neither of which exists yet" is now stale — SP1 shipped the content-addressed pack download cache (`mvm_core::pack_cache` + `mvmctl pack download`). Reword to reflect current reality: this command remains read-only diagnosis of the host default runtime-pack readiness; the acquisition path now lives in `mvmctl pack download`/`update` and the install-time `mvmctl bootstrap` prefetch. Do NOT change behavior — doc only. Keep the read-only contract intact (the `no side effects` test at `prepare.rs`'s test module still holds).

- [ ] **Step 2: Verify** — `cargo build -p mvm-cli` clean; `cargo test -p mvm-cli --lib prepare 2>&1 | tail -5` still passes (behavior unchanged).

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/prepare.rs
git commit -m "docs(prepare): refresh stale note; pack acquisition path now exists"
```

---

## Self-Review

- **Spec coverage:** dev-image prefetch in bootstrap (the real gap) → Task 1; opt-out + non-fatal + idempotent → Task 1; install.sh dead-vz + messaging → Task 2; stale-doc fix → Task 3; warm-snapshot/seed-closure seams left open → no task touches them (explicit constraint). No new `prepare` verb (constraint honored).
- **Type consistency:** `dev_image_prefetch_enabled` and `ensure_dev_image` names used consistently; the implementer confirms `ensure_dev_image`'s real module path before wiring.
- **No placeholders:** every step is concrete; the one judgment call (`ensure_dev_image` callability from bootstrap) has an explicit STOP-and-report escape.

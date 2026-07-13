# Plan 248 — Guest-op fallout on macOS 26+ (Plan 247 W4, tractable set)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Created:** 2026-07-12
**Related:** Plan 247 (`specs/plans/247-runvm-macos-shell-ops.md` §W4).
**Base:** `feat/plan-247-runvm-macos` (stacked on #1669 → #1667).
**Status:** draft

**Goal:** finish the macOS 26+ `run_in_vm` fallout for the "genuine guest op" set —
fix the common `--add-dir` case in-process with the pure-Rust ext4 writer, fix a
stale-duplicate `resolve_running_vm`, delete dead `template_init`, and replace the
remaining hard-fails with clear platform-gates. The one op that genuinely needs a
Linux builder — `build validate` (`nix flake check`) — is deferred: its typed-daemon
substrate is libkrun-only + persistent-only and HVF (the macOS 26+ default) was never
wired into it, which is its own plan.

**Naming (corrected from the W4 sketch):** the flag is `--add-dir HOST:GUEST[:ro|rw]`
(not `--mount`); the orchestration call sites are in `crates/mvm-cli/src/exec.rs`
(not `commands/vm/exec.rs`).

## Global Constraints
- `cargo fmt --all -- --check` (nightly) clean; `cargo nextest run -p <crate>` green; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- No plan/PR/ADR/issue refs in CODE comments. No `#[allow(clippy::too_many_arguments)]`. Reuse existing helpers. No AI-attribution in commits.
- `mvm-backend` test bin is SIGKILL'd by codesign locally — build-check, don't nextest it.
- All work in the `plan-248-w4` worktree.

---

### Task 1: `--add-dir` create → pure-Rust ext4 (the high-value fix)

`crates/mvm-backend/src/image.rs::build_dir_image_ro` (~line 760) builds an ext4 from
a host dir via `run_in_vm("mkfs.ext4 …" + mount + copy + unmount)` — hard-fails on
macOS 26+. `mvm-backend` already depends on `mvm-build` with `features =
["builder-vm","pure-mkfs"]`, so `mvm_build::rootfs::materialize_ext4_pure` is reachable
with no new Cargo wiring. The only gap: the guest mounts the volume by LABEL
(`mount LABEL={label}`, `crates/mvm-cli/src/exec.rs:706`), and the pure writer's current
call chain uses the label-less `mvm_ext4::emit_image`; but `mvm_ext4::BuildOptions::with_volume_name`
+ `emit_image_with_options` (`crates/mvm-ext4/src/lib.rs:212-226`) already exist.

**Files:** `crates/mvm-backend/src/image.rs` (`build_dir_image_ro`), and whichever
`materialize_ext4_pure`/`rootfs.rs` seam is needed to pass a volume label through.

- [ ] **Step 1:** Read `build_dir_image_ro` end-to-end (what host dir → what ext4 path → what label the guest expects) and `materialize_ext4_pure` / `emit_image_with_options`.
- [ ] **Step 2: Failing test** — a tempdir tree → `build_dir_image_ro` produces an ext4 file whose superblock volume label matches the expected `{label}`, WITHOUT any `run_in_vm`. Read the label back with the existing `mvm-ext4` reader-of-superblock, or assert the writer was called with the label (whichever is testable). RED first.
- [ ] **Step 3:** Reimplement `build_dir_image_ro` to walk the host dir and call `materialize_ext4_pure` (threading the volume label via `BuildOptions::with_volume_name` / `emit_image_with_options`). Remove the `run_in_vm` mkfs/mount/copy/unmount block. Preserve the exact output ext4 path + label the guest mount depends on.
- [ ] **Step 4:** GREEN. `cargo build --workspace --all-targets` + the affected tests.
- [ ] **Step 5:** Commit: `fix(add-dir): build the ext4 volume in-process, not via a VM`.

### Task 2: `resolve_running_vm` → call the already-fixed sibling

`crates/mvm-cli/src/commands/shared/resolve.rs:11 resolve_running_vm` (used only by
`machine forward`, `forward.rs:47`) echoes `config::VMS_DIR` inside a VM and greps
`/proc`. `crates/mvm-backend/src/microvm.rs:197 resolve_running_vm_dir` already fixed
this exact bug (expands `VMS_DIR` via `std::env::var("HOME")`, no VM); every other call
site uses it.

- [ ] **Step 1:** Read both. Confirm `resolve_running_vm_dir` returns what `forward.rs` needs (the running-VM dir / state).
- [ ] **Step 2:** Replace `resolve.rs`'s `resolve_running_vm` body with a call to `microvm::resolve_running_vm_dir` (or delete `resolve.rs`'s version and repoint `forward.rs:47` at the sibling). Keep behavior for `forward`.
- [ ] **Step 3:** `cargo build --workspace --all-targets` + `cargo nextest run -p mvm-cli`. Commit: `fix(forward): resolve the running VM on the host, not through a VM`.

Note (document, don't fix): `forward`'s `socat`-to-guest-IP mechanism needs a routable
guest IP, which HVF (vsock-only) never has, and its `fc.pid` check is Firecracker-only —
a pre-existing gap unrelated to the dev-VM removal. This task only removes the
`run_in_vm` crash in resolution; full `forward`-on-macOS is out of scope.

### Task 3: Delete dead `template_init` / `vm_exec`

`git grep -n template_init crates/` → one hit (its own definition); `mvmctl` has no
`template` verb. `vm_exec` (`lifecycle.rs:171`) is called only by `template_init`
(`:249`). Both dead.

- [ ] **Step 1:** Confirm zero live callers (grep). Delete both functions + any now-dead imports.
- [ ] **Step 2:** `cargo build --workspace --all-targets` + `cargo clippy --workspace --all-targets -- -D warnings` clean. Commit: `refactor(template): delete dead template_init/vm_exec (no template verb)`.

### Task 4: Clear platform-gates for the deferred guest ops

Replace the raw `run_in_vm` hard-crash with an honest, actionable error on the tiers
where these can't run yet (macOS 26+ HVF, which has no builder-exec path):

- `crates/mvm-backend/src/image.rs::rsync_image_to_host` (`--add-dir :rw` write-back — needs an ext4 *reader*, which doesn't exist).
- `crates/mvm/src/vm/template/lifecycle.rs::update_fod_hash` (`--update-hash` — a real TOFU `nix build`).
- `crates/mvm-cli/src/commands/build/validate.rs` (`nix flake check` — the deferred typed-builder case).

- [ ] **Step 1:** For each, before it would call `run_in_vm`, detect the no-builder-exec tier and return an `Err` whose message names the limitation + the workaround (run on Linux / in CI, or start a persistent libkrun builder), as a plain concept (no spec-refs). A tiny shared helper `fn require_guest_exec_available() -> Result<()>` is fine. Prefer reusing an existing platform/backend predicate — grep first (e.g. the tier check `is_vz_default_tier` used elsewhere).
- [ ] **Step 2:** Tests: each gated path returns the clear `Err` on the HVF tier (or asserts the helper's decision). Leave `lifecycle.rs`'s flake.lock `nix hash` line alone (already `.unwrap_or_default()` soft-fail — add a one-line code comment that it degrades to the revision hash off-Linux).
- [ ] **Step 3:** Workspace gate. Commit: `fix(guest-ops): gate builder-only ops with a clear error instead of a VM crash`.

### Task 5: Gate + status

- [ ] Full gate (`fmt --all` nightly, `nextest --workspace -E 'not package(mvm-backend)'`, `clippy --workspace --all-targets -D warnings`, `cargo build -p mvm-backend --all-targets`). Update `specs/REFACTOR-STATUS.md`. Commit.

---

# Deferred (own plan): `validate`/`update_fod_hash` real substrate

Make genuine guest ops work on macOS 26+ by giving the builder VM an on-demand
boot-run-teardown typed-exec path and wiring HVF into the persistent/typed-daemon mode
(today: libkrun-only, persistent-only, hidden verb; discovery still carries dead Vz-shape
code). This is the real "typed-RPC to headless builder" substrate — sized as its own plan.

# Self-review notes
- The common `--add-dir` case (T1) and both cleanups (T2, T3) make macOS 26+ correct for what's tractable in-process; T4 converts the rest from confusing crashes to honest gates.
- T1 risk: the guest mounts by LABEL — the pure-Rust ext4 MUST carry the same volume label, or `mount LABEL=…` fails in-guest. The failing test must assert the label.

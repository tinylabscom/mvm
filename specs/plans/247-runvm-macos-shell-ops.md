# Plan 247 — Retire the dev-VM dependency from host-side shell ops (macOS 26+)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development
> to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Created:** 2026-07-12
**Related:** Plan 246 Phase 2 (`mvmctl dev` removal — `specs/notes/2026-07-11-plan-246-phase2-dev-removal.md`),
which stubbed `DevVmEnv::start_dev_daemon`; this plan resolves the fallout.
**Base:** `feat/plan-246-phase2` (stacked on the dev-removal PR #1667).
**Status:** draft

**Goal:** make the common macOS 26+ commands (`mvmctl bootstrap`, `machine run --flake`,
`machine build`) work again by removing their dependence on a dev VM for host-side
shell ops — host-path ops become `std::fs`, `bootstrap` stops doing Linux-only work
on macOS, and the large body of dead `run_in_vm` code is deleted. Genuine guest ops
(`validate`, `--mount`) are deferred to a typed-builder path (W4, separate plan).

**Architecture:** `shell::run_in_vm*` resolves `default_env()`: on Linux and macOS
13–25 it is `NativeEnv` (runs `bash -c` locally, no VM — already fine); only on
**macOS 26+** is it `DevVmEnv`, which dialed the `mvm-dev` VM and now hard-fails
(auto-boot stubbed). Of ~190 call sites: ~91 are Firecracker/network ops never
reachable on macOS, ~44 are dead code, and the live macOS breakage is a narrow set
of host-path ops wrongly shelled through a VM plus `bootstrap`'s un-gated Firecracker
provisioning.

**Tech Stack:** Rust (`mvm`, `mvm-build`, `mvm-cli`, `mvm-backend`), `std::fs`.

## Global Constraints
- `cargo fmt --all -- --check` (nightly rustfmt) clean; `cargo nextest run -p <crate>` green; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- No plan/PR/ADR/issue refs in CODE comments (`Plan N`/`ADR-<n>`/`#<n>`/`W<n>.` CI-banned).
- No `#[allow(clippy::too_many_arguments)]`. Reuse `mvm-core::config`/`mvm-core::template` path helpers; never inline `$HOME/.mvm`.
- Commits carry no `Co-Authored-By: Claude` / AI-attribution.
- All work in the `plan-247-runvm` worktree.
- `mvm-backend` test bin is SIGKILL'd by macOS codesign locally — build-check it, don't `nextest` it.

---

# Phase 1 — PR: fix macOS 26+ common commands (W1 + W2 + W3)

### Task 1 (W1): Delete the dead `run_in_vm` code

The dev-removal audit found ~44 `run_in_vm` sites in orphaned code — orphaned by an
earlier orchestration-removal, unrelated to Plan 246. **Verify then delete.** The
build/clippy gate is the safety net (a not-compiled file can't break the build;
a zero-caller compiled file surfaces any real use as a compile error).

**Files (verify each before deleting):**
- Not in the module tree (dead source — `crates/mvm/src/security/mod.rs` declares only `audit, jailer, metadata, seccomp, signing`): `crates/mvm/src/security/{certs,encryption,snapshot_crypto,attestation}.rs`.
- Not compiled (`mod worker` / `mod sleep` don't exist): `crates/mvm/src/worker/hooks.rs`, `crates/mvm/src/sleep/metrics.rs` (delete the whole orphaned dirs if nothing else lives in them).
- Compiled, zero callers (grep the workspace): `crates/mvm/src/security/{audit,metadata,signing}.rs` (superseded by the signed-`ExecutionPlan`/chain-audit system), `crates/mvm-cli/src/security_cmd.rs` (no `Commands::Security` variant — folded into `doctor`), `crates/mvm-cli/src/dev_cluster.rs` (not declared in `lib.rs`).
- Zero-caller function: `crates/mvm-cli/src/shell_init.rs::ensure_shell_init_in_vm` (the live `shell-init` command only calls `print_shell_init`).

- [ ] **Step 1:** For each target, `git grep -n <symbol/mod>` to confirm it is either not declared as a module or has zero non-test callers. Record the evidence.
- [ ] **Step 2:** Delete the dead files/functions + any now-dangling `mod`/`use` lines.
- [ ] **Step 3:** `cargo build --workspace --all-targets` + `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **Step 4:** `git grep -c run_in_vm crates/` — confirm the count dropped by ~44. Commit: `refactor: delete orphaned dev-VM shell-op code (dead since orchestration removal)`.

### Task 2 (W2a): `template_build_from_manifest` artifact copy → `std::fs`

**The fix for `machine run --flake` / `machine build` on macOS 26+.** In
`crates/mvm/src/vm/template/lifecycle.rs`, `template_build_from_manifest` (~lines
770–892) copies the finished build's artifacts into the template slot via
`run_in_vm("mkdir -p …" / "cp -a …" / "ln -snf …" / "cat > … <<'EOF'")`. Both source
(`result.rootfs_path` etc. from `dev_build()`) and destination (`rev_dst` from
`mvm_core::template::template_revision_dir`) are **host paths** — this is a host→host
copy wrongly shelled through a VM.

**Interfaces:** unchanged signature; the block becomes `std::fs` calls.

- [ ] **Step 1: Write a failing test** for the extracted copy helper — e.g. `fn install_revision_artifacts(build: &BuildResult, rev_dst: &Path) -> Result<()>`:

```rust
#[test]
fn install_revision_artifacts_copies_kernel_rootfs_and_metadata_without_a_vm() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("build"); std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("vmlinux"), b"K").unwrap();
    std::fs::write(src.join("rootfs.ext4"), b"R").unwrap();
    let dst = tmp.path().join("rev");
    install_revision_artifacts(&fake_build(&src), &dst).unwrap();
    assert_eq!(std::fs::read(dst.join("vmlinux")).unwrap(), b"K");
    assert_eq!(std::fs::read(dst.join("rootfs.ext4")).unwrap(), b"R");
    assert!(dst.join("current").exists() || std::fs::read_link(tmp.path().join("current")).is_ok());
}
```

- [ ] **Step 2:** Run it — FAIL (helper not defined).
- [ ] **Step 3:** Extract the copy block into the pure helper using `std::fs::create_dir_all`, `std::fs::copy` (or a small recursive copy for dirs), `std::os::unix::fs::symlink`, `std::fs::write` for the metadata heredoc. Replace the `run_in_vm` block with a call to it. Leave line ~847 (`nix hash path {flake}/flake.lock`, `.unwrap_or_default()`, a genuine guest op) as-is — deferred to W4; note that on macOS 26+ it degrades to an empty hash (no crash).
- [ ] **Step 4:** Run the test — PASS. `cargo nextest run -p mvm` for the template module.
- [ ] **Step 5:** Commit: `fix(template): copy build artifacts on the host, not through a VM`.

### Task 3 (W2b): `dev_build.rs` artifact-metadata probes → `std::fs`

In `crates/mvm-build/src/pipeline/dev_build.rs`, `measure_artifact_sizes` (~1164,
`stat -c%s`), `detect_initrd` (~1191, `test -f`), `detect_runner` (~1209, `test -x`)
call `env.shell_exec_stdout(...)` on `build_dir` — a host path the build just wrote.
They are `.ok()`-swallowed, so on macOS 26+ they silently return wrong values
(`initrd_path: None`, zero sizes, no runner), which can steer wrong boot-arg
decisions. Replace with `std::fs`.

- [ ] **Step 1: Failing tests** — sizes from `std::fs::metadata().len()`; initrd detected via `Path::exists`; runner via unix mode `& 0o111`.
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Reimplement the three helpers with `std::fs`/`std::os::unix::fs::PermissionsExt` on `build_dir` — no `ShellEnvironment`. (If a helper's only reason to take `&dyn ShellEnvironment` was these calls, drop the param.)
- [ ] **Step 4:** Run — PASS. `cargo nextest run -p mvm-build --features builder-vm` for the affected module.
- [ ] **Step 5:** Commit: `fix(build): probe build artifacts on the host, not through a VM`.

### Task 4 (W3): Platform-gate `mvmctl bootstrap`'s Firecracker provisioning

`crates/mvm-cli/src/commands/env/setup.rs::run_setup_steps` (via `env::bootstrap`,
backing the top-level `mvmctl bootstrap` run by `install.sh`) unconditionally calls
`firecracker::is_installed()` (its first statement), `firecracker::install()`,
`download_assets()`, `prepare_rootfs()`, and `setup_security_baseline()` (which
`run_in_vm("sudo mkdir -p /var/lib/mvm/tenants")`). None is platform-gated, so on
macOS 26+ it crashes at the first Firecracker probe. On macOS, `bootstrap` should
only pre-fetch the builder VM image (`bootstrap_builder_vm_image`, already present);
Firecracker provisioning is Linux-only.

- [ ] **Step 1: Failing test** — a `run_setup_steps`-shaped unit that asserts the Firecracker/security-baseline steps are skipped on non-Linux. If the fn isn't unit-testable as-is, extract the platform decision into a pure `fn firecracker_provisioning_applies() -> bool { cfg!(target_os = "linux") }` and test that.
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Gate the Firecracker install/download/rootfs + `/var/lib/mvm` + jailer/seccomp-baseline steps behind `cfg!(target_os = "linux")` (or the resolved backend being Firecracker). Keep the builder-VM prefetch on all platforms. Confirm no `run_in_vm` remains reachable from `bootstrap` on macOS.
- [ ] **Step 4:** Run — PASS. `cargo nextest run -p mvm-cli` for the setup/bootstrap module.
- [ ] **Step 5:** Commit: `fix(bootstrap): don't provision Firecracker assets on macOS`.

### Task 5: Integration proof + workspace gate

- [ ] **Step 1:** Add/confirm a test that `machine run --flake`'s post-build artifact-install path (Task 2) and the bootstrap platform gate (Task 4) don't reference `run_in_vm`. A focused `git grep` assertion in a test, or a unit exercising the extracted helpers, is sufficient (a real macOS-26 live boot is the manual exit gate).
- [ ] **Step 2:** Full gate: `cargo fmt --all -- --check` (nightly), `cargo nextest run --workspace -E 'not package(mvm-backend)'`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build -p mvm-backend --all-targets`.
- [ ] **Step 3:** Update `specs/REFACTOR-STATUS.md`. Commit.

**Phase 1 exit gate (manual, macOS 26+):** on this Mac, `cargo run -- machine run --flake . …` builds and files its result without a dev-VM error; `cargo run -- bootstrap` completes without a Firecracker crash.

---

# W4 — Deferred (separate plan): genuine guest ops on macOS 26+

These need a real Linux VM and don't have a host-side substitute. Route them through
the existing typed-RPC-to-headless-builder seam (`MVM_BUILDERD_TYPED` / `mvm-builderd`,
already an opt-in fallback in `validate.rs` and `dev_build.rs`), not a revived generic
host-shell-in-a-VM primitive (the builder protocol is job-shaped — `BuilderJob::{Flake,Install}` — with no `Exec{script}` variant):

- `mvmctl build validate` (`nix flake check`) — the cleanest user-visible crash.
- `machine run --mount HOST:GUEST` (`mkfs.ext4` + `mount`, `image.rs::build_dir_image_ro`).
- `machine forward` (`resolve.rs:12` firecracker process check).
- `template/lifecycle.rs:847` `nix hash path` + `update_fod_hash` (`--update-hash`).

# Self-review notes
- **Coverage:** W1→T1, W2→T2+T3, W3→T4, proof→T5; W4 deferred. The three broken common commands (`bootstrap`, `machine run --flake`, `machine build`) are fixed by T2+T4.
- **Risk:** T1 is deletion — the build gate catches any mis-classified "dead" file; verify zero callers first. T2/T3 must preserve the exact destination paths (`template_revision_dir`, `build_dir`) — reuse the existing path helpers, don't reconstruct paths.

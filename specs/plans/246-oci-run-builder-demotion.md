# Kernel-cheap `machine run --image` + builder-VM demotion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan number:** 246 (verify still free against open PRs before landing PR 1)
**Design:** `specs/notes/2026-07-11-oci-run-builder-vm-demotion-design.md`
**Status:** draft — PR 1 is this document
**Owner:** Ari

**Goal:** Make `mvmctl machine run --image <oci>` acquire its kernel cheaply
(reuse-or-build-once-and-cache, never a redundant full builder-image build, never
a hermeticity-violating download in a source checkout), fix the crash, give every
builder/nix build first-class logs, and then retire the interactive `mvmctl dev`.

**Architecture:** An `--image` run already materializes its rootfs + guest-binary
overlay in-process (`oci_runtime_inject` + `materialize_ext4_pure`); only the Linux
kernel pulls in the builder VM. We (1) land the Stage 0 purity/failure-surfacing
fix, (2) correct the kernel resolver so a source checkout builds/reuses locally
(download is installed-builds-only), (3) route the noisy host-side supervisor
rebuild and in-guest nix stream through a log file with a clean heartbeat and
`-v` passthrough, then (4) delete the `mvmctl dev` interactive surface — keeping the
builder VM as a headless nix build engine.

**Tech Stack:** Rust (Cargo workspace, `mvm-cli` / `mvm-build`), libkrun Stage 0
builder VM, nix, `cargo-nextest`, clap.

## Global Constraints

Copied verbatim from the repo rules — every task's requirements include these:

- `cargo fmt --all -- --check` clean; run `rustup run nightly cargo fmt --all` before push (CI Lint is nightly rustfmt).
- `cargo nextest run --workspace` green; `cargo test --workspace --doc` green; `cargo clippy --workspace --all-targets -- -D warnings` clean. Run the FULL crate suite, not `-p`-filtered.
- Never cite plans/PRs/ADRs/workstreams in **code comments** (`Plan N`, `ADR-\d+`, `#NNNN`, `W\d.` are CI-banned via `check-no-spec-refs-in-comments`). Spec/plan prose may cite freely; example code in this plan must not carry such comments.
- No `#[allow(clippy::too_many_arguments)]`; use a params struct + builder.
- Reuse-first: no reimplementation of existing helpers; all `~/.mvm` / `~/.cache/mvm` paths via `mvm_core::config`.
- Source-checkout hermeticity: a source checkout MUST NOT download mvm-published artifacts; it builds locally. Only an installed binary downloads.
- Commits: no `Co-Authored-By: Claude` trailer; attribute to the user. No AI-tool attribution in PRs.
- All work in this worktree (`worktree-oci-run-builder-demotion-design`); never edit the main checkout.
- Keep `specs/SPRINT.md` + `specs/REFACTOR-STATUS.md` in sync in the same change that lands a workstream.

---

# Phase 1 — PR 2: kernel-cheap `machine run --image` (WS1 + WS2 + WS3)

Ship + confirm this whole phase works end-to-end (including reading a failing
builder log) before starting Phase 2.

### Task 1: Land the Stage 0 purity + failure-surfacing fix (WS1)

The `/homeless-shelter` crash and the "clean exit hides a nix failure" masking are
already fixed, with tests, on `fix/stage0-homeless-shelter-purity`. Reland, don't
rewrite.

**Files:**
- Modify: `crates/mvm-build/src/bin/stage0-init.rs` (`purge_stale_nix_builder_home` + call before nix invoke)
- Modify: `crates/mvm-build/src/libkrun_builder.rs` (`stage0_console_halt_outcome`, `Stage0HaltOutcome`, `BuildFailed`/`NoCleanHalt` surfacing after supervisor exit)
- Tests (already authored on the branch): `purge_stale_nix_builder_home_removes_leftover_and_tolerates_absence`, `stage0_console_halt_outcome_distinguishes_success_failure_and_silence`

**Interfaces produced:** a Stage 0 build that (a) self-heals a stale
`/homeless-shelter` before nix's unsandboxed purity check trips, and (b) returns
`BuilderVmError::NixBuildFailed(<msg + 20-line console tail>)` instead of a clean
`Ok(())` when the guest reported `stage0-init: build failed`.

- [ ] **Step 1: Cherry-pick the fix commits onto this branch**

```bash
git log --oneline main..fix/stage0-homeless-shelter-purity   # identify the commit(s)
git cherry-pick <sha>...<sha>
```

- [ ] **Step 2: Run the relanded tests, verify PASS**

```bash
cargo nextest run -p mvm-build purge_stale_nix_builder_home stage0_console_halt_outcome
```
Expected: both tests PASS.

- [ ] **Step 3: Full crate gate + commit**

```bash
cargo nextest run -p mvm-build && cargo clippy -p mvm-build --all-targets -- -D warnings
git commit -am "fix(stage0): purge stale nix builder home; surface guest build failure"
```

### Task 2: Kernel resolver — source checkouts build/reuse locally, never download (WS2)

**Problem (verified on `main`):** `resolve_workload_kernel_bootstrap`
(`crates/mvm-cli/src/commands/env/dev_vz/default_microvm.rs:61`) routes a
source checkout with a cold cache to the **`Download`** arm, because
`workload_kernel_source_build_requested` (`default_microvm.rs:83`) only returns
true when `MVM_KERNEL_SOURCE=compile`. That download hits
`releases/download/v{dev-version}` → 404, and it violates source-checkout
hermeticity. A source checkout must **build** (or reuse the builder kernel); only
an installed build downloads.

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/dev_vz/default_microvm.rs:83-93` (`workload_kernel_source_build_requested`)
- Test: same file's `#[cfg(test)] mod tests` (extend the existing resolver tests)

**Interfaces produced:** `resolve_workload_kernel_bootstrap(cache_dir, arch, prod, source_build_requested)` unchanged in signature; `source_build_requested` now true for *every* source checkout unless `MVM_KERNEL_SOURCE=download` explicitly overrides.

- [ ] **Step 1: Write the failing resolver matrix test**

```rust
#[test]
fn source_checkout_cold_cache_builds_never_downloads() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().to_str().unwrap();
    // No cached kernel, no reusable builder kernel, source checkout, non-prod:
    // must BUILD locally (hermeticity) — must NOT be Download.
    let got = resolve_workload_kernel_bootstrap(cache, "aarch64", false, /*source_build_requested=*/ true);
    assert!(matches!(got, WorkloadKernelBootstrap::Build(_)), "got {got:?}");
}

#[test]
fn installed_build_cold_cache_downloads() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().to_str().unwrap();
    // Installed binary (source_build_requested=false): Download is correct.
    let got = resolve_workload_kernel_bootstrap(cache, "aarch64", false, false);
    assert!(matches!(got, WorkloadKernelBootstrap::Download(_)), "got {got:?}");
}
```

- [ ] **Step 2: Run, verify the first test FAILS on current logic**

```bash
cargo nextest run -p mvm-cli source_checkout_cold_cache_builds_never_downloads
```
Expected: FAIL (current default routes source checkout → Download).

- [ ] **Step 3: Flip the default in `workload_kernel_source_build_requested`**

```rust
fn workload_kernel_source_build_requested(source_checkout: bool) -> bool {
    #[cfg(feature = "builder-vm")]
    {
        // A source checkout builds the kernel locally by default; the
        // hermeticity rule forbids depending on a published artifact. Only an
        // explicit opt-out downloads (test/CI escape hatch).
        source_checkout && !matches!(resolve_kernel_source(), Some(KernelSource::Download))
    }
    #[cfg(not(feature = "builder-vm"))]
    {
        let _ = source_checkout;
        false
    }
}
```
(Verify `KernelSource::Download` exists in `dev_vz/kernel.rs`; it is referenced in `bootstrap.rs`.)

- [ ] **Step 4: Run both resolver tests, verify PASS**

```bash
cargo nextest run -p mvm-cli source_checkout_cold_cache_builds_never_downloads installed_build_cold_cache_downloads
```
Expected: both PASS. Confirm the existing `Cached`/`ReusableBuilder` priority tests still pass (reuse still wins over build for non-prod).

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(kernel): source checkout builds workload kernel locally, never downloads"
```

### Task 3: Route the host-side builder rebuild + nix stream through a log file (WS3)

**Problem (verified):** the "terrible logs" are the host cargo rebuild of
`mvm-libkrun-supervisor` ("[mvm] building mvm-libkrun-supervisor for this source
checkout…") and the in-guest nix stream printing raw lines that interleave with
the `BuildHeartbeat` spinner (`bootstrap.rs:524`). Default runs should show one
clean labeled heartbeat; full output goes to a log file; `-v` streams live.

**Files:**
- Modify: the host aux-bin rebuild path that emits `building mvm-libkrun-supervisor …` (grep `building mvm-libkrun-supervisor for this source checkout`) — capture its child stdout/stderr to a log file instead of inheriting the terminal, unless verbose.
- Modify: `crates/mvm-cli/src/commands/env/dev_vz/bootstrap.rs` around the `BuildHeartbeat::start` sites (`:73`) — echo the log path once ("logs: <path> — tail -f, or -v to stream").
- Test: a unit test on the log-capture helper (child output lands in the file; verbose bypasses capture).

**Interfaces produced:** a small helper, e.g. `run_logged(cmd, log_path, verbose) -> Result<()>`, that streams to the terminal when `verbose`, else writes combined output to `log_path` and returns an error carrying the tail on failure. Reuse the existing `read_console_tail` for the tail.

- [ ] **Step 1: Write the failing capture test**

```rust
#[test]
fn run_logged_writes_child_output_to_file_when_quiet() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("build.log");
    run_logged(std::process::Command::new("sh").args(["-c", "echo hello; echo err 1>&2"]),
               &log, /*verbose=*/ false).unwrap();
    let body = std::fs::read_to_string(&log).unwrap();
    assert!(body.contains("hello") && body.contains("err"), "combined output captured: {body}");
}
```

- [ ] **Step 2: Run, verify FAIL (helper absent)**

```bash
cargo nextest run -p mvm-cli run_logged_writes_child_output_to_file_when_quiet
```
Expected: FAIL — `run_logged` not defined.

- [ ] **Step 3: Implement `run_logged` + wire the supervisor rebuild through it**

Implement the helper (combined stdout+stderr → file, or inherit when verbose;
on nonzero exit return an error with the last ~30 lines via `read_console_tail`).
Replace the direct terminal-inheriting spawn of the `mvm-libkrun-supervisor`
rebuild with `run_logged(cmd, &log_path, ui::is_verbose())`. Echo the log path
once next to the heartbeat.

- [ ] **Step 4: Run capture test + manual smoke, verify PASS + clean output**

```bash
cargo nextest run -p mvm-cli run_logged_writes_child_output_to_file_when_quiet
```
Expected: PASS. Manual: a cold `machine run --image` shows a single heartbeat + a
`logs: …` line, not a cargo `Building [===]` stream.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(build-logs): capture builder rebuild + nix stream to a log; -v streams"
```

### Task 4: Honest labels + failure surfaces the log path (WS3)

**Files:**
- Modify: `bootstrap.rs:73` heartbeat label `"Builder VM image build"` → a label that reflects what is happening for an `--image` run, e.g. `"Preparing build environment (one-time)"`; and `default_microvm.rs:32` `"Building workload kernel locally…"` stays but gains the log path.
- Test: assert the failure error string carries the console log path (compose with Task 1's `NixBuildFailed`).

- [ ] **Step 1: Write/extend the failure-surface test**

```rust
#[test]
fn stage0_build_failure_error_names_the_log_path() {
    let err = BuilderVmError::NixBuildFailed(
        "nix build failed inside the Stage 0 guest; console log at /tmp/c.log\n<tail>".into());
    assert!(err.to_string().contains("console log at /tmp/c.log"));
}
```

- [ ] **Step 2: Run, verify PASS after relabel (label is cosmetic; error path is Task 1)**

```bash
cargo nextest run -p mvm-cli -p mvm-build stage0_build_failure_error_names_the_log_path
```

- [ ] **Step 3: Relabel + commit**

```bash
git commit -am "feat(build-logs): honest one-time-build label; failures name the log path"
```

### Task 5: Integration proof — cold `--image` run does no redundant builder-image build (WS2, the confirm gate)

**Files:**
- Test: `tests/oci_image_runner_smoke.rs` (extend) or a new `tests/machine_run_kernel_resolution.rs`.

- [ ] **Step 1: Write the integration test**

Seed a fake reusable builder kernel at `{cache}/builder-vm/{arch}/vmlinux`, drive
the kernel-resolution entry the run path uses (`ensure_workload_kernel(false)` or
`resolve_workload_kernel_bootstrap`), assert it resolves `ReusableBuilder` (no
build) and does not invoke `bootstrap_builder_vm_image`. Then remove the kernel and
assert a source checkout resolves `Build` (not `Download`).

- [ ] **Step 2: Run, verify PASS**

```bash
cargo nextest run -p mvm-cli --test machine_run_kernel_resolution
```

- [ ] **Step 3: Full workspace gate**

```bash
cargo fmt --all -- --check && cargo nextest run --workspace && cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 4: Update sprint/refactor status + commit**

Tick the Phase 1 items in `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`.

```bash
git commit -am "test(oci-run): cold --image reuses builder kernel, never redundant builder-image build"
```

**Phase 1 exit gate (manual, with the user):** on a *fresh* cache in this source
checkout, `cargo run -- machine run --image alpine -it -- /bin/sh` boots without a
mystery "Builder VM image build", any one-time build is honestly labeled + logged,
and a deliberately-broken builder build is diagnosable from its log file. Confirm
before Phase 2.

---

# Phase 2 — PR 3: remove `mvmctl dev` (WS6)

**Hard gate:** start only after the Phase 1 exit gate passes — specifically after
we have *proven* a builder-VM build failure is diagnosable from its log (Tasks 3–4).
That inspection capability is the entire justification for removing the interactive
shell.

### Task 6: Delete the `dev` subcommand surface, keep the build internals

**Files:**
- Modify: the clap command tree (grep `Dev` / `dev up` / `dev shell` in `crates/mvm-cli/src/commands/` and the CLI enum) — remove `dev up/down/shell/status`.
- Keep: the builder-VM launch/build/teardown internals in `dev_vz/` that the build path (`ensure_workload_kernel`, `build image`, `--flake`) still calls. Only the *interactive* entry points go.
- Remove: the interactive builder-shell transport (PTY/console-over-vsock **into the builder**; grep `pick_console_transport` / builder console). Do **not** touch the workload console path (claim 15).

- [ ] **Step 1:** Enumerate callers of the `dev` subcommands and the builder-shell transport; separate "interactive-only" from "build-internal" (a short written audit committed to the PR description).
- [ ] **Step 2:** Remove the interactive command variants + their handlers; leave build internals compiling.
- [ ] **Step 3:** `cargo nextest run --workspace` + `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] **Step 4:** Commit.

### Task 7: Update CLI tests, docs, and CLAUDE.md references

**Files:**
- Modify: `tests/cli.rs` (drop `dev` help/arg-parse expectations).
- Modify: `public/src/content/docs/reference/cli-commands.md`, `public/src/content/docs/contributing/development.md` (remove `mvmctl dev …`; document "build logs live at <path>, `-v` to stream" as the debugging story).
- Modify: `CLAUDE.md` (the `mvmctl dev` bullets under "Key Design Decisions" and "Build and Run").

- [ ] **Step 1:** Update `tests/cli.rs`; run it.
- [ ] **Step 2:** Update docs + `CLAUDE.md`.
- [ ] **Step 3:** Update `specs/SPRINT.md` + `specs/REFACTOR-STATUS.md`; note the `feat/plan-222-phase4-devbackend-hvf` descope.
- [ ] **Step 4:** Full workspace gate + commit.

---

# Deferred follow-ups (out of the 3-PR scope — separate plans)

- **WS4 — end-user prebuilt-kernel download / release asset.** Make the release
  publish `vmlinux-<arch>-workload` + `kernel-<arch>-checksums-sha256.txt` so the
  installed-build `Download` arm (`default_microvm.rs:100`) stops 404-ing. Aligns
  with `#1640`.
- **WS5 — builder audited-egress cutover.** Route builder-VM nix-substituter
  fetches over host-brokered egress (attestation/traceability); hand off to Plan
  236's builder no-guest-NIC work rather than duplicate it.

# Self-review notes

- **Spec coverage:** WS1→Task 1; WS2→Tasks 2,5; WS3→Tasks 3,4; WS6→Tasks 6,7; WS4/WS5 deferred. All design goals mapped.
- **Open risk carried from design:** reusing the builder kernel as the workload kernel is only safe when configs match — the cache is keyed by kernel-config fingerprint; Task 5 must not weaken that (interacts with Plan 239 kernel slimming).

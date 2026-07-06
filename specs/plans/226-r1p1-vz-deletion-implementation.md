# Release 1 Phase 1 — Vz Deletion — Implementation Plan (refreshed against origin/main 53badc19)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. Execute in the isolated worktree `worktree-plan-226-r1p1-vz-deletion`.

**Goal:** Remove the entire Apple-Virtualization (`vz`) backend from mvm — VMM, per-VM supervisor bin, builder, dev-VM path, and the `vm_full` checkpoint/fork engine that depends on it — while keeping libkrun (and its gvproxy path) untouched. `machine checkpoint/fork`'s Vz-only `vm_full` mode is descoped to a clear tracked-unsupported error; the `fs_quick` mode (already backend-neutral as of #1481) stays.

**Architecture:** macOS-26 already defaults to the in-house HVF VMM; `vz` is opt-in. Delete in dependency order: sever the runtime consumers (checkpoint `vm_full`, dev-VM selection) → delete the `Vz` variant + dispatch → delete the Vz modules/bins → sweep residual references → clean tests/fuzz/manifests → migrate witnesses → ratify ADR → release-engineer v0.17.0.

**Tech Stack:** Rust (Cargo workspace, `cargo nextest`), objc2 (deleted with Vz), GitHub Actions, xtask claim-gates.

**Blast radius (from a fresh scout of 53badc19):** ~40 files reference Vz. Heaviest: `vz_builder.rs` (117), `vz.rs` (92), `checkpoint/mod.rs` (28), `doctor.rs` (21), `dev_vz.rs`/`dev.rs`, `checkpoint.rs` (13), `mvm-build/src/vz.rs` (12), `mvm-vz-supervisor.rs` (10), `cache.rs` (8), `host_gvproxy.rs` (8).

## Global Constraints

- **Touch `vz` only. Keep libkrun + its gvproxy path fully intact** — do NOT modify `crates/deps/libkrun-sys/src/gvproxy.rs`, `libkrun.rs`'s gateway selection, the libkrun builder, or the new `MVM_VSOCK_EGRESS` wiring (`libkrun_network_provider.rs:33` — that's R1P2 territory). Keep `passt` untouched (Linux, R2).
- **Preserve the `mvmctl::runtime::*` re-export contract** (mvmd consumes it) — do not remove/rename public re-exports from `mvm-backend::base` or the root facade.
- **Keep the `fs_quick` checkpoint path working** — only the Vz-coupled `vm_full` save/restore/fork arms are removed.
- **Gates green before every commit:** `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings` (prefer `just ci`). Run `just check-linux` before the final commit of any task touching `cfg`-gated code.
- **No `#[allow(clippy::too_many_arguments)]`** — use a params struct.
- Commit messages reference `(Plan 226 R1P1)` and end with the repo's `Co-Authored-By` trailer.
- **All paths below are worktree-relative.** Deletion tasks follow: make the edit → `cargo build` → fix every compiler-reported reference → run gates → commit. Pure deletion does not need red-green; the existing suite + the compiler are the safety net. Where a task changes *behavior*, a failing test comes first.

---

### Task 0: Land the plan docs on the branch

**Files:** `specs/plans/226-clean-replacement-release-roadmap.md`, `specs/plans/226-r1p1-vz-deletion-implementation.md` (both already copied into the worktree, untracked).

- [ ] **Step 1: Commit the plan docs**

```bash
git add specs/plans/226-clean-replacement-release-roadmap.md specs/plans/226-r1p1-vz-deletion-implementation.md
git commit -m "docs(plan): Plan 226 clean-replacement roadmap + R1P1 Vz-deletion plan"
```

---

### Task 1: Descope the Vz-coupled `vm_full` checkpoint/fork engine (WS-D)

`machine checkpoint/fork`'s `vm_full` mode is the only runtime Vz consumer left after the enum. It is wired across `crates/mvm-cli/src/commands/vm/checkpoint.rs` (gate at `:393`, callers `:454`/`:652`, `VzVmFullControl` `:463`, `VzChildSupervisorSpawner` `:956`, `SupervisorConfig` parse `:877`, `supervisor_config_path` import `:22`, `vz.paused`/`vz.pid` markers `:362-383`, backend_name `"vz"` `:906`/`:977`) and `crates/mvm-backend/src/checkpoint/mod.rs` (28 refs — the `VzVmFullControl`/`VzChildSupervisorSpawner` engine). Remove the `vm_full` path; keep `fs_quick` (backend-neutral since #1481).

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/checkpoint.rs` (remove `create_vm_full`, `restore` vm_full arm, `fork_vm_full_arm*`, `ensure_save_restore_supported`, the `vz_*` quiesce helpers `:327-383`; make the CLI surface return a tracked-unsupported error when `vm_full`/`--full` is requested)
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs` (remove the `VzVmFullControl`/`VzChildSupervisorSpawner` engine and its `::vz::` uses; keep the fs_quick record/restore surface)
- Test: `checkpoint.rs` inline `#[cfg(test)]`

**Interfaces:**
- Produces: a `machine checkpoint --full` / `machine fork` (full) CLI path that returns `Err` with a message naming the missing capability and the tracking (Plan 226 WS-E), with no reference to `mvm_backend::vz`.
- Consumes: the existing `fs_quick` checkpoint entry points (unchanged).

- [ ] **Step 1: Read the two files and map the fs_quick vs vm_full split**

Read `crates/mvm-backend/src/checkpoint/mod.rs` and `crates/mvm-cli/src/commands/vm/checkpoint.rs` in full. List every function on the `vm_full` path (Vz-coupled) vs the `fs_quick` path (keep). Confirm the CLI entry points for `checkpoint create`/`restore`/`fork` and where mode is selected.

- [ ] **Step 2: Write the failing test**

```rust
#[test]
fn vm_full_checkpoint_reports_tracked_unsupported() {
    // vm_full/full-VM save-restore was Vz-only; after Vz removal it must
    // fail with a clear, tracked message rather than panic or compile-ref Vz.
    let err = full_vm_checkpoint_unsupported_error("checkpoint");
    let msg = err.to_string();
    assert!(msg.contains("full-VM"), "names the mode: {msg}");
    assert!(msg.contains("HVF") && msg.contains("226"), "points at the tracked re-home: {msg}");
}
```

Where `full_vm_checkpoint_unsupported_error(action: &str) -> anyhow::Error` is a new small helper you add in `checkpoint.rs` and call from the CLI `vm_full` branch.

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli vm_full_checkpoint_reports_tracked_unsupported`
Expected: FAIL — helper does not exist.

- [ ] **Step 4: Remove the vm_full engine and route to the tracked error**

- In `checkpoint.rs`: delete `ensure_save_restore_supported` (`:393`), `create_vm_full`, the `vm_full` arm of `restore` (and its `VzBackend` at `:657`), `fork_vm_full_arm*`, `vz_rootfs_from_supervisor_config` + `vm_is_quiesced`/`vz_pause_marker_matches_live_pid` (`:327-383`) IF only used by vm_full, and the `use mvm_backend::vz::supervisor_config_path;` (`:22`). Add `fn full_vm_checkpoint_unsupported_error(action:&str)->anyhow::Error` returning the tracked message, and route the CLI `vm_full`/`--full` selection to `bail!` with it.
- In `checkpoint/mod.rs`: delete the `VzVmFullControl`/`VzChildSupervisorSpawner`-based engine and every `::vz::` reference; keep the fs_quick record/restore API.

- [ ] **Step 5: Build + test + gate**

Run: `cargo build -p mvm-cli -p mvm-backend` then `cargo nextest run -p mvm-cli vm_full_checkpoint_reports_tracked_unsupported && cargo nextest run -p mvm-cli -p mvm-backend -- checkpoint`
Expected: PASS. Fix/remove any vm_full test that no longer applies; keep fs_quick tests green.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/checkpoint.rs crates/mvm-backend/src/checkpoint/mod.rs
git commit -m "refactor(checkpoint)!: descope Vz-only vm_full save/restore/fork; keep fs_quick (Plan 226 R1P1 WS-D)"
```

---

### Task 2: Default macOS-26 dev VM to HVF; remove the Vz dev path + `dev_vz` module (WS-B)

`crates/mvm-cli/src/commands/env/dev.rs` defaults macOS-26 to `DevBackend::Vz` (`select_dev_backend` `:99-110`) and dispatches through `dev_vz::cmd_dev_vz*` across ~12 arms (`:332,357,462,477,612,636,658,689,703,741,762`). The engine is `crates/mvm-cli/src/commands/env/dev_vz.rs` (`cmd_dev_vz`, `cmd_dev_vz_park`, `cmd_dev_vz_down`, `cmd_dev_vz_status`, + `cmd_dev_cache_inspect`/`cmd_dev_import_image` which are NOT Vz-specific and must be preserved/relocated).

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/dev.rs` (enum `:41`, `select_dev_backend` `:89`, all `DevBackend::Vz` arms, import `:29`/`:36`)
- Modify/Delete: `crates/mvm-cli/src/commands/env/dev_vz.rs` (delete Vz VM lifecycle fns; relocate `cmd_dev_cache_inspect`/`cmd_dev_import_image` to a non-Vz module if they're the only survivors)
- Modify: `crates/mvm-cli/src/commands/env/mod.rs:11` (`mod dev_vz;` declaration)
- Test: `dev.rs` inline tests `:819-927`

**Interfaces:**
- Produces: `DevBackend::InHouse`; `select_dev_backend` returns `InHouse` on the macOS-26 tier; the in-house dev VM lifecycle entry points used by the `Up/Down/Park/Shell/Status/Rebuild` arms.

- [ ] **Step 1: Read the in-house dev-VM lifecycle + the dev_vz survivors**

Read `dev.rs` and `dev_vz.rs`. Identify (a) the in-house/HVF dev-VM equivalent of each `cmd_dev_vz_*` (boot/park/down/status) — grep `rg -n "dev.*inhouse|InHouse|hvf" crates/mvm-cli/src/commands/env` and the HVF backend; if a HVF dev path already exists (memory: `MVM_DEV_BACKEND=hvf`), reuse it. (b) Which `dev_vz.rs` functions are NOT Vz-specific (`cmd_dev_cache_inspect`, `cmd_dev_import_image`) and must survive. Record the exact substitutions.

- [ ] **Step 2: Write the failing selection test**

```rust
#[test]
fn macos_26_apple_silicon_selects_inhouse_dev_backend() {
    let choice = select_dev_backend(
        Platform::MacOS,
        /* prefers_vz */ false, /* prefers_libkrun */ false,
        /* has_vz */ true, /* is_vz_default_tier */ true,
        /* has_libkrun */ true, /* has_kvm */ false,
    );
    assert_eq!(choice, DevBackend::InHouse);
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo nextest run -p mvm-cli macos_26_apple_silicon_selects_inhouse_dev_backend`
Expected: FAIL — `DevBackend::InHouse` absent / rule returns `Vz`.

- [ ] **Step 4: Add `InHouse`, flip selection, re-home the arms**

- Replace the `Vz` variant with `InHouse` (`:49`). Remove `prefers_vz`/`has_vz` params from `select_dev_backend` and the two Vz branches; make `is_vz_default_tier` → `DevBackend::InHouse`. Delete `builder_prefers_vz()` (`:121`).
- Re-home each `DevBackend::Vz` arm to `DevBackend::InHouse` using the in-house lifecycle from Step 1 (Up/Down/Park/Shell/Status/Rebuild). Update `dev_backend_report_name` `:477` → `"inhouse"`.
- In `dev_vz.rs`: delete the Vz VM lifecycle fns; preserve `cmd_dev_cache_inspect`/`cmd_dev_import_image` (move them to `env/dev.rs` or a new `env/dev_cache.rs` and update `mod.rs`). Remove `use mvm_backend::VzBackend` from `dev.rs:29` (keep `LibkrunBackend`), and `use super::dev_vz;` `:36` if fully removed.

- [ ] **Step 5: Build + test**

Run: `cargo build -p mvm-cli && cargo nextest run -p mvm-cli -- dev`
Expected: PASS. Update/delete the Vz-selection tests at `:819-927`.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/env/
git commit -m "feat(dev)!: default macOS-26 dev VM to in-house HVF, remove Vz dev path + dev_vz lifecycle (Plan 226 R1P1 WS-B)"
```

---

### Task 3: Remove the Vz builder backend (WS-C)

**Files:**
- Modify: `crates/mvm-build/src/builder_backend_select.rs` (import `:31`, `Vz` variant `:73`, `.name()` `:89`, env map `:134`, constructors `:189`/`:212`, `builder_attempt_order` arm `:305`, tests `:577,588,595,626,639,665,722,764`)
- Delete: `crates/mvm-build/src/vz_builder.rs` (117 refs) + its `mod vz_builder;` + test `crates/mvm-build/tests/vz_builder_flake_invariant.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:** Produces `BuilderBackendChoice` with no `Vz`; `builder_attempt_order` with no `Vz` arm.

- [ ] **Step 1: Guard test**

```rust
#[test]
fn macos_inhouse_auto_falls_back_to_libkrun_only() {
    let order = builder_attempt_order(BuilderBackendChoice::InHouse, false, false, false);
    assert_eq!(order, vec![BuilderBackendChoice::InHouse, BuilderBackendChoice::Libkrun]);
}
```

- [ ] **Step 2: Run (already passes — regression guard)**

Run: `cargo nextest run -p mvm-build macos_inhouse_auto_falls_back_to_libkrun_only`
Expected: PASS.

- [ ] **Step 3: Delete Vz builder wiring**

Remove the import (`:31`), `Vz` variant (`:73`) + `.name()` (`:89`), env map (`:134`), both `VzBuilderVm::new()` constructors (`:189`,`:212`), the `builder_attempt_order` Vz arm (`:305`). `git rm crates/mvm-build/src/vz_builder.rs crates/mvm-build/tests/vz_builder_flake_invariant.rs` and remove `mod vz_builder;`. Delete Vz builder tests (`:577-773`).

- [ ] **Step 4: Build + chase errors + test**

Run: `cargo build -p mvm-build` (fix every reported ref) then `cargo nextest run -p mvm-build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A crates/mvm-build/
git commit -m "refactor(builder)!: remove Vz builder backend, keep libkrun fallback (Plan 226 R1P1 WS-C)"
```

---

### Task 4: Remove the `Vz` variant from `AnyBackend`, selection, and catalog (WS-A core)

**Files:**
- Modify: `crates/mvm-backend/src/backend.rs` (import `:21`, variant `:475`, `kind` `:626`, `inner` `:637`, `into_dyn` `:653`, `as_workload_backend` `:704`, catalog test tuple `:1549`, tests `:987-992,1161,1368`)
- Modify: `crates/mvm-backend/src/selection.rs` (import `:2` area, `capability_candidates` `:63-70` → `[AnyBackend; 3]`)
- Modify: `crates/mvm-backend/src/catalog.rs` (import `:19`, `Vz` descriptor block `:129-140`, test arrays `:295,304`)

**Interfaces:** Produces `AnyBackend` and `BackendKind` with no `Vz`; `capability_candidates() -> [AnyBackend; 3]`.

- [ ] **Step 1: Guard test in backend.rs**

```rust
#[test]
fn vz_selector_no_longer_resolves_to_vz() {
    let b = AnyBackend::from_hypervisor("vz");
    assert_ne!(b.name(), "vz", "vz selector must fall back to default after removal");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-backend vz_selector_no_longer_resolves_to_vz`
Expected: FAIL — catalog `"vz"` descriptor still yields `AnyBackend::Vz`.

- [ ] **Step 3: Delete the variant, dispatch arms, candidate, descriptor**

Remove the `use crate::vz::VzBackend;` in both files; the `Vz(VzBackend)` variant + all four dispatch arms; the `AnyBackend::Vz(VzBackend)` candidate (change arity to `[AnyBackend; 3]`); the catalog `Vz` descriptor block (`:129-140`) and the `BackendKind::Vz`-generating entry. Fix catalog test arrays (`:295,304`) and the backend tests (`:987-992,1161,1368`, incl. the `("vz", …)` tuple at `:1549`).

- [ ] **Step 4: Build + chase + test**

Run: `cargo build -p mvm-backend` (fix every `Vz`/`BackendKind::Vz` the compiler flags) then `cargo nextest run -p mvm-backend vz_selector_no_longer_resolves_to_vz && cargo nextest run -p mvm-backend`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backend/src/backend.rs crates/mvm-backend/src/selection.rs crates/mvm-backend/src/catalog.rs
git commit -m "refactor(backend)!: remove Vz variant from AnyBackend/selection/catalog (Plan 226 R1P1 WS-A)"
```

---

> **SCOPE REVISION (Option B, decided mid-run 2026-07-06).** During Task 3 we
> confirmed `crates/mvm-backend/src/base/linux_env.rs::create_linux_env()`
> returns `VzDevEnv` on `is_vz_default_tier()` (macOS-26), so the **persistent
> Vz builder VM is still the live macOS build ShellEnvironment substrate**.
> Physically deleting `vz.rs`/`vz_control.rs`/`vz_objc.rs`/`mvm-vz-supervisor`/
> `vz_builder.rs` therefore CANNOT happen in R1P1 — it must wait until that
> substrate is flipped onto the retained **libkrun** persistent builder, with a
> real build validated. That deletion + flip is deferred to a dedicated plan
> **226-R1P1b**. R1P1 (Tasks 1–4, done) makes Vz **unselectable** as a workload,
> dev, and one-shot-builder backend; the Vz code files are retained and still
> compile. Tasks 5–8 below are the cleanup/docs tail for that unselectable
> state — **no file deletion, no fuzz/witness removal** (those witnesses cover
> retained code).

### Task 5: Light residual sweep of the now-unselectable Vz *workload* wiring

After Task 4, the tree compiles (the compiler guarantees no dangling refs). This task removes only the small, provably-safe leftovers of the *workload* Vz path and the stale test assertions — WITHOUT touching the retained persistent-builder substrate (`vz.rs`, `vz_builder.rs`, `mvm-vz-supervisor`, `vz_objc.rs`, `host_gvproxy.rs`, `create_linux_env`/`VzDevEnv`, `doctor.rs`/`cache.rs` Vz-builder state-dir handling — all KEPT).

**Files:** `crates/mvm-cli/src/commands/shared/resolve.rs` (the `vz` test assertions only), plus any test/match arm the compiler flagged as unreachable after Task 4 that is unambiguously workload-only.

- [ ] **Step 1: Enumerate what Task 4 left**

Run: `rg -n "AnyBackend::Vz|BackendKind::Vz" crates/ src/` (expect zero — Task 4's bar) and `rg -n "egress_enforcement_label\(\"vz\"|resolve_effective_hypervisor\(\"vz\"" crates/mvm-cli/src/commands/shared/resolve.rs`.

- [ ] **Step 2: Remove the stale `vz` test assertions in resolve.rs**

Drop `"vz"` from the `["firecracker","libkrun","vz"]` array (`enforcement_tier_uniform_for_deny_all_and_unrestricted`), remove the `egress_enforcement_label("vz", …)` assertion, and remove the `resolve_effective_hypervisor("vz")` assertions. The `egress_enforcement_label` function itself is backend-agnostic — KEEP it. Do NOT touch `doctor.rs`/`cache.rs`/`platform.rs` Vz-builder handling (retained).

- [ ] **Step 3: Gate + commit**

Run: `cargo nextest run -p mvm-cli -- resolve && cargo fmt --all -- --check`

```bash
git add crates/mvm-cli/src/commands/shared/resolve.rs
git commit -m "test(resolve): drop Vz workload enforcement/tier assertions (Plan 226 R1P1 WS-A)"
```

---

### Task 6: Verify macOS + Linux build and confirm the retained substrate is intact

Consolidation/verification task — no new deletions. Confirm the split state is coherent: Vz unselectable, persistent-builder substrate live.

- [ ] **Step 1: Full gate on both targets**

Run: `just ci && just check-linux`
Expected: green. (`check-linux` matters — Tasks 3/4 touched `cfg(target_os="linux")`-gated builder code such as `builder_health.rs`.)

- [ ] **Step 2: Confirm Vz is unselectable but the substrate is retained**

Run and record:
- `rg -n "AnyBackend::Vz|BackendKind::Vz|DevBackend::Vz|BuilderBackendChoice::Vz" crates/ src/` → expect ZERO (Vz unselectable as workload/dev/builder).
- `ls crates/mvm-backend/src/vz.rs crates/mvm-vm-host/src/bin/mvm-vz-supervisor.rs crates/mvm-build/src/vz_builder.rs` → expect all PRESENT (retained substrate).
- `rg -n "VzDevEnv" crates/mvm-backend/src/base/linux_env.rs` → expect PRESENT (the substrate to flip in 226-R1P1b).

- [ ] **Step 3: Commit (only if fmt/lint fixups were needed)**

```bash
git add -A
git commit -m "chore: verify Vz-unselectable split builds on macOS+Linux (Plan 226 R1P1)" || echo "nothing to commit"
```

---

### Task 7: Ratify ADR-098 (partial, workload-scoped) and update docs

**Files:** `specs/adrs/098-*.md`, `CLAUDE.md`, `public/src/content/docs/**`, `specs/REFACTOR-STATUS.md`

- [ ] **Step 1: ADR-098 — partial ratification**

Set `Status: Accepted (2026-07-06)`. Record precisely: the Vz **workload** backend is removed and macOS-26 defaults to in-house HVF for workloads, dev, and one-shot builds; the **persistent Vz builder VM remains the build ShellEnvironment substrate pending Plan 226-R1P1b** (flip to the retained libkrun persistent builder, validated). Warm-restore/save-restore tracked in 226-R1E; Linux convergence in 226-R2. Do NOT claim Vz is fully removed.

- [ ] **Step 2: Update CLAUDE.md + docs (accurately)**

In `CLAUDE.md`, change the Vz description to reflect reality: "Vz is no longer a selectable workload/dev backend (Plan 226 R1P1); it survives only as the macOS-26 persistent *builder* substrate pending Plan 226-R1P1b." Do NOT write "Vz removed" — it isn't yet. Prune only docs that claim Vz is a user-selectable workload/dev hypervisor. Keep `--builder`/builder-state-dir docs accurate to the retained substrate.

- [ ] **Step 3: Verify + close #1403**

`gh issue view 1403`; if fixed on main, `gh issue close 1403 --comment "Fixed on main (--builder inhouse selectable + macOS-26 auto-detect). Vz workload/dev/one-shot-builder selection removed in Plan 226 R1P1; persistent-builder substrate flip tracked in 226-R1P1b."`

- [ ] **Step 4: Rollup + gate + commit**

Update `specs/REFACTOR-STATUS.md` (Plan 226 R1P1 landed; note R1P1b pending). Run `just ci`.

```bash
git add specs/adrs CLAUDE.md public/src/content/docs specs/REFACTOR-STATUS.md
git commit -m "docs(adr-098): ratify HVF workload backend; Vz builder substrate pending R1P1b (Plan 226 R1P1)"
```

---

### Task 8: CHANGELOG (Unreleased) — no version bump this round

Under Option B, R1P1 does not fully remove Vz, so it does NOT cut v0.17.0. Record the change under an Unreleased heading; the version bump waits until 226-R1P1b completes the removal.

**Files:** `CHANGELOG.md`

- [ ] **Step 1: Add an Unreleased entry**

Add under `## [Unreleased]`: "Vz (Apple Virtualization.framework) is no longer a selectable workload, dev, or one-shot-builder backend on macOS — the in-house HVF VMM is the default and sole selectable path. `machine checkpoint/fork` full-VM mode is temporarily unsupported pending HVF save/restore (226-R1E); `fs_quick` checkpoints unaffected. The persistent Vz *builder* substrate is retained pending 226-R1P1b."

- [ ] **Step 2: Final gate + commit**

Run: `just ci && just check-linux`

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): record Vz workload/dev/builder removal (Plan 226 R1P1)"
```

---

## Self-Review (Option B)

- **Coverage:** WS-D → Task 1; WS-B → Task 2; WS-C (one-shot builder) → Task 3; WS-A (workload dispatch) → Task 4; residual/verify/docs → Tasks 5–8. The persistent-builder flip + physical file deletion + fuzz/witness retirement are DEFERRED to 226-R1P1b (not this plan) because the substrate is still live.
- **No premature deletion:** Tasks 5–8 delete no Vz source files and remove no fuzz targets/claim witnesses — those cover retained code.
- **Honesty:** docs/ADR/CHANGELOG state Vz is *unselectable*, not *removed*.

## Follow-on plans (write after this lands)

- **226-R1P1b — persistent-builder substrate flip + full Vz deletion (NEW, highest priority).** Flip `create_linux_env()` (macOS-26) off `VzDevEnv` onto the retained **libkrun** persistent builder; validate with a real `mvmctl build image` / `mvmctl dev up` on macOS-26; then delete `vz.rs`, `vz_control.rs`, `vz_objc.rs`, `host_gvproxy.rs`, `vz_builder.rs`, the `mvm-vz-supervisor` bin + objc2 deps, the Vz fuzz target/CI step, the `fn:vz_rootfs_disk_is_read_only` witness, and the `doctor.rs`/`cache.rs` Vz-builder state-dir handling. This is the task that makes Vz truly gone and cuts **v0.17.0**.
- **226-R1P2 — macOS libkrun→vsock egress + delete gvproxy (WS-N).** Foundation (`MVM_VSOCK_EGRESS`, #1483) landed flag-gated; flip the default on macOS, resolve builder egress, delete gvproxy.
- **226-R1E — HVF SaveRestore (WS-E).** Restores `machine checkpoint/fork` full-VM mode on the in-house VMM; Task 1's tracked error is then replaced.
- **226-R2 — Linux clean-replacement** (Firecracker→vsock + delete passt, validated on the Hetzner KVM box), after a fresh post-R1 code re-evaluation. Plan 227 (instant-resume sandboxes) is adjacent — reconcile during R2 scoping.

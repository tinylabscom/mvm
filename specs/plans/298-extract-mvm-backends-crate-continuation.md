# Plan 298 continuation: move concrete drivers into `mvm-backends`

**Status:** PR #2231 merged (commit `e4708a17c`). The `VmmDriver` seam, shared host helpers, and `mvm-backends` scaffolding are in place.

**Goal:** Finish separating *concrete VMM backend implementations* from *workload lifecycle orchestration* by moving the driver modules and legacy `VmBackend` shells into `mvm-backends`, then flipping `mvm-runtime` to depend on `mvm-backends`.

## What already landed

- `mvm-vmm` owns:
  - `VmmDriver` / `RunningVm` seam (`crates/mvm-vmm/src/driver/`)
  - `VmmSpec`, post-restore signal, primed-barrier helpers, `VmFullControl`, console capture
  - Shared host helpers in `mvm-vmm::host` (`host_agent_spawn`, `substitution_spawn`, `broker_services_spawn`, `netd_spawn`, `aux_bin`, `egress_shared`, `workload_wait`, `drive_file`, `process_liveness`, `boot_config`, `egress_bridge`)
- `mvm-backends` is scaffolded with `MockDriver` gated behind `test-support`.
- `mvm-runtime` and `mvm-build` compile via re-exports.

## Remaining work

### Phase 4 — Extract remaining shared dependencies

Before the concrete drivers can move, remove the last `mvm-runtime` reaches from their implementation. Candidates identified in `specs/plans/298-extract-mvm-backends-crate.md`:

- `libkrun::open_console_capture`
- `microvm` pause/resume helpers
- `base::runtime_meta`, `base::ui`
- backend-specific Firecracker snapshot helpers

For each dependency, choose one of:

1. **Move it down** to `mvm-vmm` (or `mvm-core`) if it is backend-agnostic.
2. **Parameterize the driver** so the orchestration layer injects the dependency instead of the driver importing it.
3. **Inline a minimal equivalent** in `mvm-backends` if the dependency is small and orchestration-specific.

Acceptance: `cargo check -p mvm-backends` compiles with a skeleton module that imports the four driver files, before those files are actually moved.

### Phase 5 — Move concrete driver modules

Move the driver implementations into `mvm-backends/src/`:

- `crates/mvm-runtime/src/driver/fc.rs` → `crates/mvm-backends/src/fc.rs`
- `crates/mvm-runtime/src/driver/libkrun.rs` → `crates/mvm-backends/src/libkrun.rs`
- `crates/mvm-runtime/src/driver/qemu.rs` → `crates/mvm-backends/src/qemu.rs`
- `crates/mvm-runtime/src/backends/hvf/driver.rs` → `crates/mvm-backends/src/hvf.rs`

Update their `use` statements to pull from `mvm-vmm` and `mvm-core` instead of `mvm-runtime`. Keep `mvm-runtime` compiling by re-exporting the moved drivers under their old paths during the transition (gated by `test-support` or unconditionally, depending on the desired final crate graph).

### Phase 6 — Move legacy `VmBackend` implementations

Move the backend shells that `AnyBackend` dispatches to:

- `crates/mvm-runtime/src/backends/hvf/` → `crates/mvm-backends/src/backends/hvf/`
- `crates/mvm-runtime/src/backends/firecracker/` (if present)
- Any remaining `FirecrackerBackend`, `LibkrunBackend`, `QemuBackend` modules.

These depend on the concrete drivers moved in Phase 5, so they must follow them into `mvm-backends`.

### Phase 7 — Flip the dependency

1. Add `mvm-backends` as a dependency of `mvm-runtime`.
2. Remove the local driver/backend source files from `mvm-runtime`.
3. Update `AnyBackend` / `selection.rs` to import from `mvm-backends`.
4. Remove the temporary re-exports.

Final crate graph:

```text
mvm-runtime
    |
    v
mvm-backends
    |
    v
mvm-vmm
```

## Verification

Run these before opening the next PR:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy -p mvm-conformance --tests --features bdd -- -D warnings`
- `cargo test -p xtask`
- `cargo run -p xtask -- check-claim-catalog`
- `cargo run -p xtask -- check-mutation-witnesses`
- `cargo run -p xtask -- check-require-grant-token-allowlist`
- `cargo run -p xtask -- check-closure-budget` (ratchet; expect to justify any increase)

## Suggested worktree

```bash
cd /Users/auser/work/tinylabs/mvmco/mvm
git worktree add ../.worktrees/mvm-298-move-drivers -b feat/298-move-drivers
cd ../.worktrees/mvm-298-move-drivers
source scripts/dev-env.sh
```

## Notes for the next session

- Start with Phase 4: identify the smallest dependency that blocks compiling a skeleton `mvm-backends` driver module and move/parameterize it.
- Do **not** move all drivers in one giant commit; prefer one commit per dependency/driver pair so the diff stays reviewable.
- Keep `mvm-runtime` green after every commit; use re-exports as temporary scaffolding.
- Update this plan file and `specs/REFACTOR-STATUS.md` as each phase completes.

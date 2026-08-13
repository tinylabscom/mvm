# Task: Backend shim removal — invert the driver/backend relationship (Plan 269)

## Goal

Make `VmmDriver` the sole owner of per-VMM mechanics. Delete the legacy direct
`VmBackend` implementations (`FirecrackerBackend`, `HvfBackend`,
`LibkrunBackend`, `QemuBackend`) in `crates/mvm-backends/src/legacy/`. Every
workload backend must reach production through
`WorkloadRunner<D: VmmDriver, ...>`.

## Why

`mvm-backends/src/legacy/` contains old `VmBackend` trait shells that the new
`VmmDriver` implementations still wrap. This is unfinished debt from Plan 298.
It causes confusing naming (HVF is not legacy), duplicates VMM mechanics, and
hosts the parallel test flake in `legacy/hvf.rs`
(`terminate_pid_reaps_child_without_grace_timeout`,
`terminate_pid_escalates_when_sigterm_is_ignored`).

## Read before writing

- `specs/plans/269-backend-shim-removal.md` (authoritative plan)
- `specs/plans/recovery-open-work-2026-08-12.md` Phase 4 (where this fits)
- `crates/mvm-backends/src/legacy/mod.rs` and `legacy/{hvf,libkrun,qemu}.rs`
- `crates/mvm-backends/src/driver/{hvf,libkrun,fc,qemu}.rs`
- `crates/mvm-vmm/src/driver/traits.rs` (`VmmDriver` trait)
- `crates/mvm-core/src/protocol/vm_backend.rs` (`VmBackend` trait)
- `crates/mvm-runtime/src/backend.rs` (`AnyBackend`, runners)
- `crates/mvm-runtime/src/workload_backend.rs`
- `crates/mvm-runtime/src/codesign.rs`
- `crates/mvm-runtime/src/builder_runner/inject.rs`
- `crates/mvm-cli/src/commands/qemu_bridge.rs`

## Known gaps to resolve first

Plan 269 was drafted before tree-checking. These are wrong or unstated:

1. There is **no** blanket `impl VmBackend for WorkloadRunner<D: VmmDriver, ...>`
   yet — build it first (call this Task 0).
2. `WasmBackend` is unaccounted for — decide explicitly whether it becomes a
   `VmmDriver`, stays a documented `VmBackend` exception, or is out of scope.
3. `specs/SPRINT.md` §2.5 contradicts itself on QEMU — settle the text before
   touching `qemu.rs`.
4. Re-run the inventory greps at the start, not just the end.

## Worktree setup (per AGENTS.md)

From the main `mvm/` checkout:

```bash
cd /Users/auser/work/tinylabs/mvmco/mvm
git worktree add ../.worktrees/mvm-backend-shim-removal -b feat/269-backend-shim-removal
```

Do all code work inside `../.worktrees/mvm-backend-shim-removal/`. Run git
commands only from the main checkout with
`git -C ../.worktrees/mvm-backend-shim-removal`.

Use isolated env when running tests:

```bash
cd ../.worktrees/mvm-backend-shim-removal
source scripts/dev-env.sh
```

(Equivalently: `MVM_HOME="$PWD/.mvm-test" CARGO_TARGET_DIR="$PWD/.mvm-test/target" CARGO_HOME="$PWD/.mvm-test/cargo`.)

## Task order

1. Inventory every call from new drivers into old backends and every external
   caller of old backends. Write `MIGRATION-269.md` in the worktree root.
2. Build the blanket `impl VmBackend for WorkloadRunner<D: VmmDriver, ...>`.
3. Absorb `FirecrackerBackend` into `FcDriver`.
4. Absorb `LibkrunBackend` into `LibkrunDriver`; migrate builder VM off
   `LibkrunBackend::start`.
5. Absorb `HvfBackend` into `HvfDriver`; update `WorkloadBackend` impl.
6. Decide and execute on QEMU per settled `specs/SPRINT.md` text.
7. Consolidate `AnyBackend` and selection to hold only runner-backed variants.
8. Verify no remaining raw-backend references with:
   ```bash
   rg "FirecrackerBackend\b|HvfBackend\b|LibkrunBackend\b|QemuBackend\b" crates/ --type rust
   rg "impl VmBackend for" crates/ --type rust
   ```
9. Run `cargo xtask check-claim-catalog`, `just bdd`, and Linux builder-VM gates.

## Constraints

- Behavior-preserving refactor only. No workload-visible change, no capability
  matrix change, no security-claim weakening.
- No `#[allow(...)]` clippy suppressions. Fix the lint instead.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments.
- No `unwrap()` in production code; use `.expect("...")`.
- Keep `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`, and
  `specs/plans/recovery-open-work-2026-08-12.md` in sync as tasks complete.
- No AI-tool attribution in commits or PR body.

## Acceptance gate

- `cargo nextest run --workspace` green on macOS host.
- `cargo clippy --workspace --all-targets -- -D warnings` green.
- `cargo xtask check-claim-catalog` green.
- `just bdd` green.
- Linux all-target clippy/tests and live backend witnesses run in the builder VM.
- No production code references `FirecrackerBackend`, `HvfBackend`,
  `LibkrunBackend`, or `QemuBackend` as raw `VmBackend` impls.
- `mvm-backends/src/legacy/` deleted.
- Every selectable workload backend is a `WorkloadRunner<D: VmmDriver, ...>`,
  with any `WasmBackend` exception documented.

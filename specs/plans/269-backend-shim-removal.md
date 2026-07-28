# Backend shim removal — invert the driver/backend relationship

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `VmmDriver` the sole owner of per-VMM mechanics, delete the legacy direct `VmBackend` implementations (`FirecrackerBackend`, `HvfBackend`, `LibkrunBackend`, `QemuBackend`), and have every workload backend reach production through `WorkloadRunner<D: VmmDriver, ...>`.

**Architecture:** Today the new `VmmDriver` seam (`FcDriver`, `HvfDriver`, `LibkrunDriver`) wraps an older direct `VmBackend` implementation (`FirecrackerBackend`, `HvfBackend`, `LibkrunBackend`). The old implementations still contain real VMM mechanics and are used by tests, examples, the builder VM, and internal driver delegate methods. This inversion moves the VMM mechanics *into* the drivers, deletes the old impls, and leaves only one `VmBackend` surface: the blanket `impl VmBackend for WorkloadRunner<D: VmmDriver, ...>`.

**Tech Stack:** Rust (`mvm-runtime`, `mvm-build`), Nix (builder VM), `cargo nextest`, `cargo clippy --workspace -- -D warnings`.

## Status and known gaps — read before starting

This plan was drafted before it was checked against the tree. The core premise
holds: `driver/fc.rs`, `driver/libkrun.rs`, and `driver/hvf.rs` each still
reference the old backend types, so the inversion is genuinely undone and worth
doing. Four things below are wrong or unstated in the task list as written.
Resolve them first rather than discovering them mid-Task-2.

- **The end-state seam does not exist yet.** The Architecture paragraph above
  describes "the blanket `impl VmBackend for WorkloadRunner<D: VmmDriver, ...>`"
  as if it were present. It is not — there is no `impl VmBackend for
  WorkloadRunner` anywhere in the tree. Task 6 and Task 7 Step 2 are written
  against a target that has to be *built* first. Treat creating that blanket
  impl as **Task 0**, before absorbing any mechanics into a driver.

- **`WasmBackend` is unaccounted for.** It implements `VmBackend`
  (`crates/mvm-runtime/src/wasm_backend.rs`) and this plan never mentions it,
  yet `specs/SPRINT.md` §2.5 lists wasm as a core-goal backend. Task 7 Step 2's
  grep would flag it as a violation with no guidance. Decide explicitly whether
  wasm becomes a `VmmDriver`, stays a direct `VmBackend` impl as a documented
  exception, or is out of scope — and record the decision in the acceptance
  gate before running that grep.

- **SPRINT.md contradicts itself on QEMU, which Task 5 depends on.** §2.5 says
  QEMU is "**dropped**", while the WS1e line in the same file says the drop was
  "ratified **against**: QEMU stays a Tier-2 dev/test backend, never
  workload-bearing", and `qemu.rs` is still present. Task 5 cannot be executed
  against a self-contradicting source. Settle the sprint text first; deleting
  `QemuBackend` on the strength of §2.5 alone would remove a backend the sprint
  intends to keep.

- **Verify the inventory before trusting it.** Task 1 produces the contract for
  everything after it. The counts above were taken at the time this note was
  written; re-run the greps in Task 7 Step 1 and 2 at the start, not just the
  end, so the plan is re-anchored to the tree it is actually running against.

## Global Constraints

- Work in a dedicated worktree (e.g., `../.worktrees/mvm-backend-shim-removal`) on branch `feat/268-backend-shim-removal`; git via `git -C <wt-abs>`.
- **Behavior-preserving refactor:** no workload-visible behavior change, no capability-matrix change, no security-claim weakening.
- Security witnesses stay green: verified boot, signed plan admission, default-deny egress, no `do_exec`/console in prod agent, broker binding, secret substitution.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs`); reword to the concept. Spec docs may reference them.
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push; `cargo nextest run --workspace` green before any task is marked done.
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or PR body.
- QEMU is explicitly out of scope for this plan unless the active sprint reverts its "dropped" decision; check `specs/SPRINT.md` §2.5 before touching `qemu.rs`.

---

## Task 1: Inventory and lock the migration boundary

**Files:**
- Read: `crates/mvm-runtime/src/backend.rs`, `crates/mvm-runtime/src/libkrun.rs`, `crates/mvm-runtime/src/hvf_backend.rs`, `crates/mvm-runtime/src/qemu.rs`
- Read: `crates/mvm-runtime/src/driver/fc.rs`, `crates/mvm-runtime/src/driver/libkrun.rs`, `crates/mvm-runtime/src/driver/hvf.rs`
- Read: `crates/mvm-build/src/libkrun_builder.rs`, `crates/mvm-runtime/tests/libkrun_lifecycle_e2e.rs`, `crates/mvm-runtime/examples/*`

**Interfaces:**
- Produces: a written inventory of every method call from the new drivers into the old backends and every external caller of the old backends.
- Consumes: the current `VmBackend` trait definition and `VmmDriver` trait definition.

- [ ] **Step 1: Map driver → old-backend delegation**

  For each driver, list which `FirecrackerBackend` / `LibkrunBackend` / `HvfBackend` methods it calls (capabilities, security profile, availability, status, stop, etc.).

- [ ] **Step 2: Map external old-backend callers**

  Find every non-driver caller: builder VM, tests, examples, `AnyBackend` dispatch, `selection.rs`, `workload_backend.rs`. Note which methods they use.

- [ ] **Step 3: Classify each method as "move to driver" or "delete"**

  Methods used only by the driver → move into the driver. Methods used by tests/examples → rewrite against the driver or `WorkloadRunner`. Methods used by builder → decide if builder can use `LibkrunDriver` + `WorkloadRunner` or needs a narrower builder seam.

- [ ] **Step 4: Commit the inventory**

  Add a short markdown note in the worktree root (`MIGRATION-268.md`) listing the classification. This is the contract for the rest of the plan.

---

## Task 2: Absorb `FirecrackerBackend` into `FcDriver`

**Files:**
- `crates/mvm-runtime/src/driver/fc.rs` — absorb `boot`, `attach`, `wait`, `kill`, `pause`, `resume`, `guest_channel_info`, capability/profile/availability accessors.
- `crates/mvm-runtime/src/backend.rs` — stop storing a `FirecrackerBackend` inside `FcDriver`; remove the raw `FirecrackerBackend` `VmBackend` impl or mark it deprecated behind a feature gate.
- `crates/mvm-runtime/src/microvm/mod.rs` and `crates/mvm-runtime/src/microvm/*` — ensure the FC microvm helpers remain usable from the driver.

**Interfaces:**
- Produces: `FcDriver` owns all FC mechanics; `FirecrackerBackend` type deleted or reduced to a zero-sized token.
- Consumes: existing `microvm` primitives (`start_vm_firecracker`, API client, etc.).

- [ ] **Step 1: Inline capability, profile, and availability**

  Replace `self.backend.capabilities()` / `self.backend.security_profile()` / `self.backend.is_available()` with local `FcDriver` implementations. The values must match the current matrix exactly.

- [ ] **Step 2: Inline `boot`, `attach`, `wait`, `kill`, `pause`, `resume`, `guest_channel_info`**

  Move the relevant logic from `FirecrackerBackend` into `FcDriver`. Preserve the existing `RunningVm` handle shape.

- [ ] **Step 3: Update `AnyBackend::Firecracker` to use `FcRunner` only**

  Ensure `AnyBackend::Firecracker` holds `FcRunner` and no path constructs a raw `FirecrackerBackend` for workload execution.

- [ ] **Step 4: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-runtime
  cargo clippy -p mvm-runtime -- -D warnings
  ```

- [ ] **Step 5: Commit**

  ```bash
  git -C <wt> commit -m "refactor(runtime): move Firecracker mechanics into FcDriver"
  ```

---

## Task 3: Absorb `LibkrunBackend` into `LibkrunDriver`

**Files:**
- `crates/mvm-runtime/src/driver/libkrun.rs` — absorb mechanics.
- `crates/mvm-runtime/src/libkrun.rs` — the legacy impl to delete.
- `crates/mvm-build/src/libkrun_builder.rs` — builder uses `LibkrunBackend::start`; this must be migrated.

**Interfaces:**
- Produces: `LibkrunDriver` owns all libkrun mechanics; builder uses either `LibkrunDriver` or a dedicated `BuilderVm` path.
- Consumes: `libkrun-sys` FFI surface.

- [ ] **Step 1: Inline libkrun capability/profile/availability into `LibkrunDriver`**

- [ ] **Step 2: Inline `boot`, `attach`, `wait`, `kill`, `pause`, `resume`, `guest_channel_info` into `LibkrunDriver`**

- [ ] **Step 3: Migrate builder VM off `LibkrunBackend::start`**

  Decide: can the builder use `LibkrunDriver` + a minimal `VmmSpec`, or does it need a separate `BuilderVm` trait? Per ADR-007, builder stays a separate role. If the builder currently reaches into `LibkrunBackend` only for spawn/stop/status, create a thin builder-facing wrapper around `LibkrunDriver` or extend the existing `BuilderVm` impl.

- [ ] **Step 4: Rewrite tests and examples**

  `mvm-runtime/tests/libkrun_lifecycle_e2e.rs` and any examples using `LibkrunBackend` directly should use `LibkrunDriver` through `WorkloadRunner` or a test helper.

- [ ] **Step 5: Delete `crates/mvm-runtime/src/libkrun.rs` if no references remain**

- [ ] **Step 6: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-runtime -p mvm-build
  cargo clippy -p mvm-runtime -p mvm-build -- -D warnings
  ```

- [ ] **Step 7: Commit**

---

## Task 4: Absorb `HvfBackend` into `HvfDriver`

**Files:**
- `crates/mvm-runtime/src/driver/hvf.rs` — absorb mechanics.
- `crates/mvm-runtime/src/hvf_backend.rs` — the legacy impl to delete.
- `crates/mvm-runtime/src/workload_backend.rs` — `HvfBackend` implements `WorkloadBackend`; update to delegate to `HvfDriver`/`WorkloadRunner`.

**Interfaces:**
- Produces: `HvfDriver` owns all HVF mechanics.
- Consumes: HVF supervisor process model, `HvfSupervisorConfig`.

- [ ] **Step 1: Inline HVF capability/profile/availability into `HvfDriver`**

- [ ] **Step 2: Inline `boot`, `attach`, `wait`, `kill`, `pause`, `resume`, `guest_channel_info` into `HvfDriver`**

- [ ] **Step 3: Update `WorkloadBackend` impl**

  Change `impl WorkloadBackend for HvfBackend` to delegate to `HvfDriver` or `HvfRunner`.

- [ ] **Step 4: Rewrite examples**

  `hvf-backend-run.rs`, `hvf-agent-ping.rs`, `hvf-backend-transient.rs`, `hvf-workload-runner.rs` — update to use `HvfDriver` / `HvfRunner`.

- [ ] **Step 5: Delete `crates/mvm-runtime/src/hvf_backend.rs` if no references remain**

- [ ] **Step 6: Run tests and clippy**

- [ ] **Step 7: Commit**

---

## Task 5: Decide and execute on QEMU

**Files:**
- `crates/mvm-runtime/src/qemu.rs`
- `crates/mvm-runtime/src/selection.rs`
- `crates/mvm-runtime/src/backend.rs`

**Interfaces:**
- Produces: either a `QemuDriver` that implements `VmmDriver`, or QEMU removed from workload backends.

- [ ] **Step 1: Confirm sprint decision**

  Re-read `specs/SPRINT.md` §2.5. If QEMU is dropped, remove `QemuBackend` and `AnyBackend::Qemu`. If it is kept as a dev substrate, either create `QemuDriver` or leave it as a non-workload path.

- [ ] **Step 2: Execute the confirmed decision**

- [ ] **Step 3: Commit**

---

## Task 6: Consolidate `AnyBackend` and selection

**Files:**
- `crates/mvm-runtime/src/backend.rs`
- `crates/mvm-runtime/src/selection.rs`

**Interfaces:**
- Produces: `AnyBackend` holds only runner-backed `VmBackend` impls; no raw backend variants.

- [ ] **Step 1: Remove raw backend variants from `AnyBackend`**

  Keep only `Firecracker(FcRunner)`, `Libkrun(LibkrunRunner)`, `Hvf(HvfRunner)`, `Mock(MockBackend)`, and any decided QEMU path.

- [ ] **Step 2: Update `from_hypervisor`, `auto_select`, `for_started_vm`**

  Ensure all dispatch sites construct the runner-backed variants.

- [ ] **Step 3: Delete dead helper methods on raw backends**

- [ ] **Step 4: Run workspace tests and clippy**

  ```bash
  cargo nextest run --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  ```

- [ ] **Step 5: Commit**

---

## Task 7: Verify no remaining raw-backend references

**Files:** entire workspace.

- [ ] **Step 1: Grep for raw backend names**

  ```bash
  rg "FirecrackerBackend\b|HvfBackend\b|LibkrunBackend\b|QemuBackend\b" crates/ --type rust
  ```

  Only permitted hits: module-level re-exports that still exist for backward compat (if any), or intentional references inside the migration note. Any production-path reference is a bug.

- [ ] **Step 2: Check that `VmBackend` is implemented only by `WorkloadRunner` and `MockBackend`**

  ```bash
  rg "impl VmBackend for" crates/ --type rust
  ```

  Expected: `WorkloadRunner`, `MockBackend`, and test doubles only.

- [ ] **Step 3: Commit the cleanup**

---

## Task 8: Claims-catalog and security witness check

- [ ] **Step 1: Run `cargo xtask check-claim-catalog`** and ensure no witness drifted.

- [ ] **Step 2: Run BDD/conformance tests** if `just bdd` is available.

- [ ] **Step 3: Open PR** with a concise description of the refactor and the verification performed.

---

## Acceptance gate

- `cargo nextest run --workspace` green.
- `cargo clippy --workspace --all-targets -- -D warnings` green.
- `cargo xtask check-claim-catalog` green.
- No production code references `FirecrackerBackend`, `HvfBackend`, `LibkrunBackend`, or `QemuBackend`.
- Every selectable workload backend is a `WorkloadRunner<D: VmmDriver, ...>`,
  except any backend explicitly exempted by the `WasmBackend` decision recorded
  under "Status and known gaps". An unexplained extra `impl VmBackend` fails
  this gate; a documented exemption does not.
- The QEMU disposition matches a `specs/SPRINT.md` that no longer contradicts
  itself.
- Security claims in ADR-001 are unchanged or strengthened.

# Extract `mvm-backends` crate from `mvm-runtime`

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate *concrete VMM backend implementations* from *workload lifecycle orchestration*. After this refactor:

- `mvm-vmm` owns the backend-agnostic VMM device model **and** the high-level `VmmDriver` seam.
- `mvm-backends` owns the concrete `VmmDriver` implementations (Firecracker, HVF, libkrun, QEMU, Mock) plus the legacy `VmBackend` implementations they still delegate to.
- `mvm-runtime` owns `WorkloadRunner`, `AnyBackend` dispatch, machine lifecycle, snapshots, builder-runner orchestration, and the role policy that sits above the driver seam.
- `mvm-build` stops being a runtime dependency of the QEMU/libkrun backends; the shared `virtiofsd` host helper moves down into `mvm-vmm`.

**Prerequisite:** PR #2220 (`feat/backend-crate-separation`) must be merged first. That PR extracted the portable device model into `mvm-vmm`; this plan moves the driver seam and the concrete drivers out of `mvm-runtime`.

**Tech Stack:** Rust workspace, `cargo nextest`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo xtask check-claim-catalog`.

**Branch:** `feat/298-extract-mvm-backends`  
**Worktree:** `../.worktrees/mvm-298-extract-mvm-backends`

## Target crate graph

```text
mvm-runtime (orchestration: WorkloadRunner, AnyBackend, machine, snapshot)
    |
    v
mvm-backends (FcDriver, HvfDriver, LibkrunDriver, QemuDriver, MockDriver,
              plus the legacy VmBackend impls they still wrap)
    |
    v
mvm-vmm (device model + VmmDriver trait + VmmSpec + virtiofsd host helper)
    |
    +--> mvm-core
    +--> mvm-net
    +--> mvm-agentd

mvm-build (builder VM, image packaging, artifact verify)
    |
    +--> mvm-vmm   (for virtiofsd helper)
    +--> mvm-runtime
```

The key invariant is that `mvm-backends` sits *below* `mvm-runtime`. That only works if the `VmmDriver` trait, `VmmSpec`, and the `RunningVm` handle live in `mvm-vmm`, because today `mvm-runtime` defines that seam and the drivers implement it.

## Global Constraints

- Work in a dedicated worktree (`../.worktrees/mvm-298-extract-mvm-backends`) on branch `feat/298-extract-mvm-backends`; git via `git -C <wt-abs>`.
- **Behavior-preserving refactor:** no workload-visible behavior change, no capability-matrix change, no security-claim weakening.
- Security witnesses stay green: verified boot, signed plan admission, default-deny egress, no `do_exec`/console in prod agent, broker binding, secret substitution.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs`); reword to the concept. Spec docs may reference them.
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push; `cargo nextest run --workspace` green before any task is marked done.
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or PR body.
- `WasmBackend` is out of scope for this plan; it stays in its current location.

---

## Task 1: Survey and lock the migration boundary

**Files to read:**
- `crates/mvm-runtime/src/driver/mod.rs`
- `crates/mvm-runtime/src/driver/traits.rs`
- `crates/mvm-runtime/src/driver/spec.rs`
- `crates/mvm-runtime/src/driver/fc.rs`
- `crates/mvm-runtime/src/driver/hvf.rs`
- `crates/mvm-runtime/src/driver/libkrun.rs`
- `crates/mvm-runtime/src/driver/qemu.rs`
- `crates/mvm-runtime/src/driver/mock.rs`
- `crates/mvm-runtime/src/backend.rs`
- `crates/mvm-runtime/src/libkrun.rs`
- `crates/mvm-runtime/src/backends/hvf/backend.rs`
- `crates/mvm-runtime/src/qemu.rs`
- `crates/mvm-build/src/virtiofsd.rs`
- `crates/mvm-vmm/src/lib.rs`

**Interfaces:**
- Produces: a written boundary note (`MIGRATION-298.md`) listing every type that must move and where it lands.
- Consumes: the current `VmmDriver` trait and `VmmSpec` definition.

- [x] **Step 1: Inventory the driver seam**

  List every type referenced by `VmmDriver` and its default methods:
  `VmmSpec`, `VsockPort`, `KernelImage`, `BlockDev`, `VirtioFsShare`,
  `ConsoleCapture`, `ChildForkRequest`, `StandbyParentSpawn`, `RunningVm`,
  `DuplexStream`, `PostRestoreOutcome`, `VmFullControl`.

- [x] **Step 2: Inventory the legacy backend impls**

  List `FirecrackerBackend`, `HvfBackend`, `LibkrunBackend`, `QemuBackend`,
  and every caller (drivers, tests, examples, builder VM). Note which
  methods drivers still delegate to.

- [x] **Step 3: Decide the `virtiofsd` helper location**

  The QEMU driver and the builder VM both need `virtiofsd`. Options:
  - Move it into `mvm-vmm` under a `host` module (recommended).
  - Keep it in `mvm-build` and accept that `mvm-backends` depends on `mvm-build`
    (creates a cycle because `mvm-build` depends on `mvm-runtime`, which will
    depend on `mvm-backends`). So this is only viable if `mvm-build`'s runtime
    dependency is inverted first — do not choose without explicit approval.

- [x] **Step 4: Decide `MockBackend` location**

  It is a test-only backend. Either move it into `mvm-backends` under a
  `test-support` feature or keep a minimal mock in `mvm-runtime` tests.
  Record the decision in `MIGRATION-298.md`.

---

## Task 2: Move the driver seam into `mvm-vmm`

**Files:**
- `crates/mvm-vmm/src/lib.rs`, `crates/mvm-vmm/Cargo.toml`
- `crates/mvm-runtime/src/driver/traits.rs`
- `crates/mvm-runtime/src/driver/spec.rs`
- `crates/mvm-runtime/src/vm/instance_snapshot.rs`
- `crates/mvm-runtime/src/checkpoint/mod.rs`

**Interfaces:**
- Produces: `mvm-vmm` owns `VmmDriver`, `VmmSpec`, `RunningVm`, and related types.
- Consumes: `mvm_core::vm_backend::*`, `mvm_core::crypto::vmgenid::*`, `mvm_net::channel::GuestService`.

- [x] **Step 1: Create `mvm-vmm::driver` and `mvm-vmm::spec` modules**

  Move `VmmSpec` + types into `mvm-vmm::spec` and the `VmmDriver`/`RunningVm`
  traits + request structs into `mvm-vmm::driver`. Add `mvm_net` to
  `mvm-vmm/Cargo.toml`.

- [x] **Step 2: Move shared snapshot/checkpoint types**

  Move `PostRestoreOutcome` (from `mvm-runtime::vm::instance_snapshot`) and
  the `VmFullControl` trait (from `mvm-runtime::checkpoint`) into `mvm-vmm`.
  These are backend-agnostic seam types and belong with the driver contract.

- [x] **Step 3: Resolve `deliver_child_identity` default impl**

  The default implementation calls `mvm-runtime::vm::instance_snapshot::signal_post_restore`,
  which is a runtime helper. Options:
  - Move `signal_post_restore` and the host→agent post-restore dispatcher into
    `mvm-vmm` (preferred if it does not drag runtime policy).
  - Remove the default method and provide a runtime-provided extension trait
    or wrapper that fills it in.
  Record the chosen shape in `MIGRATION-298.md`.

- [x] **Step 4: Keep `mvm-runtime` compiling with re-exports**

  Re-export the moved types from `mvm-runtime::driver` so callers inside
  `mvm-runtime` can be updated incrementally. These re-exports are deleted in
  Task 5.

- [x] **Step 5: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-runtime -p mvm-vmm
  cargo clippy -p mvm-runtime -p mvm-vmm -- -D warnings
  ```

- [x] **Step 6: Commit**

  ```bash
  git -C <wt> commit -m "refactor(vmm): move VmmDriver seam and VmmSpec into mvm-vmm"
  ```

---

## Task 3: Relocate the host `virtiofsd` helper

**Files:**
- `crates/mvm-build/src/virtiofsd.rs`
- `crates/mvm-build/src/qemu_builder.rs`
- `crates/mvm-vmm/src/lib.rs`
- `crates/mvm-vmm/Cargo.toml`

**Interfaces:**
- Produces: `mvm-vmm` provides the host `virtiofsd` spawn helper; `mvm-build`
  re-exports or wraps it for builder-VM use.

- [x] **Step 1: Move the module into `mvm-vmm`**

  Move `crates/mvm-build/src/virtiofsd.rs` to `crates/mvm-vmm/src/host/virtiofsd.rs`
  (or `mvm-vmm/src/virtiofsd.rs` if a `host` module does not yet exist).

- [x] **Step 2: Update `mvm-build` callers**

  `mvm-build/src/qemu_builder.rs` and any other builder callers should import
  from `mvm_vmm::virtiofsd` instead of `crate::virtiofsd`.

- [x] **Step 3: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-build -p mvm-vmm
  cargo clippy -p mvm-build -p mvm-vmm -- -D warnings
  ```

- [x] **Step 4: Commit**

  ```bash
  git -C <wt> commit -m "refactor(vmm): move virtiofsd host helper into mvm-vmm"
  ```

---

## Task 4: Create `mvm-backends` and move the drivers + legacy backends

**Files:**
- New `crates/mvm-backends/Cargo.toml`
- New `crates/mvm-backends/src/lib.rs`
- `crates/mvm-runtime/src/driver/*.rs`
- `crates/mvm-runtime/src/backend.rs`
- `crates/mvm-runtime/src/libkrun.rs`
- `crates/mvm-runtime/src/backends/hvf/backend.rs`
- `crates/mvm-runtime/src/qemu.rs`
- `crates/mvm-runtime/src/selection.rs`
- `crates/mvm-runtime/Cargo.toml`

**Interfaces:**
- Produces: `mvm-backends` crate with the concrete backend implementations.
- Consumes: `mvm-vmm` (driver seam + device model), `mvm-core`, `mvm-net`, `mvm-build` is no longer needed.

- [x] **Step 1: Scaffold `mvm-backends`**

  Create `crates/mvm-backends/Cargo.toml` with dependencies on `mvm-vmm`,
  `mvm-core`, `mvm-net`, `mvm-agentd`, and whatever small third-party crates
  the drivers use (`anyhow`, `serde`, `tokio`, etc.). Do **not** depend on
  `mvm-runtime` or `mvm-build`.

- [ ] **Step 2: Move driver modules**

  Move `driver/fc.rs`, `driver/hvf.rs`, `driver/libkrun.rs`, `driver/qemu.rs`,
  and `driver/mock.rs` into `crates/mvm-backends/src/`. Preserve module paths
  with `pub mod fc`, `pub mod hvf`, `pub mod libkrun`, `pub mod qemu`,
  `pub mod mock`.

- [ ] **Step 3: Move legacy backend impls**

  Move the types and `VmBackend` impls from:
  - `mvm-runtime/src/backend.rs` → `mvm-backends/src/firecracker_backend.rs`
  - `mvm-runtime/src/libkrun.rs` → `mvm-backends/src/libkrun_backend.rs`
  - `mvm-runtime/src/backends/hvf/backend.rs` → `mvm-backends/src/hvf_backend.rs`
  - `mvm-runtime/src/qemu.rs` → `mvm-backends/src/qemu_backend.rs`

  Update imports so each legacy backend compiles inside `mvm-backends`.

- [ ] **Step 4: Move backend selection helpers if needed**

  `selection.rs` dispatches over backend kinds. The *selection logic* stays in
  `mvm-runtime`; the per-backend constructors move to `mvm-backends`. Add a
  small `mvm-backends::registry` module if it makes the dispatch cleaner.

- [x] **Step 5: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-backends -p mvm-vmm
  cargo clippy -p mvm-backends -p mvm-vmm -- -D warnings
  ```

- [x] **Step 6: Commit**

  ```bash
  git -C <wt> commit -m "refactor(backends): create mvm-backends crate and move drivers + legacy backends"
  ```

---

## Task 5: Update `mvm-runtime` to depend on `mvm-backends`

**Files:**
- `crates/mvm-runtime/src/lib.rs`
- `crates/mvm-runtime/src/driver/mod.rs`
- `crates/mvm-runtime/src/selection.rs`
- `crates/mvm-runtime/src/workload_backend.rs`
- `crates/mvm-runtime/src/backends/mod.rs`
- `crates/mvm-runtime/Cargo.toml`

**Interfaces:**
- Produces: `mvm-runtime` no longer contains driver or raw backend source;
  it imports them from `mvm-backends`.

- [ ] **Step 1: Add `mvm-backends` dependency and remove driver source files**

  Add `mvm-backends = { workspace = true }` to `crates/mvm-runtime/Cargo.toml`.
  Delete `crates/mvm-runtime/src/driver/*.rs` (except the re-export shim) and
  the legacy backend files moved in Task 4.

- [ ] **Step 2: Re-export the driver surface from `mvm-backends`**

  Keep the public paths stable where possible:
  - `mvm_runtime::driver::VmmDriver` → `pub use mvm_vmm::driver::VmmDriver;`
  - `mvm_runtime::driver::FcDriver` → `pub use mvm_backends::fc::FcDriver;`
  - etc.

  This minimizes churn in downstream callers. Mark these re-exports with a
  `// Re-exported while consumers migrate` comment; do not keep them forever.

- [ ] **Step 3: Update `AnyBackend` / `selection.rs`**

  Ensure `AnyBackend` holds runner-backed variants and constructs drivers from
  `mvm-backends`, not from local modules.

- [ ] **Step 4: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-runtime -p mvm-backends
  cargo clippy -p mvm-runtime -p mvm-backends -- -D warnings
  ```

- [ ] **Step 5: Commit**

  ```bash
  git -C <wt> commit -m "refactor(runtime): depend on mvm-backends and remove local driver modules"
  ```

---

## Task 6: Update `mvm-build` and remaining consumers

**Files:**
- `crates/mvm-build/src/qemu_builder.rs`
- `crates/mvm-build/src/lib.rs`
- `crates/mvm-build/Cargo.toml`
- Examples and tests that import driver types directly.

- [ ] **Step 1: Update `mvm-build` imports**

  Switch from `crate::virtiofsd` to `mvm_vmm::virtiofsd`. Remove the local
  module.

- [ ] **Step 2: Update examples and tests**

  Find direct imports of `mvm_runtime::driver::*` or raw backend types in
  `crates/mvm-runtime/examples/` and `crates/mvm-runtime/tests/`. Route them
  through `mvm_backends` or the stable `mvm_runtime` re-exports.

- [ ] **Step 3: Run workspace tests and clippy**

  ```bash
  cargo nextest run --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  ```

- [x] **Step 4: Commit**

  ```bash
  git -C <wt> commit -m "refactor(workspace): update consumers for mvm-backends and mvm-vmm virtiofsd"
  ```

---

## Task 7: Verify security witnesses and claim catalog

- [ ] **Step 1: Run `cargo xtask check-claim-catalog`** and ensure no witness drifted.

- [ ] **Step 2: Run the dormant-controls check** if it is not already part of CI:

  ```bash
  cargo xtask check-dormant-controls
  ```

- [ ] **Step 3: Run BDD/conformance tests** if `just bdd` is available.

---

## Task 8: Docs, rollup, and PR

- [ ] **Step 1: Update `specs/SPRINT.md`** with a concise bullet for the completed work.

- [ ] **Step 2: Update `specs/REFACTOR-STATUS.md`** with the new workstream and PR link.

- [ ] **Step 3: Delete `MIGRATION-298.md`** or fold its boundary notes into the plan doc.

- [ ] **Step 4: Open PR** with a concise description of the new crate boundaries and verification performed.

---

## Acceptance gate

- `cargo nextest run --workspace` green.
- `cargo clippy --workspace --all-targets -- -D warnings` green.
- `cargo xtask check-claim-catalog` green.
- `mvm-runtime` no longer contains `driver/fc.rs`, `driver/hvf.rs`, `driver/libkrun.rs`, `driver/qemu.rs`, or the legacy `FirecrackerBackend` / `HvfBackend` / `LibkrunBackend` / `QemuBackend` source files.
- `mvm-backends` has no dependency on `mvm-runtime` or `mvm-build`.
- The public re-export surface in `mvm-runtime` keeps downstream callers compiling (examples, tests, `mvm-build`, `mvm-cli`).
- Security claims in `model/claims.toml` and ADR-001 are unchanged or strengthened.

# Extract the Firecracker driver into `mvm-backends`

> **Parent plan:** [`298-extract-mvm-backends-crate.md`](./298-extract-mvm-backends-crate.md)
>
> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

## Goal

Finish the concrete backend extraction started in the parent plan by moving `FcDriver` and its Firecracker-specific substrate out of `mvm-runtime` into `mvm-backends`, preserving the **single `VmmDriver` trait** for all backends. No per-backend trait may be introduced.

## Why Firecracker is still in `mvm-runtime`

The parent plan moved HVF, libkrun, QEMU, and Mock. `FcDriver` stayed behind because it reaches directly into runtime internals instead of using only the shared helpers in `mvm-vmm::host`:

| `driver/fc.rs` dependency | Current home | Where it must go |
|---|---|---|
| `microvm::{pause_vm, resume_vm, secure_vsock_socket_for_caller, start_vm_firecracker, api_put_socket, …}` | `mvm-runtime::microvm` | `mvm-backends::fc` |
| `firecracker::{FcVmFullControl, FcForkRestorer, is_vm_running, is_firecracker_pid_running}` | `mvm-runtime::firecracker` | `mvm-backends::fc` |
| `vm::instance_snapshot::{FirecrackerIO, SnapshotIO}` | `mvm-runtime::vm` | `SnapshotIO` → `mvm-vmm`; `FirecrackerIO` → `mvm-backends::fc` |
| `checkpoint::ForkVmFullRestorer` | `mvm-runtime::checkpoint` | **deleted** — see the budget below |
| `backend::FirecrackerBackend` | `mvm-runtime::backend` | already in `mvm-backends::legacy::fc` |

Every other driver became self-contained once the shared host helpers moved into `mvm-vmm::host`. Firecracker did not, so it needs a seam decision rather than a file move.

## Design decision

**`VmmDriver` is the single backend trait.** It must not gain a Firecracker-shaped sibling, and `mvm-runtime` must not inject FC-specific behaviour into backends. FC mechanics become private modules inside `mvm-backends`. The generic snapshot/guard seam lifts into `mvm-vmm` so runtime orchestration and backend implementations share it without a cycle.

HVF already demonstrates the correct shape: `HvfVmFullControl` is a private type inside `mvm-backends/src/driver/hvf.rs`, and it implements `fork_standby_child` directly against the `VmmDriver` seam. Firecracker follows that shape.

## Trait and type budget

A move-only refactor that *adds* abstraction has failed. This plan adds **zero new traits and zero new structs**, and deletes several. Treat the table as a constraint: reject any step that grows the count.

| Item | Today | After | Why |
|---|---|---|---|
| `VmmDriver` | 1 trait, 5 impls | unchanged | the single backend seam |
| `VmFullControl` | 1 trait, 3 impls (Fc, Hvf, Mock) | unchanged | genuinely polymorphic |
| `SnapshotIO` | 1 trait, 3 impls | 1 trait, **2 impls** | the injectable seam behind the guard-ordering witnesses |
| `ForkVmFullRestorer` | 1 trait, 1 real impl + 1 double | **deleted** | below |
| `MockRestorer` | struct | **deleted** | dies with the trait |
| `CannedIO` + `SpyIO` | 2 doubles for one trait | **1 double** | `SpyIO` is already a superset |
| `RestoredDeviceModel` | `pub` in `mvm-runtime` | private to `mvm-backends` | FC wire format, not a seam type |
| device-model view trait | — | **not introduced** | Task 1 |
| `mvm-backends::registry` | — | **not introduced** | the parent plan floated it "if cleaner"; it deletes no code, so no |

**Delete `ForkVmFullRestorer`.** One method, exactly one production implementation (`FcForkRestorer`), one test double, one call site — `fork_vm_full_fc(store, params, restorer, anchor)`. Its only purpose is test injection, and `VmmDriver::fork_standby_child` is already the real backend seam. A one-method injection point is a function: `fork_vm_full_fc` takes `restore: &dyn Fn(&str, &Path) -> Result<()>`. That removes a trait, a struct, and an impl block, and the test passes a closure recording its arguments — strictly less code than `MockRestorer`.

**Keep `RestoredDeviceModel` in `mvm-backends`.** Despite the name it is not backend-agnostic: its own doc comment calls it "a slice of Firecracker's own config schema", and it is deliberately not `deny_unknown_fields` so it tolerates upstream FC additions. Lifting it into `mvm-vmm` would put an FC wire format in the neutral crate. The guard needs a count, not the type — see Task 1.

**Merge the two `SnapshotIO` doubles.** `CannedIO` writes caller-chosen bytes and always reports a no-NIC device model; `SpyIO` records call order and can force a NIC. `SpyIO` is a behavioural superset; the only thing `CannedIO` adds is the payload fields. One double with `vmstate_bytes`, `mem_bytes`, `nic_on_restore`, and a call log covers every existing test. Keep the name `CannedIO` — `mvm-client`, `mvm-conformance`, and `tests/audit_emissions_live.rs` name it — and keep it reachable without those consumers enabling a test-only feature.

**Reuse, do not re-derive.** Moved code keeps calling existing helpers instead of growing local copies: `~/.mvm` paths through `mvm_core::config` (never `$HOME` + `join`), host command execution through `mvm_vmm::host::shell`, process liveness through `mvm_vmm::host::process_liveness`. That last one is not hypothetical — `checkpoint` and `mvm-cli` each carried their own `vm_is_running` and both had drifted to marker lists that missed live backends. They now delegate; this extraction must not add a third.

### The guard must not become weaker

`assert_vsock_only_device_model` runs between `load_snapshot_paused` and `resume`. That ordering is what stops a snapshot carrying a NIC from resuming and bypassing the vsock-only egress boundary (claims 10, 13). It is sequenced by `verify_and_resume_from_dir`, which is generic and moves intact. **The sequencing stays inside the moved generic helper and is not reimplemented in `FcDriver`.** If a step here finds itself calling `resume()` from backend code, the seam has been cut in the wrong place.

`xtask check-uniform-vsock-egress` and `check-vsock-only-egress` pin the egress spawn site across backends and must stay green throughout.

## Target crate graph

```text
mvm-runtime (WorkloadRunner, AnyBackend, machine lifecycle, snapshot orchestration)
    |
    v
mvm-backends (FcDriver, HvfDriver, LibkrunDriver, QemuDriver, MockDriver,
              legacy VmBackend shells, and FC-specific substrate under fc/)
    |
    v
mvm-vmm (VmmDriver, VmmSpec, VmFullControl, SnapshotIO,
         assert_vsock_only_device_model, host helpers)
    |
    +--> mvm-core, mvm-net, mvm-agentd
```

Invariant: `mvm-backends` must not depend on `mvm-runtime` or `mvm-build`.

## Already completed (do not redo)

- `mvm-vmm` owns the backend-agnostic `VmmDriver` seam, `VmmSpec`, `VmFullControl`, and the `mvm-vmm::host` helper module.
- `mvm-backends` owns the HVF, libkrun, QEMU, and Mock drivers plus the legacy `FirecrackerBackend` / `HvfBackend` / `LibkrunBackend` / `QemuBackend` shells.
- Host command execution (`base::shell`, `base::linux_env`) moved to `mvm-vmm::host`, so backend code runs shell commands without depending on `mvm-runtime`.
- The mutation surface is re-pinned for the moved claim-1/claim-15 witnesses and `mvm-backends` has its own mutation shard.

Verify against the tree before trusting this list: `ls crates/mvm-backends/src/driver/` should show `hvf.rs`, `libkrun.rs`, `qemu.rs`, and `ls crates/mvm-vmm/src/host/` should show `shell/` and `linux_env.rs`. An earlier revision of this section claimed both while sitting on a branch that had neither.

---

## Task 1: Lift the generic snapshot seam into `mvm-vmm`

**Files:** `crates/mvm-runtime/src/vm/instance_snapshot.rs`, `crates/mvm-runtime/src/checkpoint/mod.rs`, `crates/mvm-runtime/src/microvm/snapshot.rs`, `crates/mvm-vmm/src/checkpoint.rs`, `crates/mvm-vmm/src/lib.rs`

- [ ] **Split the device-model guard from the Firecracker config view.**
      `SnapshotIO::restored_device_model` returns `RestoredDeviceModel`, so
      something must move before the trait can. The guard's entire body is
      `ensure!(config.network_interfaces.is_empty())` — it needs a count, not
      the type. Change the seam method to
      `fn restored_network_interface_count(&self) -> Result<usize>` and move
      `assert_vsock_only_device_model(count: usize)` into `mvm-vmm` as a free
      function. `RestoredDeviceModel` stays Firecracker's (Task 2).

      Two shapes were considered and rejected: a `RestoredDeviceModelView`
      trait (one method, one impl, one consumer — a type-shaped way of saying
      "a number"), and making the guard a `SnapshotIO` method (hands every
      backend its own copy of a claim-bearing refusal). A bare `usize` is
      right here despite the general newtype preference: the method name
      carries the unit and nothing else consumes the value.

- [ ] **Move the `SnapshotIO` trait and the generic guard helpers** from
      `vm/instance_snapshot.rs` into `mvm-vmm`: `pause_and_seal`,
      `verify_and_resume`, `verify_and_resume_from_dir`, `guarded_load_resume`,
      `guarded_fork_load_resume`, `guarded_fork_load_paused`,
      `guard_and_resume`, `guard_loaded_device_model`. All are already generic
      over `IO: SnapshotIO + ?Sized`, so they move without signature change.

- [ ] **Merge `SpyIO` into `CannedIO`** and move the single double with the
      helpers it tests.

- [ ] **Delete the `ForkVmFullRestorer` trait.** Change `fork_vm_full_fc`'s
      third parameter to `restore: &dyn Fn(&str, &Path) -> Result<()>`, delete
      the trait and `MockRestorer`, and pass a closure at the one call site.
      Verify it is genuinely single-use first (`rg 'ForkVmFullRestorer'`); if a
      second production impl has appeared, stop and re-decide.

- [ ] **Keep in `mvm-runtime`:** the seal/verify/HMAC orchestration and on-disk
      layout helpers in `vm/instance_snapshot.rs` (`instance_dir`,
      `snapshot_dir`, `prepare_instance_snapshot_dir`,
      `list_instance_snapshots`, `delete_instance_snapshot`). Those are runtime
      policy, not backend substrate.

- [ ] Re-export the moved types from `mvm-runtime::vm::instance_snapshot` and
      `mvm-runtime::checkpoint` so `mvm-cli` / `mvm-hostd` keep resolving.

- [ ] `cargo nextest run -p mvm-vmm -p mvm-runtime` and `cargo clippy -p mvm-vmm -p mvm-runtime --all-targets -- -D warnings`.

---

## Task 2: Move the Firecracker substrate into `mvm-backends`

Create `crates/mvm-backends/src/fc/` for FC-specific implementation detail. Keep items `pub(crate)` unless something outside genuinely names them.

- [ ] `fc/mod.rs` — path helpers (`resolve_running_vm_dir`, `fc_pid_path`, `firecracker_vsock_uds_path`) and re-exports.
- [ ] `fc/api.rs` — body builders (`boot_source_body`, `drive_body`, `vsock_body`, `machine_config_body`, `logger_body`, `balloon_body`) and `api_put_socket`.
- [ ] `fc/client.rs` — the HTTP-over-UDS client from `microvm/fc_api.rs`.
- [ ] `fc/process.rs` — `start_vm_firecracker`, `start_vm_firecracker_for_snapshot`, `read_firecracker_pid`, `secure_vsock_socket_for_caller`.
- [ ] `fc/control.rs` — `pause_vm`, `resume_vm`, balloon control.
- [ ] `fc/guard.rs` — `FirecrackerGuard`.
- [ ] `fc/snapshot.rs` — `create_snapshot_files`, `remap_paths_for_fork`, and `RestoredDeviceModel` (crate-private).
- [ ] `fc/host.rs` — `is_vm_running`, `is_firecracker_pid_running`. Route these through `mvm_vmm::host::process_liveness` rather than open-coding a third `kill(0)`.
- [ ] `fc/io.rs` — `FirecrackerIO`, the `SnapshotIO` impl, plus `FcVmFullControl`. The former `FcForkRestorer` body becomes a plain function here (its trait died in Task 1); prefer folding it straight into `FcDriver::fork_standby_child` if nothing else calls it.
- [ ] Add `pub mod fc;` to `mvm-backends/src/lib.rs`.
- [ ] Update imports to `mvm_vmm::host::shell`, `mvm_vmm::host::ui`, and `mvm_core::config` path helpers.
- [ ] `cargo check -p mvm-backends -p mvm-runtime` + clippy.

**Do not move** the install/asset helpers in `mvm-runtime/src/firecracker.rs` (`is_installed`, `download_assets`, …). Those are runtime/CLI policy, not backend substrate, and they stay.

---

## Task 3: Move `driver/fc.rs` into `mvm-backends`

- [ ] Move `crates/mvm-runtime/src/driver/fc.rs` → `crates/mvm-backends/src/driver/fc.rs`.
- [ ] Update imports: `crate::backend::FirecrackerBackend` → `crate::legacy::fc::FirecrackerBackend`; `crate::microvm::*` / `crate::firecracker::*` → `crate::fc::*`; `crate::base::shell::*` → `mvm_vmm::host::shell::*`; `crate::checkpoint::VmFullControl` and the snapshot seam → `mvm_vmm::*`.
- [ ] Add `pub mod fc;` to `mvm-backends/src/driver/mod.rs`.
- [ ] Reduce `mvm-runtime/src/driver/mod.rs` to `pub use mvm_backends::driver::fc::FcDriver;` and delete the local module.
- [ ] **Relocate the test-only couplings.** `fc.rs` tests reach `crate::wasm_backend::WasmBackend` (a capability-matrix assertion), `crate::workload_runner::{factory_parent_config, factory_parent_spec}`, and `crate::test_support::bind_unix_listener`. None can follow the driver down. Leave those specific tests in `mvm-runtime` (they assert things *about runtime orchestration*) and move the rest with the file. Do not weaken them by stubbing what they call.
- [ ] `cargo nextest run -p mvm-backends -p mvm-runtime` + clippy.

---

## Task 4: Update remaining runtime callers

- [ ] `vm/instance_snapshot.rs` — keep seal/verify/HMAC orchestration; import the seam from `mvm_vmm` and `FirecrackerIO` from `mvm_backends::fc`.
- [ ] `firecracker.rs` — keep install/asset helpers; import moved control/restorer entry points from `mvm_backends::fc`.
- [ ] `microvm/*.rs` — remove moved helpers or reduce the modules to thin re-exports; delete `microvm/fc_api.rs` once emptied.
- [ ] Confirm `selection.rs` needs no per-backend branch. Selection *policy* stays in `mvm-runtime`; per-backend *construction* lives in `mvm-backends`. Call those constructors directly — introduce a registry only if it removes a match arm that would otherwise be duplicated at a second call site, and say which one in the commit message.

---

## Task 5: Verification gates

- [ ] `cargo nextest run --workspace` and `cargo test --workspace --doc` green.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` green.
- [ ] `cargo run -p xtask -- check-claim-catalog`, `check-dormant-controls`, `check-uniform-vsock-egress`, `check-vsock-only-egress`, `check-no-vz` green.
- [ ] `check-mutation-witnesses` — re-pin if the surface moved, and confirm the claim-bearing witnesses still resolve at their new paths before accepting the re-pin.
- [ ] `just check-linux` — `microvm/` is the most Linux-gated tree in the workspace.
- [ ] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` in the same change.

## Acceptance criteria

- `mvm-runtime` contains no `driver/fc.rs`, no `microvm/fc_api.rs`, and no FC-specific control/restorer types.
- `FcDriver` lives in `mvm-backends/src/driver/fc.rs` and implements the same `mvm_vmm::driver::VmmDriver` trait as every other backend.
- No per-backend trait was introduced, and the budget table's counts hold.
- The device-model guard still runs between snapshot load and resume, sequenced by the generic helper, as exactly one function with one implementation.
- No Firecracker wire format leaked into `mvm-vmm`.
- `mvm-backends` depends on neither `mvm-runtime` nor `mvm-build`.

## Notes

- `WasmBackend` stays in `mvm-runtime` and is out of scope.
- Keep spec/ADR/PR references out of code comments (CI `check-no-spec-refs-in-comments`); process context belongs here and in commit messages.

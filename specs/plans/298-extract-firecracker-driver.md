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

- [x] **Split the device-model guard from the Firecracker config view.**
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

- [x] **Move the `SnapshotIO` trait and the generic guard helpers** from
      `vm/instance_snapshot.rs` into `mvm-vmm`: `pause_and_seal`,
      `verify_and_resume`, `verify_and_resume_from_dir`, `guarded_load_resume`,
      `guarded_fork_load_resume`, `guarded_fork_load_paused`,
      `guard_and_resume`, `guard_loaded_device_model`. All are already generic
      over `IO: SnapshotIO + ?Sized`, so they move without signature change.

- [x] **Merge `SpyIO` into `CannedIO`** and move the single double with the
      helpers it tests.

- [x] **Delete the `ForkVmFullRestorer` trait.** Change `fork_vm_full_fc`'s
      third parameter to `restore: &dyn Fn(&str, &Path) -> Result<()>`, delete
      the trait and `MockRestorer`, and pass a closure at the one call site.
      Verify it is genuinely single-use first (`rg 'ForkVmFullRestorer'`); if a
      second production impl has appeared, stop and re-decide.

- [x] **Keep in `mvm-runtime`:** the seal/verify/HMAC orchestration and on-disk
      layout helpers in `vm/instance_snapshot.rs` (`instance_dir`,
      `snapshot_dir`, `prepare_instance_snapshot_dir`,
      `list_instance_snapshots`, `delete_instance_snapshot`). Those are runtime
      policy, not backend substrate.

- [x] Re-export the moved types from `mvm-runtime::vm::instance_snapshot` and
      `mvm-runtime::checkpoint` so `mvm-cli` / `mvm-hostd` keep resolving.

- [x] `cargo nextest run -p mvm-vmm -p mvm-runtime` and `cargo clippy -p mvm-vmm -p mvm-runtime --all-targets -- -D warnings`.

---

## Task 2: Move the Firecracker substrate into `mvm-backends`

Create `crates/mvm-backends/src/fc/` for FC-specific implementation detail. Keep items `pub(crate)` unless something outside genuinely names them.

- [x] `fc/mod.rs` — path helpers (`resolve_running_vm_dir`, `fc_pid_path`, `firecracker_vsock_uds_path`) and re-exports.
- [x] `fc/api.rs` — body builders (`boot_source_body`, `drive_body`, `vsock_body`, `machine_config_body`, `logger_body`, `balloon_body`) and `api_put_socket`.
- [x] `fc/client.rs` — the HTTP-over-UDS client from `microvm/fc_api.rs`.
- [x] `fc/process.rs` — `start_vm_firecracker`, `start_vm_firecracker_for_snapshot`, `read_firecracker_pid`, `secure_vsock_socket_for_caller`.
- [x] `fc/control.rs` — `pause_vm`, `resume_vm`, balloon control.
- [x] `fc/guard.rs` — `FirecrackerGuard`.
- [x] `fc/snapshot.rs` — `create_snapshot_files`, `remap_paths_for_fork`, and `RestoredDeviceModel` (crate-private).
- [x] `fc/host.rs` — `is_vm_running`, `is_firecracker_pid_running`. Route these through `mvm_vmm::host::process_liveness` rather than open-coding a third `kill(0)`.
- [x] `fc/io.rs` — `FirecrackerIO`, the `SnapshotIO` impl, plus `FcVmFullControl`. The former `FcForkRestorer` body becomes a plain function here (its trait died in Task 1); prefer folding it straight into `FcDriver::fork_standby_child` if nothing else calls it.
- [x] Add `pub mod fc;` to `mvm-backends/src/lib.rs`.
- [x] Update imports to `mvm_vmm::host::shell`, `mvm_vmm::host::ui`, and `mvm_core::config` path helpers.
- [x] `cargo check -p mvm-backends -p mvm-runtime` + clippy.

**Do not move** the install/asset helpers in `mvm-runtime/src/firecracker.rs` (`is_installed`, `download_assets`, …). Those are runtime/CLI policy, not backend substrate, and they stay.

### The `FlakeRunConfig` knot — decide before moving the rest

The four modules moved so far had no orchestration coupling. The remainder is
not so clean, and the blocker is one type:

- `flake_run.rs` defines `FlakeRunConfig` **and** consumes
  `crate::image::RuntimeVolume`, which is a `mvm-runtime` type.
- `run_info.rs`, `snapshot.rs`, and `boot_config.rs` all consume
  `FlakeRunConfig`.
- `guards.rs` calls `observe::release_slot_reservation`; `observe.rs` and
  `control.rs` reach `crate::firecracker`.

So `flake_run.rs` cannot follow the others down while it needs a
`mvm-runtime` type, and the three modules that consume its config cannot
move while it stays. Pick one before touching them:

1. **Move `RuntimeVolume` down** (to `mvm-vmm`, or `mvm-contract` beside the
   other volume DTOs) and take `flake_run.rs` with it. Check first whether
   `RuntimeVolume` is genuinely a contract type or carries runtime policy —
   `mvm-cli`, `mvm-client`, and `backend.rs` all name it, so this widens
   beyond the FC extraction.
2. **Split `FlakeRunConfig` from `flake_run.rs`**: the config struct moves to
   `mvm-vmm` as a plain descriptor, the flake-running orchestration stays in
   `mvm-runtime`. Cheapest if the struct turns out not to reference
   `RuntimeVolume` in a load-bearing way.
3. **Leave `flake_run.rs`, `run_info.rs`, `snapshot.rs`, and `boot_config.rs`
   in `mvm-runtime`** and accept a smaller `mvm-backends::fc`. Legitimate if
   they are closer to "which flake and which volumes to run" than to "how
   Firecracker works" — but then say so in the module docs, so the boundary
   is a decision rather than an accident.

**Investigated — the knot is smaller than it looks.** `flake_run.rs` is 383
lines, and its module doc already says what it is: "Compatibility data types
for the retired raw Firecracker flake launcher." Checking each public
function against the whole repo (`crates/`, `tests/`, `src/`, `examples/`,
`xtask/`, `features/`, excluding comment lines) finds **zero callers** for
all four:

| Function | Non-comment references |
|---|---|
| `run_from_build` | 0 |
| `run_from_prestarted_build` | 0 |
| `create_dev_config_drive` | 0 |
| `create_dev_secrets_drive` | 0 |

`run_from_build` does not launch anything either — its body is
`config.validate()?` followed by `bail!("raw Firecracker flake launch is
disabled; use the vsock workload runner")`. It is a refusal stub, and an
unreachable one.

That refusal is **not** a registered control: `cargo xtask
check-dormant-controls` reports 4 total (1 live, 3 declared dormant) and
none of them is this, and neither `model/claims.toml` nor ADR-001 names
`flake_run` or `run_from_build`. The invariant it gestures at — workloads
enter through the runner, guests have no NIC — is enforced live by
`check-vsock-only-egress` and `check-uniform-vsock-egress`.

So the cheap resolution is **delete the dead launcher, keep the
descriptor**: drop the four functions plus the private
`drive_file_inject_commands`, leaving `FlakeRunConfig` and its `validate()`.
That removes the `run_in_vm` dependency outright and shrinks the coupling
question to just `VmSlot` and `RuntimeVolume` on a plain data struct.

**Confirm before deleting** that removing an unreachable refusal is wanted.
It guards nothing today, but it is the kind of stub someone added on
purpose; a reviewer should agree it is redundant with the two egress gates
rather than discovering later that it was load-bearing prose.

**Settled: option 3, and the tree already says so.** With the dead launcher
deleted, `flake_run.rs` is 207 lines of descriptor plus `validate()`, and
`boot_config.rs`'s own module doc reads "`FlakeRunConfig`-dependent helpers
that still need `mvm-runtime` types" — a previous author drew this boundary
and labelled it. The split is therefore:

**Stays in `mvm-runtime`** (the "which flake, which volumes, how much RAM"
layer — orchestration, not FC mechanics):
`flake_run.rs` (`FlakeRunConfig` + `validate`), `boot_config.rs`,
`run_info.rs`, `activation.rs`, and the one `snapshot.rs` function that
takes a `FlakeRunConfig`.

**Moves to `mvm-backends::fc`** (how Firecracker actually works):
`control.rs` (`pause_vm`, `resume_vm`), `observe.rs`, `guards.rs`,
`firecracker.rs`, `FirecrackerIO`, and the rest of `snapshot.rs`
(`create_snapshot_files`, `remap_paths_for_fork`).

Neither `RuntimeVolume` nor `VmSlot` needs to move, which is what made
options 1 and 2 expensive. `snapshot.rs` is the only file needing a split
rather than a move.

Remaining order: `firecracker.rs` + `control.rs` + `observe.rs` + `guards.rs`
together (they are mutually referential), then split `snapshot.rs`, then
`driver/fc.rs` itself.

---

## Task 3: Move `driver/fc.rs` into `mvm-backends`

- [x] Move `crates/mvm-runtime/src/driver/fc.rs` → `crates/mvm-backends/src/driver/fc.rs`.
- [x] Update imports: `crate::backend::FirecrackerBackend` → `crate::legacy::fc::FirecrackerBackend`; `crate::microvm::*` / `crate::firecracker::*` → `crate::fc::*`; `crate::base::shell::*` → `mvm_vmm::host::shell::*`; `crate::checkpoint::VmFullControl` and the snapshot seam → `mvm_vmm::*`.
- [x] Add `pub mod fc;` to `mvm-backends/src/driver/mod.rs`.
- [x] Reduce `mvm-runtime/src/driver/mod.rs` to `pub use mvm_backends::driver::fc::FcDriver;` and delete the local module.
- [x] **Relocate the test-only couplings.** `fc.rs` tests reach `crate::wasm_backend::WasmBackend` (a capability-matrix assertion), `crate::workload_runner::{factory_parent_config, factory_parent_spec}`, and `crate::test_support::bind_unix_listener`. None can follow the driver down. Leave those specific tests in `mvm-runtime` (they assert things *about runtime orchestration*) and move the rest with the file. Do not weaken them by stubbing what they call.
- [x] `cargo nextest run -p mvm-backends -p mvm-runtime` + clippy.

---

## Task 4: Update remaining runtime callers

- [x] `vm/instance_snapshot.rs` — keep seal/verify/HMAC orchestration; import the seam from `mvm_vmm` and `FirecrackerIO` from `mvm_backends::fc`.
- [x] `firecracker.rs` — keep install/asset helpers; import moved control/restorer entry points from `mvm_backends::fc`.
- [x] `microvm/*.rs` — remove moved helpers or reduce the modules to thin re-exports; delete `microvm/fc_api.rs` once emptied.
- [x] Confirm `selection.rs` needs no per-backend branch. Selection *policy* stays in `mvm-runtime`; per-backend *construction* lives in `mvm-backends`. Call those constructors directly — introduce a registry only if it removes a match arm that would otherwise be duplicated at a second call site, and say which one in the commit message.

---

## Task 5: Verification gates

- [x] `cargo nextest run --workspace` and `cargo test --workspace --doc` green.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` green.
- [x] `cargo run -p xtask -- check-claim-catalog`, `check-dormant-controls`, `check-uniform-vsock-egress`, `check-vsock-only-egress`, `check-no-vz` green.
- [x] `check-mutation-witnesses` — re-pin if the surface moved, and confirm the claim-bearing witnesses still resolve at their new paths before accepting the re-pin.
- [x] `just check-linux` — `microvm/` is the most Linux-gated tree in the workspace.
- [x] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` in the same change.

## Outcome

Complete. `mvm-runtime` holds no `driver/fc.rs`, no `firecracker.rs`, and no
Firecracker `microvm` modules; `mvm-backends::fc` owns them and depends on
neither `mvm-runtime` nor `mvm-build`.

Two things the move surfaced that were not in the original plan:

- **`require_linux_env` deleted.** A `fn(..) -> Result<()> { Ok(()) }` no-op
  called at seven sites, documented as kept "so callers stay well-formed".
  It asserted nothing; the calls went with it.
- **`bind_unix_listener` de-duplicated.** `mvm-runtime` and `mvm-vmm` both
  carried one; the runtime copy went dead when its last caller moved, so the
  `mvm-vmm` one is now the only copy.

One judgement call worth a reviewer's eye: `FirecrackerBackend::start`
previously delegated to `fc_runner()`, which lives in `mvm-runtime` and would
have inverted the dependency. `FcDriver` never calls it, nothing else
constructs the type, and `AnyBackend` routes every real start through the
runner — so it now refuses loudly instead. That is a refusal on an
unreachable path, not a stub standing in for missing work; if a caller ever
lands there it must be routed to the runner rather than handed a VM that
skipped plan admission.

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

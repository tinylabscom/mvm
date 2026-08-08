# Migration boundary — Plan 298: Extract `mvm-backends`

> Living boundary contract for the crate split. Update this file as decisions
> change; it is deleted once the refactor merges.

## Current state (post PR #2220)

- `mvm-vmm` already owns the portable device model (`src/vmm/`) and the
  vsock-egress bridge.
- `mvm-runtime` still owns:
  - the `VmmDriver` seam (`driver/traits.rs`, `driver/spec.rs`);
  - the concrete driver modules (`driver/fc.rs`, `driver/libkrun.rs`,
    `driver/qemu.rs`, `driver/mock.rs`, `backends/hvf/driver.rs`);
  - the legacy `VmBackend` implementations (`backend.rs`, `libkrun.rs`,
    `qemu.rs`, `backends/hvf/backend.rs`);
  - backend-specific substrate (`microvm/`, `firecracker/`, `libkrun/`,
    `qemu/`, `kvm/`);
  - workload lifecycle orchestration (`workload_runner/`, `machine/`,
    `checkpoint/`, `vm/instance_snapshot.rs`).

## Progress

- [x] `VmmSpec` moved to `mvm-vmm::driver::spec`.
- [x] `vsock_transport` moved to `mvm-vmm::vsock_transport`; `mvm_core::config::running_vm_dir` added so the transport no longer depends on `mvm-runtime::microvm`.
- [x] Post-restore signal + primed barrier helpers → `mvm-vmm`.
- [x] `VmFullControl` trait → `mvm-vmm` (plus `DeviceAnchors` moved to `mvm-core::checkpoint`).
- [x] `VmmDriver` trait + `RunningVm` + `ChildForkRequest` + `StandbyParentSpawn` + `DuplexStream` → `mvm-vmm`.
- [x] `virtiofsd` helper → `mvm-vmm::host::virtiofsd`; `mvm-build` re-exports it.
- [x] `mvm-backends` crate scaffolded; `MockDriver` moved under `test-support` feature.
- [~] Create `mvm-backends` and move drivers (MockDriver moved; Fc/Hvf/Libkrun/Qemu remain).

## Target crate graph

```text
mvm-runtime (WorkloadRunner, AnyBackend, machine, snapshot orchestration)
    |
    v
mvm-backends (FcDriver, HvfDriver, LibkrunDriver, QemuDriver, MockDriver,
              plus the legacy VmBackend shells and backend-specific substrate)
    |
    v
mvm-vmm (device model + VmmDriver trait + VmmSpec + host virtiofsd helper)
    |
    +--> mvm-core, mvm-net, mvm-agentd
```

`mvm-build` must not be on the path from `mvm-backends` back to `mvm-runtime`.

## What moves into `mvm-vmm`

| Item | Current path | New path | Notes |
|---|---|---|---|
| `VmmDriver` trait | `mvm-runtime/src/driver/traits.rs` | `mvm-vmm/src/driver/traits.rs` | Includes `ChildForkRequest`, `StandbyParentSpawn`, `DuplexStream`. |
| `RunningVm` trait | `mvm-runtime/src/driver/traits.rs` | `mvm-vmm/src/driver/traits.rs` | Stays with the driver seam. |
| `VmmSpec` + types | `mvm-runtime/src/driver/spec.rs` | `mvm-vmm/src/driver/spec.rs` | Adds `mvm_net` dep to `mvm-vmm`. |
| `VmFullControl` trait | `mvm-runtime/src/checkpoint/mod.rs` | `mvm-vmm/src/control.rs` | Backend-agnostic pause/save/resume surface. |
| `PostRestoreOutcome` | `mvm-runtime/src/vm/instance_snapshot.rs` | `mvm-vmm/src/post_restore.rs` | Returned by `VmmDriver::deliver_child_identity`. |
| `PostRestoreSignal` + `signal_post_restore` | `mvm-runtime/src/vm/instance_snapshot.rs` | `mvm-vmm/src/post_restore.rs` | Move the default impl helper so `mvm-vmm` does not depend on `mvm-runtime`. |
| `virtiofsd` host helper | `mvm-build/src/virtiofsd.rs` | `mvm-vmm/src/host/virtiofsd.rs` | Used by QEMU driver and builder VM; breaks the build↔runtime cycle. |

`mvm-vmm` will gain dependencies on `anyhow` (already transitively present) and
`mvm_net` (for `GuestService`). It must remain free of `mvm-runtime`, `mvm-build`,
and heavy backend crates (`libkrun-sys`, `wasmtime`, etc.).

## What moves into `mvm-backends`

| Item | Current path | New path | Notes |
|---|---|---|---|
| `FcDriver` | `mvm-runtime/src/driver/fc.rs` | `mvm-backends/src/fc/driver.rs` | Delegates to `FirecrackerBackend` for caps/profile today. |
| `LibkrunDriver` | `mvm-runtime/src/driver/libkrun.rs` | `mvm-backends/src/libkrun/driver.rs` | Delegates to `LibkrunBackend`. |
| `QemuDriver` | `mvm-runtime/src/driver/qemu.rs` | `mvm-backends/src/qemu/driver.rs` | Uses `virtiofsd` from `mvm-vmm`. |
| `MockDriver` | `mvm-runtime/src/driver/mock.rs` | `mvm-backends/src/mock/driver.rs` | Test-only. |
| `HvfDriver` | `mvm-runtime/src/backends/hvf/driver.rs` | `mvm-backends/src/hvf/driver.rs` | Already isolated under `backends/hvf/`. |
| `FirecrackerBackend` | `mvm-runtime/src/backend.rs` | `mvm-backends/src/fc/legacy.rs` | Legacy `VmBackend` shell. |
| `LibkrunBackend` | `mvm-runtime/src/libkrun.rs` | `mvm-backends/src/libkrun/legacy.rs` | Legacy `VmBackend` shell. |
| `QemuBackend` | `mvm-runtime/src/qemu.rs` | `mvm-backends/src/qemu/legacy.rs` | Legacy `VmBackend` shell. |
| `HvfBackend` | `mvm-runtime/src/backends/hvf/backend.rs` | `mvm-backends/src/hvf/legacy.rs` | Legacy `VmBackend` shell. |
| HVF primitives | `mvm-runtime/src/backends/hvf/{boot_smoke,console_smoke,dax_mapper,guest_ram,hv_impl,kernel_boot,sys,vcpu}.rs` | `mvm-backends/src/hvf/` | Hypervisor.framework-specific substrate. |
| Firecracker substrate | `mvm-runtime/src/microvm/`, `mvm-runtime/src/firecracker/` | `mvm-backends/src/fc/` | Process/API control needed by `FcDriver`. Keep only higher-level orchestration in `mvm-runtime`. |
| libkrun substrate | `mvm-runtime/src/libkrun.rs` (non-legacy parts) | `mvm-backends/src/libkrun/` | Supervisor spawn and supervisor protocol. |
| QEMU substrate | `mvm-runtime/src/qemu.rs` (non-legacy parts) | `mvm-backends/src/qemu/` | Bridge/CID/console helpers. |
| KVM backend | `mvm-runtime/src/kvm/` | `mvm-backends/src/kvm/` | Drives `mvm-vmm` on Linux; keep out of `mvm-runtime`. |

## Cycle breakers

1. **`virtiofsd` helper.** Move from `mvm-build` to `mvm-vmm`. `mvm-build` keeps
   using it via `mvm-vmm`; `mvm-backends` uses it via `mvm-vmm`. This removes
   any need for `mvm-backends` to depend on `mvm-build`.

2. **`VmmDriver` default impl for `deliver_child_identity`.** Move
   `PostRestoreSignal`, `VsockPostRestoreSignal`, and `signal_post_restore` into
   `mvm-vmm`. The protocol is driver-domain; runtime orchestration will call the
   seam version.

3. **`VmFullControl` trait.** Move the trait into `mvm-vmm`. Concrete impls
   (`FcVmFullControl`, etc.) live in `mvm-backends`; orchestration in
   `mvm-runtime` depends on the trait from `mvm-vmm`.

4. **Shared small helpers.** Several tiny helpers are used by both runtime and
   drivers today:
   - `standby_pool::now_unix_secs` → move to `mvm-core::time` or inline.
   - `vm_state_dir`, `vm_hvf_vsock_port_socket_at` → already in `mvm-core::config`.
   - `libkrun::open_console_capture` → move next to the console-capture logic or
     into `mvm-vmm`.
   - `base::ui` progress helpers → keep in `mvm-runtime`; QEMU driver should not
     print UI progress; remove that coupling.

## What stays in `mvm-runtime`

- `workload_runner/` — `WorkloadRunner`, standby boot, spec mapping.
- `backend.rs` — `AnyBackend` enum and dispatch, importing backend types from
  `mvm-backends`.
- `selection.rs` — backend selection policy.
- `checkpoint/mod.rs` — orchestration (`capture_vm_full`, `fork_vm_full_fc`,
  concrete restorers) importing `VmFullControl` from `mvm-vmm`.
- `vm/instance_snapshot.rs` — pause/seal/verify/resume orchestration importing
  `PostRestoreSignal` from `mvm-vmm`.
- `machine/`, `handle_registry/`, `standby_pool/` — product lifecycle above drivers.
- `builder_runner/` — builder VM orchestration (depends on `mvm-build`).

## Open decisions

- Should `MockDriver` live in `mvm-backends` under a `test-support` feature, or
  remain as a test double inside `mvm-runtime`? **Tentative:** move to
  `mvm-backends/src/mock/` gated by `test-support`.
- Should we inline capability/profile methods into drivers and delete the legacy
  `VmBackend` shells as part of this plan, or move the shells and let plan 269
  delete them later? **Tentative:** move the shells with the drivers; deletion
  remains plan 269 scope.
- How much of `firecracker/` and `microvm/` is orchestration vs. mechanics? `resolve_running_vm_dir` already moved to `mvm-core`; `microvm` keeps the rest.
  **Tentative:** anything that talks to the Firecracker API socket or manages
  the Firecracker process moves to `mvm-backends`; admission-level orchestration
  stays in `mvm-runtime`.

## Validation checkpoints

- After Task 2: `cargo check -p mvm-vmm -p mvm-runtime` passes with the seam
  moved.
- After Task 4: `cargo check -p mvm-backends` passes with drivers + legacy
  backends moved.
- After Task 5: `cargo check --workspace` passes with `mvm-runtime` depending on
  `mvm-backends`.
- Final: `cargo nextest run --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` green.

# Backend shim removal — migration boundary

This note locks the inventory for **Plan 269: invert the driver/backend
relationship**. The end-state seam — a blanket `impl VmBackend for
WorkloadRunner<D: VmmDriver, ...>` — already exists in
`crates/mvm-runtime/src/workload_runner/runner/backend.rs`. The remaining work
is to move the VMM mechanics that still live in the legacy direct `VmBackend`
implementations into the `VmmDriver` implementations, then delete the legacy
shells.

## Decisions taken before implementation

- **QEMU disposition:** `specs/SPRINT.md` §2.5 now reads consistently: QEMU
  stays as an **opt-in Tier-2 dev/test backend**, never workload-bearing and
  never auto-selected. The raw `QemuBackend` shell is therefore in-scope for
  deletion; `QemuDriver` remains the dev/test workload path and must keep the
  shared QEMU machinery it already delegates to `QemuBackend`.
- **`WasmBackend` exception:** `WasmBackend` (`crates/mvm-runtime/src/wasm_backend.rs`)
  is intentionally **not** converted to a `VmmDriver`. It is a claim-free
  portability/demo tier with no microVM boundary, so it cannot share the
  `VmmSpec`/`RunningVm` model. It remains a direct `VmBackend` implementation
  and is recorded here as the sole production exemption from the
  runner-only rule.
- **Behavior-preserving:** no capability-matrix changes, no security-claim
  weakening, no workload-visible changes.

## Driver → legacy-backend delegation (to be inlined)

| Driver | Legacy type | Delegated items | Action |
|--------|-------------|-----------------|--------|
| `FcDriver` (`mvm-backends/src/driver/fc.rs`) | `FirecrackerBackend` (`mvm-runtime/src/backend.rs`) | `start`, `stop`, `stop_all`, `pause`, `resume`, `status`, `list`, `logs`, `balloon_set_target`, `balloon_state`, `is_available`, `install`, `capabilities`, `security_profile` | Inline FC lifecycle into `FcDriver` using existing `crate::fc::*` helpers; delete `FirecrackerBackend` |
| `HvfDriver` (`mvm-backends/src/driver/hvf.rs`) | `HvfBackend` (`mvm-backends/src/legacy/hvf.rs`) | `capabilities`, `security_profile`, `is_available`, `guest_channel_info`, plus shared helpers `terminate_pid_timed`, `signal_vm`, `wait_for_pause_state`, `read_pid`, `pid_alive`, `resolve_supervisor_path`, `hvf_workload_disks`, `hvf_console_data_sockets`, `spawn_hvf_gating_endpoint_if_needed`, `hvf_bootargs` | Inline capability/profile into `HvfDriver`; move shared process/endpoint helpers into a driver support module; delete `HvfBackend` |
| `LibkrunDriver` (`mvm-backends/src/driver/libkrun.rs`) | `LibkrunBackend` (`mvm-backends/src/legacy/libkrun.rs`) | `capabilities`, `security_profile`, `is_available`, `guest_channel_info`, plus shared helpers `resolve_supervisor_path`, `read_pid`, `pid_alive`, `cleanup_vsock_sockets`, `STOP_TIMEOUT`, `PID_FILE_TIMEOUT`, `VSOCK_SOCKET_TIMEOUT`, `libkrun_kernel_for_host`, cmdline/builder constants | Inline capability/profile into `LibkrunDriver`; move shared helpers into a driver support module; delete `LibkrunBackend` |
| `QemuDriver` (`mvm-backends/src/driver/qemu.rs`) | `QemuBackend` (`mvm-backends/src/legacy/qemu.rs`) | Shared helpers: `resolve_workload_kernel_path`, `locate_qemu`, `kvm_available`, `allocate_cid`, `read_cid`, `used_cids`, `read_pid`, `pid_alive`, `send_signal`, `QemuBridgeSpec`, `spawn_vsock_bridges`, `cleanup_vsock_bridge_sockets`, `run_vsock_bridge_from_spec_file`, constants | Keep `QemuDriver`; move shared QEMU machinery into a driver support module; delete `QemuBackend` `VmBackend` impl |

## External callers of legacy backends (to be rewritten or deleted)

- `mvm-runtime/src/backend.rs`: defines `FirecrackerBackend` and re-exports legacy
  types; rewrite tests/examples against `FcRunner`/`HvfRunner`/`LibkrunRunner`.
- `mvm-runtime/src/lib.rs`: re-exports `LibkrunBackend` and `QemuBackend`; remove.
- `mvm-runtime/src/workload_backend.rs`: `impl WorkloadBackend for HvfBackend`;
  delete and rely on the blanket `impl WorkloadBackend for WorkloadRunner`.
- `mvm-runtime/src/backends/hvf/mod.rs`: re-exports `HvfBackend`; remove or
  redirect to `HvfDriver`.
- `mvm-runtime/examples/hvf-backend-*.rs`: direct `HvfBackend::start`; rewrite
  against `HvfRunner` / `WorkloadRunner`.
- `mvm-runtime/tests/libkrun_lifecycle_e2e.rs`: direct `LibkrunBackend` lifecycle;
  rewrite against `LibkrunRunner`.
- `mvm-cli/src/bench/probe.rs`, `mvm-cli/src/bench/stats.rs`: direct
  `LibkrunBackend` usage; rewrite against runner or dedicated benchmark seam.
- `mvm-build/src/libkrun_builder.rs`: uses `LibkrunBackend::start` for the builder
  VM; migrate to a small builder-facing helper over `LibkrunDriver` + `VmmSpec`
  or a dedicated builder seam.
- `mvm-runtime/src/codesign.rs`: references legacy HVF backend for signing
  contexts; audit and update to `HvfDriver`/`HvfRunner`.
- `mvm-runtime/src/builder_runner/inject.rs`: may reference legacy libkrun
  backend; update to `LibkrunDriver`.
- `mvm-cli/src/commands/qemu_bridge.rs`: uses raw QEMU bridge machinery; keep
  using the shared helpers after they move out of `QemuBackend`.

## Classification summary

- **Move into driver / support module:** all process lifecycle helpers, PID
  file handling, supervisor resolution, cmdline constants, bridge spec helpers.
- **Delete:** the four legacy `VmBackend` impl structs and their `impl VmBackend
  for` blocks (`FirecrackerBackend`, `HvfBackend`, `LibkrunBackend`, `QemuBackend`).
- **Rewrite:** tests/examples/benchmarks/builder that directly constructed the
  legacy backends.
- **Keep as exemption:** `WasmBackend` (direct `VmBackend`, not a `VmmDriver`).

## Expected final `VmBackend` implementors

- `WorkloadRunner<D: VmmDriver, S: EndpointSpawner, B: BrokerRegistrar>` — the
  sole path for selectable microVM backends.
- `MockBackend` (`test-support` only).
- `WasmBackend` (documented exemption — a WASI module boundary, not a microVM).
- `AppleContainerBackend` (pre-existing container-tier backend; not part of this VMM-shim removal).
- Test doubles inside `#[cfg(test)]` modules.

## Verification greps (run at start and end)

```bash
rg "FirecrackerBackend\b|HvfBackend\b|LibkrunBackend\b|QemuBackend\b" crates/ --type rust
rg "impl VmBackend for" crates/ --type rust
```

After the refactor, the first grep should show only re-export deprecation
stubs (if any), the migration note, documentation, and test/example files that
have been rewritten. The second grep should show only `WorkloadRunner`,
`MockBackend`, `WasmBackend`, and test doubles.

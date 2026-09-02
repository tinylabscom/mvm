# mvm-runtime

`mvm-runtime` is the machine lifecycle and orchestration layer. It selects a VMM
backend, prepares verified artifacts and storage, provisions networking,
coordinates host/guest services, and persists enough state to stop, inspect,
checkpoint, and restore machines safely.

## Who uses it

`mvm-cli` calls it for local machine commands. `mvm-client` wraps it in
`LocalBackend`, and `mvm-hostd` uses its lifecycle machinery under admitted
host processes. The root `mvmctl` facade re-exports it. `mvm-conformance` and
several lower-level crates use its test support.

## How it works

1. Selection chooses an admitted backend based on requested capabilities and
   the host platform.
2. Artifact validation resolves the kernel, rootfs, initramfs, overlays, and
   sidecars that will be booted.
3. Storage and network providers create per-machine resources and return typed
   handles with explicit teardown ownership.
4. A `WorkloadRunner` drives the selected `VmmDriver` from `mvm-backends`.
5. Agent sessions, host services, output capture, and lifecycle events are
   connected over bounded channels and vsock.
6. Runtime state and lineage are persisted only after identity checks, then
   reconciled during later list, stop, checkpoint, or restore operations.

Owned live resources prefer event-driven observation; durable records remain
the source of recovery truth. Partial starts use guards so failure does not
delete resources belonging to another process or stale generation.

## Main areas

| Area | Representative modules |
|---|---|
| Backend lifecycle | `backend`, `backends`, `driver`, `selection` |
| Machine state | `machine`, `handle_registry`, `lineage`, `catalog` |
| Boot artifacts | `artifacts`, `image`, `base`, `sdk_sidecar` |
| Build execution | `builder_runner`, `build_env` |
| Storage | `storage`, `volume`, `warm_snapshot` |
| Lifecycle acceleration | `resident_pool`, `standby_pool`, `checkpoint` |
| Platform paths | `kvm`, `apple_container`, `hvf_restore`, `wasm_backend` |
| Security | `security`, `netinit_audit`, artifact validation |

## Backends and features

The production Linux path uses Firecracker/KVM. macOS supports the in-house
HVF path and libkrun where configured. QEMU and Apple Container are explicitly
lower-tier development substrates; the optional wasm backend is a host
wasmtime execution path, not a microVM. Features include `wasm-backend`,
`template-registry-s3`, `trusted-apfs`, `manifest-verify`, and `test-support`.

## Developing

Run `cargo test -p mvm-runtime` on the host for portable tests. Firecracker,
Linux syscall, and runtime commands run inside the builder VM; explicitly
scoped HVF live tests run on macOS. Shared lifecycle changes must also compile
all gated targets.

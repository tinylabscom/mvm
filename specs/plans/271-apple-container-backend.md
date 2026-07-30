# Plan 271: Apple Container backend — same boot contract through vminitd

**Status:** Stage 1 (backend skeleton) implemented; stages 2–4 designed below.
**Owner:** mvm core.
**Depends on:** universal initramfs + `ActivateEnvironment` (PR #1914).

## Goal

An `--hypervisor apple-container` backend that runs mvm workloads inside
Apple's Containerization-framework VMs with the **same guest-visible
functionality** as every other backend: a fail-closed init gate, an
environment-activation step, dm-verity rootfs + runtime overlay, virtio-fs
volumes, privilege drop to uid 901, and the standard operational RPC surface
after activation.

Apple's framework is Swift-only and owns two things we cannot replace:
the kernel boot path and `vminitd` as guest PID 1. The universal initramfs
therefore does not apply verbatim; the **activation contract** applies
through `vminitd`'s existing gRPC API instead. The contract, the guest
binaries, the mount logic (`mvm_agentd::guest_mount`), and the RPC surface
are unchanged.

## Design

```text
Firecracker / libkrun / HVF / QEMU / WHP:  kernel + universal initramfs
                                           → agent is PID 1 → ActivateEnvironment over vsock:5252

Apple Container:                           framework kernel + vminitd (PID 1, vsock:1024)
                                           → host drives SandboxContext gRPC
                                           → agent started as root process → same mounts → uid 901
```

Activation equivalence:

| Contract step | Runner backends | Apple Container |
| --- | --- | --- |
| Fail-closed init gate | agent is PID 1; only `ActivateEnvironment` accepted | agent started only after host prepares env; agent's own RPC gate unchanged (`NotActivated` until activation completes) |
| Root env delivery | `ActivateEnvironment` over vsock:5252 | serialized `ActivateEnvironment` written via `WriteFile` to `/run/mvm/activation.json`, then `CreateProcess`/`StartProcess` for the agent with `MVM_ACTIVATION_FILE` |
| Rootfs + overlay mount | agent `guest_mount` (dm-verity, plain, virtiofs) | identical — the agent runs as root in the container VM, which has `CAP_SYS_ADMIN`; block devices are attached by the framework |
| Pivot | `pivot_to_root` (PID 1 owns `/`) | agent `chroot`s workload children into the verified root; vminitd keeps `/` |
| Privilege drop | uid/gid 901 | uid/gid 901 (same `WORKLOAD_UID`/`WORKLOAD_GID`) |
| Operational RPCs | vsock:5252 | vsock:5252, reached through `ProxyVsock` or direct CID connect |
| Egress gate | per-VM substitution endpoint | unchanged (host-side, same seam) |

What is honestly different, and must be documented as such:

- The kernel is supplied by the framework (or by us through the framework's
  kernel slot), not bundled by mvm. Verified boot of the rootfs still holds —
  dm-verity runs in-guest — but the *kernel image* chain of custody is the
  framework's, exactly like libkrun's bundled kernel.
- The fail-closed gate is weaker at the very first hop: `vminitd`'s own gRPC
  listens from boot. That surface is Apple's signed component, not a
  workload-reachable mvm verb; the mvm agent still refuses every operational
  RPC until activation. This is recorded as a named caveat in the backend's
  `security_profile()`, mirroring how Tier-2 caveats are recorded today.

## Milestones

### Stage 1 — Backend skeleton (this change)

- `BackendKind::AppleContainer`; `AnyBackend::AppleContainer`.
- `AppleContainerBackend` implementing `VmBackend`: construction does no I/O;
  `capabilities()` reports nothing supported; `security_profile()` records
  the tier honestly; every operation fails closed with a typed
  `AppleContainerError` naming the milestone that provides it (mirrors
  `WasmBackend`'s `NotCompiledIn` discipline).
- Catalog descriptor: selector `apple-container`, aliases `["container"]`,
  never auto-selected, not in `started_vm_probe_descriptors`, Tier 2.
- Tests: selector resolves; auto-select never returns it; capabilities and
  security profile are honest; `start`/`stop`/`wait`/`pause`/`resume`/
  `snapshot`/`warm_start` all fail closed with the typed error.
- Gate: workspace clippy + tests + policy xtasks green.

### Stage 2 — Swift Containerization shim

- New SwiftPM package `swift/container-shim/` vendoring
  `github.com/apple/containerization` (pin to a tagged release; record the
  pin and its SHA in the shim's `Package.swift` comment and in
  `xtask check-forbidden-deps` allowance if the checker scans it).
- `@_cdecl` exports: `mvm_ac_create(config_json) -> handle`,
  `mvm_ac_start(handle)`, `mvm_ac_stop(handle)`,
  `mvm_ac_vsock_fd(handle, port) -> fd`, `mvm_ac_destroy(handle)`.
  Config JSON carries: kernel path, rootfs block, verity sidecar, overlay
  pair, virtiofs shares, cpus/mem, vm name.
- Rust binding crate `crates/mvm-runtime/src/apple_container/sys.rs`
  (hand-written `extern "C"`, `// SAFETY:` per call) built by `build.rs`
  invoking `swift build` behind the `apple-container` Cargo feature —
  off by default so the default build has no SwiftPM dependency (same
  discipline as `wasm-backend`).
- Kernel: reuse the mvm workload kernel artifact
  (`mvmctl kernel build --which workload`) in the framework's kernel slot.
- Entitlements: add `com.apple.vm.networking` to
  `assets/mvmctl.entitlements` only if the endpoint path needs vmnet;
  document the codesign step in the milestone PR.
- Verification: a macOS-only `#[cfg(all(target_os = "macos",
  feature = "apple-container"))]` smoke test that creates and destroys a VM
  running the stock container kernel — gated `MVM_AC_E2E=1`, ignored by
  default (mirrors `MVM_LIBKRUN_E2E`).

### Stage 3 — vminitd gRPC-over-vsock transport

- Generate prost types from `crates/mvm-runtime/src/vm/proto/sandbox_context.proto`
  (`prost-build` in the existing build pipeline; the proto is already
  vendored).
- Transport: HTTP/2 gRPC over the shim's vsock fd using `tonic` with a
  custom connector, or `h2` hand-framed if the `tonic` dependency tree is
  rejected at audit time — decision recorded in the stage-3 PR after
  `cargo deny` output.
- Fill `vm/vminitd_client.rs` (typed interface already exists): `WriteFile`,
  `CreateProcess`, `StartProcess`, `WaitProcess`, `KillProcess`,
  `ProxyVsock`, `Mount`.
- Tests: in-process mock gRPC server over a Unix socket pair asserting the
  exact request bytes for the activation sequence; no Apple framework
  required.

### Stage 4 — Activation through vminitd + driver wiring

- `AppleContainerDriver: VmmDriver` assembling the framework VM config from
  `VmmSpec` (blocks: rootfs `/dev/vda`, verity `/dev/vdb`, overlay
  `/dev/vdc`+`/dev/vdd`; virtiofs shares; vsock ports 1024 + 5252).
- Boot sequence: shim create/start → connect vminitd:1024 →
  `WriteFile(/run/mvm/activation.json)` with the serialized
  `ActivateEnvironment` (same builder as `microvm::activation`) →
  `CreateProcess` + `StartProcess` for `/sbin/mvm-guest-agent
  --activation-file /run/mvm/activation.json` as uid 0 → agent performs the
  identical `guest_mount` sequence and drops to uid 901 → host connects
  vsock:5252 and proceeds through the standard `WorkloadRunner` broker/exit
  wiring.
- Agent flag: `--activation-file <path>` added to `mvm-guest-agent` (reads
  the env, applies it, then serves; fails closed on malformed JSON).
- Verification: `MVM_AC_E2E=1` macOS smoke booting the dev image to
  `Ping`; dm-verity sealed smoke reusing the existing
  `mvm-ext4 output mounts on the real kernel` lane's artifacts where
  possible; BDD scenario under `features/suites/` mirroring the
  initramfs-cache feature.

## Constraints that do not change

- `ActivateEnvironment` semantics, `guest_mount`, uid 901, the
  `NotActivated` gate, the egress endpoint, and the broker registration are
  shared verbatim. No backend-specific fork of the guest agent.
- Auto-select never returns this backend (opt-in only) until it carries a
  production tier, same discipline as QEMU.
- `BackendKind` exhaustiveness is load-bearing: the stage-1 ripple across
  match sites is intentional and keeps every dispatch site honest.

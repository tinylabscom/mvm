# Plan 271: Apple Container backend — same boot contract through vminitd

**Status:** Stage 1 (backend skeleton) and stage 2 (Swift shim + Rust
client + backend wiring through vminitd injection) implemented; stage 3
collapsed into the shim; stage 4 (agent bring-up) remains.
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

### Stage 2 — Swift Containerization shim (implemented)

- SwiftPM package `swift/mvm-container-shim/` (swift-tools-version 6.2,
  platforms macOS 26, `apple/containerization` from 0.6.0) — one detached
  executable per VM, mirroring the other per-VM supervisors. It takes
  `--spec <path>` (JSON boot spec: kernel, initfs, cpus/mem, rootfs,
  blocks, virtio-fs shares, control socket, agent port, boot-log dir),
  builds `Kernel` + initfs `Mount` + `VZVirtualMachineManager` +
  `LinuxContainer` (`useInit = true`, no network interfaces, blocks +
  shares as mounts), and serves newline-delimited JSON RPC on the control
  socket: `ping`, `stop`, `kill`, `wait`, `vminitd_write_file`,
  `vminitd_mkdir`, `vminitd_mount`, `vminitd_create_process`,
  `vminitd_start_process`, `vminitd_wait_process`, `vminitd_signal`, and
  `dial_vsock` (fd handoff via SCM_RIGHTS: ok response line, then one
  sendmsg with a 1-byte payload + the fd).
- Rust side `crates/mvm-runtime/src/apple_container/`: `spec.rs` (the
  serde spec + pure `VmStartConfig` → spec mapping with the vda/vdb/vdc/
  vdd block order and `device_only` marking for verity sidecars) and
  `shim_client.rs` (detached spawn, newline-JSON client, SCM_RIGHTS
  receive; framing unit-tested against an in-process mock server).
- Backend wiring in `apple_container_backend.rs`: artifact resolution from
  `<mvm_cache>/apple-container/` (shim binary, kernel, initfs) with typed
  `ArtifactMissing { what, path, hint }` errors naming the exact fetch;
  `stop`/`stop_all`/`status`/`list`/`wait`/`logs` via the shim and the
  pid-file conventions the QEMU backend established.
- File injection rides `LinuxContainer.copyIn` (streaming copy channel),
  not `Vminitd.writeFile` — `WriteFileFlags` has no public constructor in
  0.6.0 (internal init), so the unary write is unreachable outside the
  framework module.
- Build + sign: `scripts/build-apple-container-shim.sh` (swift build,
  install to `<MVM_HOME>/cache/apple-container/bin/`, codesign with
  `assets/mvmctl.entitlements`), wired as `just apple-container-shim`.
- Entitlements: `com.apple.security.virtualization` covers the boot; no
  network interfaces are attached, so `com.apple.vm.networking` is not
  needed.
- What stage 2 deliberately does NOT do: launch the guest agent. The agent
  has no activation-file entry point yet, so `start_with_mode` boots,
  injects, tears the VM down, and returns a typed `NotImplemented` naming
  stage 4.
- Verification: spec-mapping and shim-framing unit tests; a macOS-only
  `MVM_AC_E2E=1` gated smoke (`#[ignore]`) that boots a framework VM and
  injects files when the artifacts exist.

### Stage 3 — collapsed into the shim

The Rust-side vminitd gRPC-over-vsock transport (prost + tonic/h2 from the
vendored proto) is **not built**: the Swift shim owns the vminitd gRPC via
the framework's own `Vminitd` client, and Rust speaks newline-JSON +
SCM_RIGHTS to the shim. This removes the proto-generation and
transport-dependency milestones entirely; `crates/mvm-runtime/src/vm/
vminitd_client.rs` stays the typed interface doc for the port constants.

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

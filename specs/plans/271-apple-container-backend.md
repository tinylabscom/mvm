# Plan 271: Apple Container backend — same boot contract through vminitd

**Status:** Stages 1–3 implemented (backend skeleton; HVF boot + vminitd transport + injection; agent container-mode activation + real bring-up). Stage 4 (runner/driver parity + e2e validation) designed below.
**Owner:** mvm core.
**Depends on:** universal initramfs + `ActivateEnvironment` (PR #1914).

> **Design change (stage 2, as built):** the Swift/Virtualization.framework
> shim originally planned for stage 2 was abandoned (PR #1939 closed). The
> container kernel and the `initfs.ext4` that carries `/sbin/vminitd` boot
> on mvm's own HVF supervisor instead — no Swift, no
> Virtualization.framework, no `swift/` tree. Apple's code runs only
> guest-side, unmodified. Stages 2–4 below describe the design as built.

## Goal

An `--hypervisor apple-container` backend that runs mvm workloads inside
Apple's Containerization-framework VMs with the **same guest-visible
functionality** as every other backend: a fail-closed init gate, an
environment-activation step, dm-verity rootfs + runtime overlay, virtio-fs
volumes, privilege drop to uid 901, and the standard operational RPC surface
after activation.

Apple's containerization package supplies two guest-side artifacts we do
not rebuild: the container kernel and `vminitd` as guest PID 1. The boot
itself runs on mvm's own HVF supervisor (the original Swift/
Virtualization.framework shim design was abandoned — see the status note
above). The universal initramfs therefore does not apply verbatim; the
**activation contract** applies through `vminitd`'s existing gRPC API
instead. The contract, the guest binaries, the mount logic
(`mvm_agentd::guest_mount`), and the RPC surface are unchanged.

## Design

```text
Firecracker / libkrun / HVF / QEMU / WHP:  kernel + universal initramfs
                                           → agent is PID 1 → ActivateEnvironment over vsock:5252

Apple Container:                           container kernel + initfs.ext4 on the in-house HVF VMM,
                                           init=/sbin/vminitd (PID 1, vsock:1024)
                                           → host drives SandboxContext gRPC over the supervisor's
                                             vsock port bridge
                                           → agent started as root process → same mounts → uid 901
```

Activation equivalence:

| Contract step | Runner backends | Apple Container |
| --- | --- | --- |
| Fail-closed init gate | agent is PID 1; only `ActivateEnvironment` accepted | agent started only after host prepares env; agent's own RPC gate unchanged (`NotActivated` until activation completes) |
| Root env delivery | `ActivateEnvironment` over vsock:5252 | serialized `ActivateEnvironment` written via `WriteFile` to `/run/mvm/activation.json`, then `CreateProcess`/`StartProcess` for the agent with `MVM_ACTIVATION_FILE` |
| Rootfs + overlay mount | agent `guest_mount` (dm-verity, plain, virtiofs) | identical — the agent runs as root in the container VM, which has `CAP_SYS_ADMIN`; block devices are attached by the HVF supervisor in the activation environment's fixed slot order |
| Pivot | `pivot_to_root` (PID 1 owns `/`) | agent `chroot`s workload children into the verified root; vminitd keeps `/` |
| Privilege drop | uid/gid 901 | uid/gid 901 (same `WORKLOAD_UID`/`WORKLOAD_GID`) |
| Operational RPCs | vsock:5252 | vsock:5252, reached through `ProxyVsock` or direct CID connect |
| Egress gate | per-VM substitution endpoint | unchanged (host-side, same seam) |

What is honestly different, and must be documented as such:

- The kernel is an Apple-built artifact cached on the host, not bundled by
  mvm. Verified boot of the rootfs still holds —
  dm-verity runs in-guest — but the *kernel image* chain of custody is the
  artifact cache's, exactly like libkrun's bundled kernel.
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

### Stage 2 — HVF boot of the Apple guest stack + vminitd transport (this change)

- Boot path: the container kernel (`vmlinux`) and `initfs.ext4` resolve from
  `<mvm-cache>/apple-container/` (typed `ArtifactMissing{what,path,hint}`
  naming the build command — `make kernel` / `make init` from Apple's
  containerization package) and boot on the in-house HVF supervisor. The
  initfs is the **root block device**, attached *last* so the workload disks
  keep the activation environment's fixed slot names (rootfs `/dev/vda`,
  verity `/dev/vdb`, overlay `/dev/vdc`, overlay verity `/dev/vdd`); the
  cmdline is `console=ttyAMA0 … root=/dev/vd<last> rw init=/sbin/vminitd`.
  Deviation from Apple's own runtime, documented: their cmdline uses
  `console=hvc0` (virtio-console), which our VMM does not implement — the
  PL011 UART is the only serial console, so the console token differs and
  nothing else does.
- Disk shapes: sealed (both verity sidecars) and plain (neither) only;
  partial sets, virtiofs-root dev boots, separate initrds, and extra
  block-device volumes fail closed with a typed `UnsupportedConfig`.
- vminitd's control channel (guest vsock port 1024) rides the supervisor's
  existing port-bridge mechanism (`console_data_sockets` →
  `ConsoleBridge::bind_ports`), one host UDS per guest port — no new VMM
  code.
- Transport: `h2` + hand-written `prost` wire types (no protoc/
  `prost-build` in the pipeline; `h2`/`http` were already in the lockfile
  via the S3 client tree). A hand-rolled HTTP/2 client was rejected: HPACK
  *decoding* (dynamic tables + Huffman) cannot honestly be minimized. The
  client is a blocking facade over a single-threaded tokio runtime so the
  rest of the backend stays synchronous.
- Injection: `Mkdir /run/mvm` → `WriteFile` agent binary (0755) →
  `WriteFile` activation.json (0644, the same `ActivateEnvironment` builder
  every backend uses) → `CreateProcess` (uid 0, `MVM_ACTIVATION_FILE` set)
  → `StartProcess`.
- Fail-closed edge: the agent has no non-PID-1 activation entry point yet,
  so a fully successful `start` tears the VM down and returns a typed
  `NotImplemented` naming that milestone. `stop`/`status` are real
  (pid-file, same convention as the HVF driver); `wait`/`logs`/`pause`/
  `resume` stay fail-closed.
- Tests: mock h2 gRPC server over `tokio::io::duplex` asserting the exact
  activation-sequence frames + error paths; pure boot-spec mapping tests
  (sealed/plain/partial/refusals); artifact resolution tests; pid-guard
  test; pid-file stop/status tests. E2E: `MVM_AC_E2E=1`, `#[ignore]`d.

### Stage 3 — Agent non-PID-1 activation entry + real bring-up (this change)

- Agent entry: `MVM_ACTIVATION_FILE=<path>` selects the activation entry
  mode at startup (`select_activation_entry`): PID 1 always keeps the
  RPC-driven path (a stray file is ignored so it can never self-activate
  an initramfs boot); not-PID-1 with the file self-activates in
  **container mode** before the first accept; not-PID-1 without it keeps
  the legacy no-op behavior.
- Container mode: `unshare(CLONE_NEWNS)` + recursive-private propagation
  FIRST (no mount can perturb vminitd's namespace), then the identical
  mount sequence as the PID-1 path — `mount_rootfs` (verity/plain/
  virtio-fs), `mount_runtime_overlay`, `mount_volumes` — then
  `pivot_to_root_container` (MS_MOVE for real mounts, a fresh
  proc/sysfs/devtmpfs mount when the source is not a mountpoint of its
  own), then `drop_privilege(901, 901)`. The ordered steps are built by
  `container_activation_plan` (pure, unit-tested per rootfs shape incl.
  `in_place`) and executed step-for-step. The SIGCHLD reaper stays
  PID-1-only; the `ActivationState` transitions (`Activating` →
  `Activated`/`Failed`) match the PID-1 path exactly. A missing/malformed
  file is a typed error and a non-zero exit, never a panic.
- Bring-up: the injection additionally writes the host-signer trust
  anchor (`/run/mvm/host-signer.pub`, without which the agent rejects all
  control connections), and `start` then waits for the agent to answer an
  authenticated Ping on vsock:5252 (the standard session handshake every
  backend uses) instead of tearing down. `wait` rides vminitd
  `WaitProcess` on the agent process; `logs` reads the console capture;
  `stop` SIGTERMs the agent via vminitd before terminating the
  supervisor; `list`/`stop_all` key on an `apple-container.marker` state
  file (the pid-file convention is shared with the HVF driver). Rollback
  on any failure is unchanged.
- `device_only` sidecars: verified — the boot spec attaches verity
  sidecars as plain read-only virtio-blk devices in the activation
  environment's fixed slot order (rootfs/verity/overlay/overlay-verity,
  initfs last); a test pins the order, the read-only flag, and
  file-backed (non-ephemeral) attachment for every disk.

### Stage 4 — Runner/driver parity + e2e validation

- Live validation with the real artifacts (the only remaining functional
  gate): `MVM_AC_E2E=1 MVM_AC_E2E_ROOTFS=<plain ext4>` macOS smoke booting
  to an authenticated `Ping`, then `stop`; dm-verity sealed smoke reusing
  the existing `mvm-ext4 output mounts on the real kernel` lane's
  artifacts where possible; claim-by-claim review of `security_profile()`
  afterwards.
- `AppleContainerDriver: VmmDriver` or equivalent wiring so admitted plans
  reach the backend with the same egress/broker relay sockets the HVF
  driver assembles (the bring-up leaves them unwired).
- virtio-fs shares for `DirShare` volumes through the supervisor's
  virtiofs device (only the root share exists today).
- BDD scenario under `features/suites/` mirroring the initramfs-cache
  feature.

## Constraints that do not change

- `ActivateEnvironment` semantics, `guest_mount`, uid 901, the
  `NotActivated` gate, the egress endpoint, and the broker registration are
  shared verbatim. No backend-specific fork of the guest agent.
- Auto-select never returns this backend (opt-in only) until it carries a
  production tier, same discipline as QEMU.
- `BackendKind` exhaustiveness is load-bearing: the stage-1 ripple across
  match sites is intentional and keeps every dispatch site honest.

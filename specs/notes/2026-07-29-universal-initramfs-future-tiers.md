# Universal initramfs: future tiers and backends (Wasm, Docker, Apple Container, WHP)

Date: 2026-07-29
Status: design note — no implementation committed. Captures how the
universal-initramfs + `ActivateEnvironment` boot contract (PR #1914) extends
to tiers that do not provide a Linux kernel with virtio-blk/virtio-fs and
`AF_VSOCK` today. User-facing summary lives in
`public/src/content/docs/architecture/boot-flow.md` ("Future tiers and
backends").

## Wasm (`WasmBackend`)

- Constraint source: ADR-024 (`specs/adrs/024-wasm-sandbox-backend.md`) —
  opt-in only, never auto-selected, honest capabilities, zero numbered
  claims, fail-closed on kernel/verified-boot/vsock requests, and
  engine-in-guest if it ever executes real workloads.
- Boot contract: implemented in adapted form as the **capability
  handshake** (`crates/mvm-runtime/src/wasm_activation.rs`). Preopens
  instead of mounts: the runtime-overlay guest binaries are preopened
  read-only at `/mvm/runtime`, each `DirShare` volume at its guest
  mountpoint with read-only honored (`Disk` volumes fail closed, as do
  volume paths that fail mount-path policy). Policy/grant delivery instead
  of a vsock verb: an `activation.json` (overlay guest path, volume
  mountpoints, network-policy posture label, grant presence) is written
  into a per-run 0700 directory preopened read-only at `/run/mvm`, with
  `MVM_ACTIVATION_FILE` set in the module's env. The grant itself is a
  signed host artifact and only its presence travels — there is no
  in-guest signature verification because the WASI host is the trust
  boundary. The WASI capability model is the `NotActivated` analog: the
  module receives exactly the capabilities the plan admits and nothing
  else. Rootfs: WASI has no mountable root — the module's filesystem view
  IS its root (the in-place analog of a container's image root).
- Open design work (unwritten, per ADR-024 consequences): the promotion path
  from a demo session to a claims-bearing production microVM.

## Docker / shared-kernel containers

- Constraint source: ADR-034 (`specs/adrs/034-docker-dev-tier-backend.md`) —
  an opt-in, never-auto-selected, prod-refused shared-kernel container dev
  tier, applying the ADR-024 discipline (honest capabilities, fail closed,
  none of the hardware-isolation claims) to a Docker substrate. The default
  and production rules are unchanged: a host with no microVM backend still
  fails closed on every path it did not explicitly opt out of.
- Implemented design: `DockerBackend` (`crates/mvm-runtime/src/docker_backend.rs`)
  runs the container with the identical static `mvm-guest-agent` bind-mounted
  read-only as `/init` (PID 1 of the container's PID namespace),
  `--network none`, `--security-opt no-new-privileges`, the runtime-overlay
  guest binaries bind-mounted read-only at `/mvm/runtime`, and DirShare
  volumes as read-only-honored bind mounts. The agent listens on AF_UNIX
  (`MVM_AGENT_TRANSPORT=unix`) instead of vsock — the only guest-side
  transport change; the socket lives on a host-owned 0700 directory
  bind-mounted into the container, and that directory's permissions are the
  peer boundary (deliberately weaker than the vsock host-CID gate). After
  start the host delivers `ActivateEnvironment` over that socket: the root
  is `in_place` (the container already owns `/` — no mount, no pivot), so
  activation is the uid-901 drop and the `NotActivated` gate flip. Egress,
  when the policy allows it, rides the same per-VM substitution endpoint
  over a bind-mounted socket the in-container forward proxy relays to.
  Kernel/initrd boot, dm-verity, block volumes, snapshots, pause/resume,
  warm start, and the standby pool all fail closed with typed errors.
- Boot contract: adapted, not shared literally. Container init IS
  `mvm-guest-agent` (unlike the arbitrary container this note originally
  considered), but mounts are host bind mounts, not dm-verity block
  devices, and claims 1/2/3/6 report `DoesNotHold`. Prod admission refuses
  the tier structurally (`as_workload_backend` → `None`, Tier 3,
  `is_workload: false`).

## Apple Container

- Today: the backend boots Apple's guest stack — the container kernel and
  the `initfs.ext4` that carries `vminitd` — on mvm's own HVF supervisor
  behind `--hypervisor apple-container` (alias `container`), opt-in only and
  never auto-selected. The Swift/Virtualization.framework shim originally
  planned for this stage was abandoned; Apple's code now runs only
  guest-side, unmodified. The two artifacts resolve from
  `<mvm-cache>/apple-container/` with typed, hint-carrying errors; the boot
  attaches the initfs as the root block device (last slot, so the workload
  disks keep the activation environment's fixed device names) with
  `init=/sbin/vminitd`; and the host drives `vminitd`'s SandboxContext gRPC
  (h2 transport over the supervisor's vsock port bridge, hand-written prost
  wire types) to inject the guest agent and the serialized
  `ActivateEnvironment` and start the agent as a root process. The final
  agent bring-up step stays fail-closed — the agent has no non-PID-1
  activation entry point yet — so `start` tears the VM down and returns a
  typed error naming that milestone; `stop`/`status` are real (pid-file),
  `wait`/`logs`/`pause`/`resume` fail closed, and the security profile still
  reports all seven claims `DoesNotHold`. The staged design lives in
  `specs/plans/271-apple-container-backend.md`.
- Remaining shape: the agent's non-PID-1 activation entry (mount namespace
  + `chroot` instead of `pivot_root`, reading the injected activation file),
  then runner/driver parity (egress/broker relay sockets, virtio-fs shares
  for `DirShare` volumes). The agent performs the same mounts and the
  uid-901 drop unchanged. Capability and security-profile honesty rules from
  ADR-024 apply verbatim.

## QEMU (converged onto the unified runner)

- Today: QEMU boots through the unified `WorkloadRunner` via
  `crates/mvm-runtime/src/driver/qemu.rs` (`QemuDriver`), the same seam as
  Firecracker/libkrun/HVF. A QEMU boot attaches the universal initramfs and
  receives `ActivateEnvironment` over vsock exactly like the other backends;
  the legacy `mvm.roothash=`/`mvm.data=`/`mvm.hash=` cmdline tokens are no
  longer built by this path. Because QEMU's `vhost-vsock` speaks real
  `AF_VSOCK`, the driver spawns a spec-driven per-VM `AF_VSOCK`↔UNIX bridge
  (one detached `mvmctl __qemu-vsock-bridge` process) that serves the
  host-dialed agent channel, relays the guest-dialed egress/broker channels
  to the runner-bound listeners, and captures the workload-exit report.
- Tier/status unchanged: dev/test tier only (Tier 2 best-case on KVM, TCG
  runtime fallback banner-flagged), opt-in via `--hypervisor qemu`, never
  auto-selected, and still barred from the admitted workload funnel. The
  converged boot attaches no slirp user-mode NIC — egress routes solely
  through the per-VM vsock endpoint, matching the other runner backends.
  The raw `QemuBackend` remains as the driver's identity delegate.

## WHP (Windows Hypervisor Platform)

- Guest side: unchanged — same kernel + universal initramfs, same
  `ActivateEnvironment`, dm-verity executed in-guest, so verified boot is
  host-agnostic.
- Host side work items:
  1. A WHP `VmmDriver` behind the driver seam
     (`crates/mvm-runtime/src/driver/traits.rs`).
  2. virtio-blk / virtio-fs device model wiring so the fixed slot layout
     (`/dev/vda`…`/dev/vdd`) is honored.
  3. A vsock transport over Hyper-V sockets (`AF_HYPERV`) in place of
     `AF_VSOCK`, behind the same connect/send seam
     (`mvm-agentd::vsock::GUEST_AGENT_PORT` protocol unchanged).
  4. The per-VM gating endpoint for egress (claims 10/12/13) before any
     production tier claim.
- Tiering expectation: Tier 2 (like HVF/libkrun) once the egress gate
  lands; verified boot should hold because dm-verity is guest-side. Until a
  WHP backend exists, WSL2 with nested `/dev/kvm` is the supported
  Windows-adjacent path (already documented in matryoshka.md "Choosing a
  tier").

## Invariants to preserve when adding any of these

- Fail-closed on every capability the tier lacks (typed error naming the
  supported alternative) — never silently drop a security-relevant
  requirement.
- Capability matrices and `security_profile()` report the tier honestly;
  no claim-table promotion without a named ADR.
- `ActivateEnvironment` remains the only pre-privilege-drop control verb on
  any Linux-kernel boot that attaches the universal initramfs.

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

- **Removed by Plan 329.** The Docker dev-tier backend described in
  ADR-034 has been deleted. MVM is microVM-only: a host without a usable
  hypervisor fails closed rather than falling back to a shared-kernel
  container. The ADR-034 discipline (honest capabilities, fail closed, none
  of the hardware-isolation claims) is preserved in the sense that the tier
  no longer exists; there is nothing to fence.
- Historical design: `DockerBackend` (`crates/mvm-runtime/src/docker_backend.rs`)
  ran the container with the static `mvm-guest-agent` bind-mounted read-only
  as `/init`, `--network none`, `--security-opt no-new-privileges`, runtime
  overlay guest binaries bind-mounted read-only at `/mvm/runtime`, and
  DirShare volumes as read-only-honored bind mounts. The agent listened on
  AF_UNIX instead of vsock, with the socket on a host-owned 0700 directory
  bind-mounted into the container. Activation carried an `in_place` rootfs
  (the container already owned `/`). Egress, when allowed, rode the same
  per-VM substitution endpoint. Kernel/initrd boot, dm-verity, block
  volumes, snapshots, pause/resume, warm start, and the standby pool all
  failed closed with typed errors.

## Apple Container

- Today: the backend is the HVF workload runner with Apple's prebuilt
  container kernel substituted for the boot image, behind
  `--hypervisor apple-container` (alias `container`), opt-in only and never
  auto-selected. Earlier designs — a Swift/Virtualization.framework shim,
  then booting Apple's `vminitd` initfs and driving its gRPC API — were
  both abandoned: vminitd is Swift with no prebuilt artifact, so the final
  design is 100% Rust-native (zero Swift, zero Virtualization.framework;
  `xtask check-no-vz` guards this). The kernel resolves from
  `<mvm-cache>/apple-container/vmlinux` with a typed, hint-carrying error
  when missing; the backend sets it as the launch's `kernel_path` and
  delegates the entire lifecycle to `hvf_runner()` — the same universal
  initramfs, the same agent-as-PID-1, the same `ActivateEnvironment`
  flow, egress gate, and RPC surface as `--hypervisor hvf`.
  `capabilities()` and the claims array mirror the HVF runner verbatim;
  the profile notes record that the kernel is a fetched artifact whose
  provenance is not an mvm build. The design lives in
  `specs/plans/271-apple-container-backend.md`.
- Remaining shape: live e2e validation with a real fetched kernel (boot a
  dev image to `Ping`, sealed-boot smoke), then a claim-by-claim review.
  Capability and security-profile honesty rules from ADR-024 apply
  verbatim.

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

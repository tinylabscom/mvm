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
- Boot contract: not applicable as-is (no Linux kernel, no initramfs, PID 1
  is the wasmtime host process). The analog is a capability handshake over
  the wasm import channel, extending the existing host-mediated `mvm:egress`
  import seam: admission binds policy, the module receives exactly the host
  functions the plan admits.
- Open design work (unwritten, per ADR-024 consequences): the promotion path
  from a demo session to a claims-bearing production microVM.

## Docker / shared-kernel containers

- Constraint source: `public/src/content/docs/security/matryoshka.md` ("No
  container fallback") — mvm has no Tier 3; a host with no microVM backend
  fails closed rather than dropping to a weaker boundary.
- Boot contract: cannot apply without becoming a microVM. Container init is
  not `mvm-guest-agent`; mounts are host-kernel namespaces, not dm-verity
  block devices. A future container tier would be dev-tier only, refused by
  prod admission (same discipline as the Lima test-tier exception in
  `AGENTS.md`), and would carry its own explicitly weaker boot contract
  rather than sharing the universal initramfs.

## Apple Container

- Today: the stage-1 backend skeleton exists — `BackendKind::AppleContainer`
  and `AnyBackend::AppleContainer` behind `--hypervisor apple-container`
  (alias `container`), opt-in only and never auto-selected. Every operation
  fails closed with a typed error naming the milestone that provides it;
  capabilities and the security profile report honestly (no snapshot, no
  standby pool, all seven claims `DoesNotHold`). The staged design lives in
  `specs/plans/271-apple-container-backend.md`. Two doc comments in
  `crates/mvm-runtime/src/backend.rs` still name Apple Container
  (`start` example, `for_started_vm` probe) — they describe the real
  variant's eventual shape (no pid-file marker; the framework tracks VM
  state out-of-band).
- Future support shape: Apple's Swift-only framework owns the kernel boot
  and `vminitd` as guest PID 1 (gRPC on vsock port 1024), so the universal
  initramfs does not apply verbatim — the **activation contract** rides
  `vminitd`'s gRPC API instead. The host writes the serialized
  `ActivateEnvironment` into the container VM, starts `mvm-guest-agent` as
  a root process, and the agent performs the same mounts and the uid-901
  drop unchanged. Capability and security-profile honesty rules from
  ADR-024 apply verbatim.

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

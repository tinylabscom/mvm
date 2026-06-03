# ADR 069 - `wasm-sandbox` portable backend (non-microVM)

**Status**: Proposed
**Date**: 2026-06-03
**Cross-refs**: ADR-002 (security posture — wasm-sandbox is OUTSIDE its claim
set), ADR-066 (target architecture — `VmBackend` seam), Plan 144

## Context

mvm's real backends provide hardware-isolated microVMs (Firecracker/KVM,
Apple VZ, Cloud Hypervisor, libkrun). We also want a backend that runs in
browser/WASM and WASI-like environments for demos, docs playgrounds, and
deterministic repros. Browsers expose none of the primitives the security model
depends on: no KVM, no Apple VZ, no TAP, no virtio, no vsock, no privileged
mounts. A backend in that environment therefore cannot honestly claim microVM
isolation — but it can still be useful if it is explicit about what it is.

## Decision

### 1. Add a `wasm-sandbox` backend that reports its non-virtualization honestly

It implements the existing `VmBackend` seam and declares a `BackendCapabilities`
matrix with `hardware_virtualization=false`, `kvm=false`,
`real_linux_kernel=false`, `tap_networking=false`, `virtio=false`,
`vsock=false`, `virtual_filesystem=true`, `logical_snapshots=true`,
`browser_compatible=true`, `network_mode=ProxyOnly`. It is opt-in only
(`--hypervisor wasm-sandbox`/`browser`); `auto_select()` never returns it.

### 2. Fail closed on microVM-only requests

Kernel image, TAP networking, vsock, raw block passthrough, and host mounts each
return an explicit typed `WasmSandboxError` naming the supported alternative.
The artifact validator rejects any artifact whose `BackendCompat` row demands a
kernel format (wasm-sandbox accepts none).

### 3. It provides NONE of the ADR-002 numbered security claims

The wasm-sandbox is a portability/demo tier, not an isolation tier. ADR-002's
threat model and per-backend tier matrix do not extend to it, and this ADR does
not request claim-table promotion.

## Alternatives

- Emulate a Linux kernel in WASM to "be a real microVM" — rejected: enormous,
  and still not hardware isolation; dishonest framing.
- Silently degrade (accept a kernel arg and ignore it) — rejected: violates
  "do not silently degrade security semantics".

## Consequences

- Differs from Firecracker/Vz/Cloud Hypervisor: no hardware boundary, no real
  kernel, proxy-only networking, logical (not memory) snapshots.
- Intended uses: browser demos, docs playground, deterministic repros,
  lightweight plugin sandbox, offline-ish development.
- Not for: production tenant isolation, untrusted multi-tenant compute, real
  kernel testing, real network-device testing.
- Future work (Plan 144 deferred follow-ups): real WASI execution, live
  websocket/MessageChannel transports, a `wasm32` browser build target.

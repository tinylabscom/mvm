---
title: "ADR-001: Multi-Backend VM Execution"
description: Architecture Decision Record for supporting multiple VM backends with Firecracker as primary.
---

## Status

Accepted (updated Sprint 38 -- expanded from Firecracker-only to multi-backend)

> **Note (superseded in part):** earlier drafts of this ADR mentioned Docker/container fallback and a legacy macOS runtime path. Those paths are no longer current product backends. The active matrix is Firecracker, HVF, libkrun, and explicit dev/test QEMU.

## Context

mvmctl needs VM backends for running isolated workloads across different platforms. Options considered:

1. **QEMU/KVM** -- Full hardware virtualization, maximum compatibility
2. **Firecracker** -- Purpose-built microVM monitor, minimal attack surface
3. **Hypervisor.framework / HVF** -- Native macOS 26+ virtualization, sub-second startup target
4. **libkrun** -- Lightweight microVM runtime for supported Linux/macOS hosts
5. **Container fallback** -- Rejected as a production workload runtime because it weakens the isolation boundary

## Decision

Use Firecracker as the primary production backend. Support multiple backends: HVF for native macOS Apple Silicon, libkrun where explicitly selected and supported, and QEMU as a dev/test backend. Auto-select the strongest backend available on the host and fail closed instead of silently dropping to a weaker container or legacy runtime.

## Rationale

- **Firecracker**: Minimalist design, strong Linux/KVM isolation, sealed snapshot support
- **HVF**: Native macOS Apple Silicon runtime with vsock-only workload egress and no guest NIC requirement
- **libkrun**: Useful Tier-2 bridge on supported hosts when operators explicitly opt in
- **Auto-selection**: Developers get the best supported backend on their platform without reworking artifacts
- **QEMU**: Real microVM dev/test path when explicitly requested; not a production fallback
- **Same rootfs**: All backends consume the same image/build outputs -- only the runtime differs

## Backend Selection Order

1. **Linux with `/dev/kvm`** -- Firecracker directly
2. **macOS 26+ Apple Silicon** -- HVF
3. **Explicit override on a supported host** -- libkrun
4. **Explicit dev/test override** -- QEMU
5. **Other hosts** -- unsupported for local microVM isolation today; mvm fails closed rather than falling back to containers

Override with `--hypervisor firecracker`, `--hypervisor hvf`, `--hypervisor libkrun`, or `--hypervisor qemu`.

## Consequences

- Requires native Linux with `/dev/kvm` for Firecracker, or macOS 26+ Apple Silicon for HVF
- libkrun support is scoped to supported Linux KVM and macOS Apple Silicon hosts; macOS Intel is not a supported local host
- WSL2 nested KVM and Hyper-V managed Linux builders are future backend work, not current support
- Guests must use a Linux kernel (no Windows/macOS guests)
- No OCI runtime fallback -- uses microVM backends only
- Shipped pause/resume recovery is backend-specific; current public docs publish Firecracker sealed snapshots and require explicit backend naming for any other restore path
- Limited device model -- no GPU passthrough, limited disk types

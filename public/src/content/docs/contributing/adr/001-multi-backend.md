---
title: "ADR-001: Multi-Backend VM Execution"
description: Architecture Decision Record for supporting multiple VM backends with Firecracker as primary.
---

## Status

Accepted (updated Sprint 38 -- expanded from Firecracker-only to multi-backend)

## Context

mvmctl needs VM backends for running isolated workloads across different platforms. Options considered:

1. **Docker/OCI containers** -- Widely adopted, large ecosystem
2. **QEMU/KVM** -- Full hardware virtualization, maximum compatibility
3. **Firecracker** -- Purpose-built microVM monitor, minimal attack surface
4. **Apple Virtualization.framework** -- Native macOS 26+ virtualization, sub-second startup
5. **Cloud Hypervisor** -- Similar to Firecracker, more features

## Decision

Use Firecracker as the primary production backend. Support multiple backends: Apple Virtualization.framework for native macOS dev, microvm.nix for NixOS-native QEMU, and Docker as a universal fallback. Auto-select the best backend based on platform capabilities.

## Rationale

- **Firecracker**: Minimalist design (<50K LOC), ~125ms cold boot, snapshot support, hardware isolation via KVM
- **Apple Container**: Sub-second startup on macOS 26+, native Hypervisor.framework, native vsock -- ideal for dev workflows
- **Auto-selection**: Developers get the best experience on their platform without manual configuration
- **Docker**: Universal fallback when no hypervisor is available -- pause/resume via container lifecycle, unix socket guest channel
- **microvm.nix**: NixOS-native QEMU runner with vsock and TAP networking support
- **Same rootfs**: All backends consume the same Nix-built ext4 image -- only the runtime differs

## Backend Selection Order

1. **KVM available** (native Linux with `/dev/kvm`) -- Firecracker directly
2. **macOS 26+** (Apple Silicon) -- Apple Virtualization.framework
3. **Docker running** -- Docker as container-based fallback
4. **Other** (macOS Intel, Linux without KVM, native Windows, WSL2) -- unsupported for local microVM isolation today; Docker remains a Tier 3 convenience fallback only

Override with `--hypervisor firecracker`, `--hypervisor vz`, `--hypervisor qemu`, or `--hypervisor docker`.

## Consequences

- Requires native Linux with `/dev/kvm` for Firecracker, or macOS 26+ Apple Silicon for Apple Container
- libkrun support is scoped to Linux KVM and macOS Apple Silicon; macOS Intel is not a supported local host
- WSL2 nested KVM and Hyper-V managed Linux builders are future backend work, not current support
- Guests must use a Linux kernel (no Windows/macOS guests)
- No OCI image compatibility -- uses Nix flakes for image building instead
- Snapshots only available on Firecracker backend
- Limited device model -- no GPU passthrough, limited disk types

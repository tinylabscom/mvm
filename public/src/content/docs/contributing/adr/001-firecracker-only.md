---
title: "ADR-001: Firecracker-Only Execution"
description: Architecture Decision Record for using Firecracker as the sole execution engine.
---

## Status

Accepted

## Context

mvm needs a VM engine for running isolated workloads. Options considered:

1. **Docker/OCI containers** — Widely adopted, large ecosystem
2. **QEMU/KVM** — Full hardware virtualization, maximum compatibility
3. **Firecracker** — Purpose-built microVM monitor, minimal attack surface
4. **Cloud Hypervisor** — Similar to Firecracker, more features

## Decision

Use Firecracker as the sole engine. No container runtime.

## Rationale

- **Security**: Firecracker's minimalist design (no BIOS, no USB, no PCI) reduces attack surface to <50K LOC
- **Performance**: ~125ms cold boot, ~5ms snapshot restore, minimal memory overhead
- **Snapshot support**: Built-in VM snapshotting enables the sleep/wake lifecycle
- **Predictable resources**: Each microVM gets dedicated vCPUs and memory, no noisy-neighbor
- **Multi-tenancy**: Hardware-level isolation via KVM, not namespace isolation

## Consequences

- Requires Linux with `/dev/kvm` (macOS uses Lima VM for nested virtualization)
- Guests must use a Linux kernel (no Windows/macOS guests)
- No OCI image compatibility — uses Nix flakes for image building instead
- Limited device model — no GPU passthrough, limited disk types

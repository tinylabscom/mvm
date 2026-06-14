---
title: Architecture
description: Workspace structure, backend layering, dependency graph, and canonical trait seams.
---

## Overview

`mvmctl` has two distinct execution layers:

- **Build layer**: Nix evaluation/builds and Linux-only host operations run through the
  shared builder VM.
- **Runtime layer**: a selected VM backend boots the finished guest artifacts.

The key design choice is that these layers are separated by traits. Build code depends on
build/environment traits; runtime code depends on `VmBackend`; host policy/audit code depends
on launcher and service traits.

## Multi-Backend Runtime Design

Concrete runtime backends implement `mvm_core::vm_backend::VmBackend` — the one runtime
behavior contract. Backend *discovery* (which backends exist and their metadata) lives in the
compile-time descriptor registry described below; the closed enum
`mvm_backend::backend::AnyBackend` is the dispatch layer for the operations that are still
genuinely backend-specific:

- applies platform auto-selection policy,
- preserves explicit backend selection (`--hypervisor ...`),
- routes already-started VMs back to the backend that owns their state.

### Runtime backend matrix

| Backend | Selection mode | Notes |
|---------|----------------|-------|
| Firecracker | Auto on Linux with native KVM | Production Tier 1 backend |
| Apple Container | Auto on supported macOS 26+ hosts | Preferred macOS local backend when available |
| libkrun | Auto fallback on supported hosts | Fast local Tier 2 backend |
| Vz | Explicit opt-in (`--hypervisor vz`) | Supported, but not auto-selected |
| QEMU | Explicit opt-in (`--hypervisor qemu`) | Linux dev/test backend |
| Mock | Explicit opt-in (`--hypervisor mock`) | Test-only in-memory backend |

The backend descriptor registry in `crates/mvm-backend/src/catalog.rs` is the single source of
truth for backend discovery: each `BackendDescriptor` carries the selector, aliases, isolation
tier, per-VM marker file, started-VM probe order, and the listing/support sets that `mvmctl
doctor` and `mvmctl ls` read. Both enum (`AnyBackend`) and trait-object (`Arc<dyn VmBackend>`)
consumers construct from the same descriptors via `instantiate` / `instantiate_dyn`.

## Workspace Structure

The workspace is organized by responsibility rather than by platform:

| Area | Crates | Role |
|------|--------|------|
| Core types and contracts | `mvm-core` | Shared types, protocols, config helpers, canonical lightweight traits |
| Runtime backends | `mvm-backend`, `mvm`, `mvm-vm-host` | VM lifecycle, backend adapters, per-VM host helpers |
| Build pipeline | `mvm-build` | Builder VM flow, artifact production, builder backend seams |
| Host policy / supervision | `mvm-hostd` | Admission, audit, policy enforcement, launch preparation |
| Guest / protocol surfaces | `mvm-guest`, `mvm-guest-helpers`, `mvm-mcp` | Guest agent and protocol-facing tooling |
| Domain-specific subsystems | `mvm-storage`, `mvm-network`, `mvm-oci`, `mvm-verify` | Storage, networking, OCI, audit verification |
| CLI / SDK surface | `mvm-cli`, `mvm-sdk`, `mvm-sdk-macros` | User interface and workload authoring APIs |

The root crate (`mvm`) is the facade/runtime integration crate. `mvm-cli` is the binary-facing
command surface.

## Dependency Graph

At a high level:

```text
mvm-core
├── mvm-storage
├── mvm-network
├── mvm-build
├── mvm-backend
├── mvm-hostd
├── mvm-guest
├── mvm
└── mvm-cli
```

Interpretation:

- `mvm-core` is the dependency root and should stay runtime-light.
- `mvm-backend`, `mvm-build`, and `mvm-hostd` are peer owning crates for their
  respective execution domains.
- `mvm-cli` sits at the top of the stack and composes the lower layers.

## Canonical Trait Seams

These are the main behavior seams in the current codebase:

| Trait | Owning crate | Purpose |
|-------|--------------|---------|
| `VmBackend` | `mvm-core` | Runtime VM lifecycle and capability contract |
| `ShellEnvironment` | `mvm-core` | Minimal shell/logging seam for build flows |
| `BuildEnvironment` | `mvm-core` | Extended build orchestration environment |
| `LinuxEnv` | `mvm-core` | Linux execution boundary abstraction |
| `KeyProvider` | `mvm-core` | Snapshot/secret key loading |
| `SecretStore` | `mvm-core` | Secret retrieval/storage seam |
| `ServiceHandler` | `mvm-core` | Protocol service dispatch |
| `BuilderVm` | `mvm-build` | High-level builder VM driver |
| `VmBackendForBuilder` | `mvm-build` | Low-level builder backend seam |
| `BackendLauncher` | `mvm-hostd` | Host-side backend launch preparation/execution |
| `NetworkProvider` | `mvm-network` | Network provisioning / policy seam |
| `VolumeBackend` | `mvm-storage` | Storage backend seam |

### Ownership rule

Reusable, runtime-light seams live in `mvm-core`.

That means traits like `VmBackend`, `KeyProvider`, `SecretStore`, and the build-shell
abstractions belong in `mvm-core` because many crates depend on them and they do not require
runtime-heavy backend code.

Backend- or subsystem-specific seams stay in the owning crate:

- `VmBackendForBuilder` belongs in `mvm-build`.
- `BackendLauncher` belongs in `mvm-hostd`.
- `NetworkProvider` belongs in `mvm-network`.
- `VolumeBackend` belongs in `mvm-storage`.

This keeps `mvm-core` small while still giving the rest of the workspace stable contracts.

## Runtime Flow

Runtime launch is layered:

1. `mvm-cli` parses intent and assembles launch configuration.
2. `mvm-hostd` handles admission, audit, and launch-time host policy.
3. `mvm-backend` selects a concrete `VmBackend` implementation.
4. The selected backend boots the Nix-built artifacts.

The ownership split is deliberate: `VmBackend` owns runtime behavior, the compile-time backend
descriptor registry owns backend discovery metadata and constructor wiring, and `AnyBackend`
remains a closed enum for the operations that are genuinely backend-specific (auto-selection
policy, explicit-variant handling). The registry is static, not a runtime plugin system — there
is no dynamic registration or dylib discovery. Generic consumers that only need behavior
construct an `Arc<dyn VmBackend>` straight from a descriptor instead of matching the enum.

## Build Pipeline

`mvmctl build` and related build flows do not boot workload backends directly.

Instead:

1. the host prepares a build request,
2. the builder VM performs the Linux/Nix work,
3. the produced artifacts are handed to the runtime layer,
4. a runtime backend boots those artifacts later.

The builder VM is the Linux execution boundary for Nix eval/builds and microVM-management
operations. It is not the same thing as the selected workload runtime backend.

## Platform Support

| Host platform | Default runtime path |
|---------------|----------------------|
| Linux with native KVM | Firecracker |
| Supported macOS 26+ host | Apple Container |
| Supported host with libkrun available | libkrun |

Other backends such as Vz and QEMU exist, but they are selected explicitly rather than by
default policy.

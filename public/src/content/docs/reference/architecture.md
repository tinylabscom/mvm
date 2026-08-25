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
behavior contract. Backend _discovery_ (which backends exist and their metadata) lives in the
compile-time descriptor registry described below; the closed enum
`mvm_runtime::backend::AnyBackend` is the dispatch layer for the operations that are still
genuinely backend-specific:

- applies platform auto-selection policy,
- preserves explicit backend selection (`--hypervisor ...`),
- routes already-started VMs back to the backend that owns their state.

### Runtime backend matrix

| Backend     | Selection mode                                | Notes                                                            |
| ----------- | --------------------------------------------- | ---------------------------------------------------------------- |
| Firecracker | Auto on Linux with native KVM                 | Production Tier 1 backend                                        |
| HVF         | Auto on supported macOS 26+ hosts             | Preferred macOS local backend (Hypervisor.framework, vsock-only) |
| libkrun     | Auto fallback on supported hosts              | Fast local Tier 2 backend                                        |
| QEMU        | Explicit opt-in (`--hypervisor qemu`)         | Linux dev/test backend                                           |
| BrowserWasi | Explicit opt-in (`--hypervisor browser-wasm`) | Browser-tier WASI backend (no hypervisor)                        |
| Mock        | Explicit opt-in (`--hypervisor mock`)         | Test-only in-memory backend                                      |

The backend descriptor registry in `crates/mvm-runtime/src/catalog.rs` is the single source of
truth for backend discovery: each `BackendDescriptor` carries the selector, aliases, isolation
tier, per-VM marker file, started-VM probe order, and the listing/support sets that `mvmctl
doctor` and `mvmctl machine ls` read. Both enum (`AnyBackend`) and trait-object (`Arc<dyn VmBackend>`)
consumers construct from the same descriptors via `instantiate` / `instantiate_dyn`.

## What runs where: the trust gradient

mvm runs long-lived processes in three layers, one per trust tier. Authority decreases as
you move away from the host, and each layer is trusted accordingly (see ADR-001 and ADR-090).

| Layer            | Process                                                                             | Owns                                                                               | Authority  | Trust                      |
| ---------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ---------- | -------------------------- |
| Host             | the `mvmctl` control plane (plus, under the fleet, per-tenant signer/audit daemons) | host signing keys, plan admission, the chain-signed audit log, VM + pool lifecycle | full       | trusted (TCB)              |
| Builder VM       | the Linux builder environment (Nix + the builder store)                             | building guest/workload images                                                     | build-only | trusted to build; dev-tier |
| Workload microVM | the guest agent                                                                     | answering vsock RPCs for its one workload                                          | none       | untrusted                  |

The governing rule: **a process never holds authority above its trust tier, and authority
only ever decreases host → builder → workload.** Host signing keys, plan admission, and the
audit chain never cross the host→builder boundary. The workload guest agent is the deliberate
runt — a sealed production build links no `do_exec` and no console (claims 4 and 15) and holds
no signing key or admission code. `mvmctl`'s `check-trust-gradient` lint machine-checks this
ledger (`specs/claims/trust-gradient.md`) on every PR; the ledger carries the host and workload
rows today, and the builder row is added once the resident builder daemon (`mvm-builderd`) exists.

### Browser-tier exception

The browser-tier `BrowserWasi` backend runs inside the browser's own WebAssembly engine.
It has **no hypervisor boundary** and runs the guest workload directly as a WASI module.
This makes it a claim-free tier: it cannot assert any of the numbered security claims
because there is no hardware isolation. It is for demos, playgrounds, and browser-local
development only, and it is never auto-selected.

What is installed where:

- The **host** has `mvmctl` (and, under the fleet, the per-tenant `mvm-host-agent` +
  `mvm-signer-helper` daemons). Host Nix is optional.
- The **builder VM** owns Nix and the build toolchain. Making the builder a _resident_ typed
  vsock service (`mvm-builderd`) is the direction recorded in ADR-089 / Plan 204; today builder
  work is controlled job execution, not yet a resident daemon.
- **Workload microVM images** contain neither `mvmctl` nor builder tooling — only the minimal
  guest agent baked by `mkGuest`.

### Residency: how warm the standby pool is kept

The standby pool is governed by a single residency policy (ADR-090), surfaced on `mvmctl
doctor`'s `residency` line as `<policy> — <source> — warm_target=N[, idle=Nm]`.

- `MVM_RESIDENCY=warm|parked|cold` overrides the policy. Unset, it resolves to `parked`
  (nothing is held warm) because the default selectable backend does not advertise a
  standby pool. An explicit `warm` request is accepted only when the selected backend
  advertises that capability.
- The trade-off is resource cost vs. first-command latency: `warm` keeps a standby ready,
  `parked`/`cold` hold none.
- Standby and snapshot capabilities are separate axes. The authoritative per-backend
  matrix is exposed by `mvmctl doctor`; unsupported recovery requests fail with a typed
  error instead of silently changing to another tier. `mvmctl pool status` reports `idle`,
  `claimed`, and `parked` counts when the selected backend provides that pool.

## Workspace Structure

The workspace is organized by responsibility rather than by platform:

| Area                       | Crates                              | Role                                                                            |
| -------------------------- | ----------------------------------- | ------------------------------------------------------------------------------- |
| Core types and contracts   | `mvm-core`                          | Shared types, protocols, config helpers, canonical lightweight traits           |
| Runtime backends           | `mvm-runtime`                       | VM lifecycle, backend adapters, storage/volume backends                         |
| Build pipeline             | `mvm-build`                         | Builder VM flow, artifact production, builder backend seams                     |
| Host policy / supervision  | `mvm-hostd`                         | Admission, audit, policy enforcement, launch preparation, per-VM host processes |
| Guest / protocol surfaces  | `mvm-agentd`                        | Guest agent and in-guest protocol tooling                                       |
| Domain-specific subsystems | `mvm-fs`, `mvm-net`, `mvm-contract` | OCI/filesystem handling, networking, audit-log verification                     |
| CLI / SDK surface          | `mvm-cli`, `mvm-sdk`                | User interface and workload authoring APIs                                      |

The root crate (`mvmctl`) is the facade/runtime integration crate. `mvm-cli` is the binary-facing
command surface.

## Dependency Graph

At a high level:

```text
mvm-core
├── mvm-net
├── mvm-build
├── mvm-runtime
├── mvm-hostd
├── mvm-agentd
└── mvm-cli
```

Interpretation:

- `mvm-core` is the dependency root and should stay runtime-light.
- `mvm-runtime`, `mvm-build`, and `mvm-hostd` are peer owning crates for their
  respective execution domains.
- `mvm-cli` sits at the top of the stack and composes the lower layers.

## Canonical Trait Seams

These are the main behavior seams in the current codebase:

| Trait                 | Owning crate  | Purpose                                        |
| --------------------- | ------------- | ---------------------------------------------- |
| `VmBackend`           | `mvm-core`    | Runtime VM lifecycle and capability contract   |
| `ShellEnvironment`    | `mvm-core`    | Minimal shell/logging seam for build flows     |
| `BuildEnvironment`    | `mvm-core`    | Extended build orchestration environment       |
| `LinuxEnv`            | `mvm-core`    | Linux execution boundary abstraction           |
| `KeyProvider`         | `mvm-core`    | Snapshot/secret key loading                    |
| `SecretStore`         | `mvm-core`    | Secret retrieval/storage seam                  |
| `ServiceHandler`      | `mvm-core`    | Protocol service dispatch                      |
| `BuilderVm`           | `mvm-build`   | High-level builder VM driver                   |
| `VmBackendForBuilder` | `mvm-build`   | Low-level builder backend seam                 |
| `BackendLauncher`     | `mvm-hostd`   | Host-side backend launch preparation/execution |
| `NetworkProvider`     | `mvm-net`     | Network provisioning / policy seam             |
| `VolumeBackend`       | `mvm-runtime` | Storage backend seam                           |

### Ownership rule

Reusable, runtime-light seams live in `mvm-core`.

That means traits like `VmBackend`, `KeyProvider`, `SecretStore`, and the build-shell
abstractions belong in `mvm-core` because many crates depend on them and they do not require
runtime-heavy backend code.

Backend- or subsystem-specific seams stay in the owning crate:

- `VmBackendForBuilder` belongs in `mvm-build`.
- `BackendLauncher` belongs in `mvm-hostd`.
- `NetworkProvider` belongs in `mvm-net`.
- `VolumeBackend` belongs in `mvm-runtime`.

This keeps `mvm-core` small while still giving the rest of the workspace stable contracts.

## Runtime Flow

Runtime launch is layered:

1. `mvm-cli` parses intent and assembles launch configuration.
2. `mvm-hostd` handles admission, audit, and launch-time host policy.
3. `mvm-runtime` selects a concrete `VmBackend` implementation.
4. The selected backend boots the Nix-built artifacts.

The ownership split is deliberate: `VmBackend` owns runtime behavior, the compile-time backend
descriptor registry owns backend discovery metadata and constructor wiring, and `AnyBackend`
remains a closed enum for the operations that are genuinely backend-specific (auto-selection
policy, explicit-variant handling). The registry is static, not a runtime plugin system — there
is no dynamic registration or dylib discovery. Generic consumers that only need behavior
construct an `Arc<dyn VmBackend>` straight from a descriptor instead of matching the enum.

## Build Pipeline

`mvmctl machine build` and related build flows do not boot workload backends directly.

Instead:

1. the host prepares a build request,
2. the builder VM performs the Linux/Nix work,
3. the produced artifacts are handed to the runtime layer,
4. a runtime backend boots those artifacts later.

The builder VM is the Linux execution boundary for Nix eval/builds and microVM-management
operations. It is not the same thing as the selected workload runtime backend.

## Platform Support

| Host platform                         | Default runtime path |
| ------------------------------------- | -------------------- |
| Linux with native KVM                 | Firecracker          |
| Supported macOS 26+ host              | HVF                  |
| Supported host with libkrun available | libkrun              |

Other backends such as QEMU exist, but they are selected explicitly rather than by
default policy.

---
title: Architecture
description: Workspace structure, multi-backend design, dependency graph, and key abstractions.
---

## Multi-Backend Design

mvmctl supports multiple VM backends and auto-selects the best one for your platform:

| Backend | Platform | Selection Priority |
|---------|----------|-------------------|
| Firecracker | Linux with `/dev/kvm` | 1st (preferred) |
| Apple Container | macOS 26+ (Apple Silicon) | 2nd |
| Docker | Any platform with Docker daemon | 3rd |
| microvm.nix | Linux (NixOS-native QEMU) | Via `--hypervisor qemu` |
| Lima + Firecracker | macOS <26, Linux without KVM | 4th (legacy fallback) |

```
Linux (KVM):    mvmctl up  -->  Firecracker microVM (direct)
macOS 26+:      mvmctl up  -->  Apple Container (Virtualization.framework)
Docker:         mvmctl up  -->  Docker container (universal fallback)
macOS <26:      mvmctl up  -->  Lima VM (Ubuntu)  -->  Firecracker microVM
```

All backends consume the same Nix-built ext4 rootfs. Override auto-detection with `--hypervisor`:

```bash
mvmctl up --flake . --hypervisor apple-container
mvmctl up --flake . --hypervisor firecracker
mvmctl up --flake . --hypervisor docker
mvmctl up --flake . --hypervisor qemu    # microvm.nix
mvmctl doctor   # check available backends
```

### Backend Capabilities

| Capability | Firecracker | Apple Container | microvm.nix | Docker | Lima + FC |
|------------|:-----------:|:---------------:|:-----------:|:------:|:---------:|
| Snapshots | Yes | No | No | No | Yes |
| Pause/resume | Yes | No | No | Yes | Yes |
| vsock | Yes | Yes | Yes | No | Yes |
| TAP networking | Yes | No (vmnet) | Yes | No | Yes |
| Port forwarding (`-p`) | Yes | Yes | Yes | Yes | Yes |
| Detach mode (`-d`) | Yes | Yes | Yes | Yes | Yes |

Template snapshots (`--snapshot`) are only available on the Firecracker backend.

## Workspace Structure

mvmctl is a Cargo workspace with 7 crates plus a root facade:

| Crate | Purpose |
|-------|---------|
| **mvm-core** | Pure types, IDs, config, protocol, signing, routing (no runtime deps) |
| **mvm-guest** | Vsock protocol, integration health checks, guest agent binary |
| **mvm-build** | Nix builder pipeline (dev_build for local, pool_build for fleet) |
| **mvm-runtime** | Shell execution, VM lifecycle, UI, template management |
| **mvm-security** | Security posture evaluation, jailer operations, seccomp profiles |
| **mvm-apple-container** | Apple Virtualization.framework backend (macOS 26+) |
| **mvm-cli** | Clap CLI, bootstrap, update, doctor, template commands |

The root crate is a facade (`src/lib.rs`) that re-exports all sub-crates as `mvmctl::core`, `mvmctl::runtime`, `mvmctl::build`, `mvmctl::guest`. The binary entry point (`src/main.rs`) delegates to `mvm_cli::run()`.

## Dependency Graph

```
mvm-core (foundation, no mvm deps)
├── mvm-guest (core)
├── mvm-build (core, guest)
├── mvm-security (core)
├── mvm-apple-container (core)
├── mvm-runtime (core, guest, build, security)
└── mvm-cli (core, runtime, build, guest)
```

Changes to `mvm-core` affect all crates. Changes to `mvm-cli` affect nothing else.

## Key Abstractions

### VmBackend

VM lifecycle abstraction defined in `mvm-core`:

- `start()`, `stop()`, `status()`, `list()`
- `capabilities()` -- pause/resume, snapshots, vsock, TAP networking

Implementations:
- **`FirecrackerBackend`** -- KVM microVMs via Firecracker (Linux native or via Lima)
- **`AppleContainerBackend`** -- Virtualization.framework (macOS 26+)
- **`MicrovmNixBackend`** -- NixOS-native QEMU runner
- **`DockerBackend`** -- Container-based fallback, universal platform support
- **`AnyBackend`** -- enum dispatch, auto-selects at runtime

### LinuxEnv

Where Linux commands run. Defined in `mvm-core`:

- `run()` -- run a command, return Output
- `run_visible()` -- run with stdout/stderr forwarded
- `run_stdout()` -- run and return stdout as String
- `run_capture()` -- run and capture both stdout and stderr

Implementations:
- **`LimaEnv`** -- delegates commands via `limactl shell mvm` (macOS <26, or Linux without KVM)
- **`NativeEnv`** -- runs commands directly (Linux with `/dev/kvm`)

### ShellEnvironment

Build-time shell abstraction:

- `shell_exec()`, `shell_exec_stdout()`, `shell_exec_visible()`
- `log_info()`, `log_success()`, `log_warn()`

Used by `dev_build()` for local Nix builds.

### BuildEnvironment

Extends `ShellEnvironment` for fleet orchestration:

- `load_pool_spec()`, `load_tenant_config()`
- `ensure_bridge()`, `setup_tap()`, `teardown_tap()`
- `record_revision()`

## How It Works

At startup, mvmctl detects the platform and selects the appropriate backend:

1. **Linux with `/dev/kvm`** -- uses `FirecrackerBackend` directly via `NativeEnv`
2. **macOS 26+** -- uses `AppleContainerBackend` for VM lifecycle; Nix builds still run in Lima
3. **Docker available** -- uses `DockerBackend` as a universal fallback
4. **macOS <26 / Linux without KVM** -- uses `FirecrackerBackend` via `LimaEnv`

```
Host (macOS/Linux)
  └── VM Backend (auto-selected)
        └── Guest (your workload, headless, vsock only)
```

## Build Pipeline

`mvmctl build` and `mvmctl template build` invoke `nix build` inside the Linux environment, producing:

- **vmlinux** -- Firecracker-compatible kernel
- **rootfs.ext4** or **rootfs.squashfs** -- guest root filesystem

No initrd is needed -- the kernel boots directly into a busybox init script on the rootfs.

## Platform Support

| Platform | Architecture | Backend |
|----------|-------------|---------|
| macOS 26+ | Apple Silicon (aarch64) | Apple Container (native) |
| macOS <26 | Apple Silicon (aarch64) | Lima + Firecracker |
| macOS <26 | Intel (x86_64) | Lima + Firecracker |
| Linux with `/dev/kvm` | x86_64, aarch64 | Firecracker (native) |
| Linux without `/dev/kvm` | x86_64, aarch64 | Docker or Lima + Firecracker |
| WSL2 | x86_64 | Docker (may have KVM) |
| Any platform with Docker | x86_64, aarch64 | Docker (universal fallback) |

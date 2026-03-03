---
title: Architecture
description: Workspace structure, dependency graph, and key abstractions.
---

## Workspace Structure

mvm is a Cargo workspace with 6 crates plus a root facade:

| Crate | Purpose |
|-------|---------|
| **mvm-core** | Pure types, IDs, config, protocol, signing, routing (no runtime deps) |
| **mvm-guest** | Vsock protocol, integration health checks, guest agent binary |
| **mvm-build** | Nix builder pipeline (dev_build for local, pool_build for fleet) |
| **mvm-runtime** | Shell execution, Lima/Firecracker VM lifecycle, UI, template management |
| **mvm-security** | Security posture evaluation, jailer operations, seccomp profiles |
| **mvm-cli** | Clap CLI, bootstrap, update, doctor, security, template commands |

The root crate is a facade (`src/lib.rs`) that re-exports all sub-crates as `mvmctl::core`, `mvmctl::runtime`, `mvmctl::build`, `mvmctl::guest`. The binary entry point (`src/main.rs`) delegates to `mvm_cli::run()`.

## Dependency Graph

```
mvm-core (foundation, no mvm deps)
├── mvm-guest (core)
├── mvm-build (core, guest)
├── mvm-security (core)
├── mvm-runtime (core, guest, build, security)
└── mvm-cli (core, runtime, build, guest)
```

Changes to `mvm-core` affect all crates. Changes to `mvm-cli` affect nothing else.

## Key Abstractions

### LinuxEnv

Where Linux commands run. Defined in `mvm-core`:

- `run()` — run a command, return Output
- `run_visible()` — run with stdout/stderr forwarded
- `run_stdout()` — run and return stdout as String
- `run_capture()` — run and capture both stdout and stderr

Implementations:
- **`LimaEnv`** — delegates commands via `limactl shell mvm bash -c "..."` (macOS)
- **`NativeEnv`** — runs commands directly via `bash -c` (Linux with KVM)

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

Used by `pool_build()` in [mvmd](https://github.com/auser/mvmd).

### VmBackend

VM lifecycle abstraction:

- `start()`, `stop()`, `status()`, `list()`
- `capabilities()` — pause/resume, snapshots, vsock, TAP networking

Current implementations: `FirecrackerBackend`, `MicrovmNixBackend`.

## How It Works

All Linux operations are routed through the `LinuxEnv` abstraction. On macOS, `LimaEnv` delegates commands via `limactl shell mvm bash -c "..."`. On Linux with KVM, `NativeEnv` runs commands directly.

```
Host (macOS/Linux)
  └── Linux environment (Lima VM on macOS, native on Linux)
        └── Firecracker microVM (your workload)
```

## Build Pipeline

`mvmctl build` and `mvmctl template build` invoke `nix build` inside the Linux environment, producing:

- **vmlinux** — Firecracker-compatible kernel
- **rootfs.ext4** or **rootfs.squashfs** — guest root filesystem

No initrd is needed — the kernel boots directly into a busybox init script on the rootfs.

## Platform Support

| Platform | Architecture | Method |
|----------|-------------|--------|
| macOS | Apple Silicon (aarch64) | Via Lima VM |
| macOS | Intel (x86_64) | Via Lima VM |
| Linux | x86_64, aarch64 | Native (`/dev/kvm`) — Lima skipped |

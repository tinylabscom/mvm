---
title: Development Guide
description: Getting started as a contributor to mvm.
---

## Prerequisites

- **Rust 1.85+** (Edition 2024) — install via [rustup](https://rustup.rs)
- **macOS or Linux** — macOS for development via Apple Container (26+) or libkrun (pre-26); Linux for native `/dev/kvm`
- **Nix** (optional) — only needed for building microVM images

Run the bootstrap script on a fresh machine:

```bash
./ops/bootstrap/dev-setup.sh
```

## Building and Running

```bash
# Build
just build

# Run CLI
just run -- --help

# Dev mode (auto-bootstraps the dev VM + Firecracker)
just run -- dev

# Release build (stripped, LTO)
just release-build
```

### Kernel builds

The builder-VM and workload microVM kernels are slim custom Linux
builds (`nix/lib/kernel/base.nix` + per-variant deltas in
`nix/images/builder-vm/kernel/`). Because the config is custom,
`cache.nixos.org` has no substitute, so the first `dev up` on a fresh
machine compiles the kernel from source (3-10 min, memory-heavy).

`mvmctl kernel build` makes that compile explicit and one-time, so it
stops hijacking your first `dev up`:

```bash
# Compile the builder kernel once into the cache + persistent nix store.
# The next `dev up` reuses it (substituted, not rebuilt).
just run -- kernel build --which builder

# Or both kernels:
just run -- kernel build --all
```

To skip the kernel compile entirely on a fresh machine, boot the builder
VM on a published kernel (once a release has shipped one):

```bash
# Build only the rootfs locally; fetch + hash-verify the kernel.
just run -- --kernel-source download dev up
# `auto` downloads if available, else compiles in-image (the default).
```

Notes:

- **Host-arch only for `--source compile`.** Stage 0 boots a host-arch
  VM under libkrun, so it builds your host's arch (aarch64 *or* x86_64).
  The other arch is published by the `kernel-build` GitHub workflow,
  which builds both on native runners — fetch it with `--source
  download` once a release ships it.
- On macOS the compile arm needs the libkrun trio (`slp/krun/*`), since
  Stage 0 is libkrun-backed even on Vz-default hosts.
- Editing `base.nix` or the builder delta? Just re-run the command — a
  custom config always compiles locally; downloads only ever return the
  kernel that shipped with that exact `mvmctl` release. See ADR-046
  §"Amendment: kernel acquisition".

## Testing

```bash
# Run all tests with nextest
just test

# Test a single crate
just test-crate mvm-core

# Run tests matching a filter
just test-filter "test_snapshot"

# Full CI gate (lint + test)
just ci
```

### Test Organization

| Location | Type | What it tests |
|----------|------|---------------|
| `crates/*/src/**/*.rs` (`#[cfg(test)]`) | Unit tests | Internal functions within the crate |
| `crates/*/tests/*.rs` | Integration tests | Public API of each crate |
| `tests/cli.rs` | Binary tests | CLI arg parsing, help output, subcommand structure |

### Testing Conventions

- Unit tests go in `#[cfg(test)] mod tests {}` at the bottom of the source file
- CLI binary tests go in root `tests/cli.rs`
- Use `#[serde(default)]` when adding fields to structs used in test fixtures

### Gated E2E: the core-demo regression guard

`crates/mvm-cli/tests/core_demo_e2e.rs` exercises the whole `dev up → compile → up → vsock ping` spine end-to-end. It boots the persistent builder VM, lowers `examples/python/hello-app/app.py` to a flake, builds + boots the workload microVM, and waits for the guest agent to answer over vsock. Default-skips so it doesn't fire on routine `cargo test` runs; gate is `MVM_E2E_SMOKE=1`:

```bash
# Local run — requires libkrun + libkrunfw + gvproxy on macOS, or
# native /dev/kvm on Linux. Threads `--hypervisor` per host.
MVM_E2E_SMOKE=1 cargo test -p mvm-cli --test core_demo_e2e -- --nocapture
```

The lane mirrored at `.github/workflows/ci.yml::core-demo-e2e` runs the same command on a self-hosted runner labelled `[self-hosted, macOS, ARM64, libkrun]`, gated on the `MACOS_LIBKRUN_AVAILABLE` repo variable. GitHub-hosted macOS runners cannot serve this lane (no nested HVF, no libkrun) — it stays opt-in until a self-hosted runner is wired.

The same gated convention covers `sdks/python/tests/test_sandbox_exec.py`, which exercises `Sandbox.exec(*argv) -> ExecResult` against a real microVM. Default-skips on `pytest`; opt-in with `MVM_E2E_SMOKE=1 python -m pytest sdks/python/tests/test_sandbox_exec.py`.

## Linting and Formatting

```bash
just fmt          # Format all code
just clippy       # Lint (zero warnings required)
just lint         # Both format check + clippy
```

### Style Rules

- **Edition 2024**: `use` statements don't need `extern crate`; let chains supported
- **No `clippy::too_many_arguments`**: never suppress this lint — refactor into a params struct
- **No `format!()` in `format!()` named args**: extract to a variable first
- **Cross-crate imports**: always use `mvm_core::`, `mvm_runtime::`, etc.

## Architecture Principles

### Multi-Backend

mvmctl's supported local microVM hosts are native Linux with `/dev/kvm` and macOS Apple Silicon. Firecracker is the Linux baseline; Apple Container and libkrun-backed components cover Apple Silicon macOS. Docker remains a Tier 3 convenience fallback, not a microVM isolation boundary. WSL2 nested KVM and a Hyper-V managed Linux builder are future backend work.

### Host vs. VM

All Linux build operations run inside the builder VM on macOS:

```rust
// On Linux this runs directly on the host; on supported macOS hosts it
// routes into the libkrun-backed builder VM.
mvm_runtime::shell::run_in_vm("ip link add br-tenant-1 type bridge")?;
```

On native Linux, `run_in_vm` executes directly on the host. On supported macOS Apple Silicon hosts, it delegates into the builder VM.

### Key Patterns

- **Idempotent operations**: every setup step checks if already done before acting
- **Config drive for metadata**: instance metadata delivered via read-only ext4 disk
- **Vsock over SSH**: guest communication uses vsock, not sshd (all backends)
- **Same rootfs everywhere**: Nix-built ext4 images work on all backends

### Adding New Types

When adding fields to structs in serialized state:

1. Add `#[serde(default)]` to the new field for backward compatibility
2. `cargo test --workspace` to find all broken test constructions
3. Fix each one
4. Add a unit test for the new behavior

## Developer Workflow Commands

Beyond the standard build/test/lint cycle, mvmctl provides commands for managing the dev environment:

```bash
# First-time setup (installs deps, creates the dev VM, default network)
just run -- init

# Image catalog — browse and build images from Nix templates
just run -- image list              # browse bundled catalog
just run -- image search http       # search by name/tag
just run -- image fetch minimal     # build from catalog entry

# Named dev networks
just run -- network create isolated # create a named network
just run -- network list            # list all networks
just run -- up --flake . --network isolated  # attach VM to a network

# Interactive console (PTY-over-vsock, no SSH)
just run -- console myvm            # interactive shell
just run -- console myvm --command "uname -a"  # one-shot exec

# Cache and diagnostics
just run -- cache info              # show cache dir and disk usage
just run -- cache prune             # clean stale temp files
just run -- security status         # security posture evaluation
just run -- doctor                  # dependency checks
```

### Console Access

microVMs have no SSH. Interactive access is via `mvmctl console` which uses PTY-over-vsock:
- Authenticated via the existing Ed25519 vsock protocol
- Dev-mode only (`access.console` must be `true` in the guest security policy)
- Single session per VM, 15-minute idle timeout
- Supports both Firecracker and Apple Container backends

### XDG Directory Layout

Dev tool state uses XDG-compliant paths (override with `MVM_CACHE_DIR`, `MVM_CONFIG_DIR`, etc.):

| Path | Purpose |
|------|---------|
| `~/.cache/mvm/` | Build artifacts, images, VM runtime state |
| `~/.config/mvm/` | User config (`config.toml`) |
| `~/.local/state/mvm/` | Logs, audit trail |
| `~/.local/share/mvm/` | Templates, network definitions, VM name registry |

Legacy `~/.mvm/` paths are auto-detected as fallback.

## CI/CD

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | Push to main/feat/*, PRs | check, fmt, clippy, test (macOS + Linux), audit |
| `release.yml` | Tags matching `v*` | Builds 4 platform binaries, creates GitHub Release |
| `publish-crates.yml` | Release published | Publishes to crates.io in dependency order |
| `pages.yml` | Push to main | Deploys docs to GitHub Pages |

## Release Process

```bash
# 1. Bump version in root Cargo.toml [workspace.package]
# 2. Update CHANGELOG.md
# 3. Commit and tag
git add -A && git commit -m "release: v0.3.0"
git tag v0.3.0

# 4. Push (triggers release.yml)
git push && git push --tags
```

The deploy guard (`scripts/deploy-guard.sh`) validates the tag matches the workspace version before publishing.

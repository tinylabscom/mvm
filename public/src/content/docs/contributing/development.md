---
title: Development Guide
description: Getting started as a contributor to mvm.
---

## Prerequisites

- **Rust 1.85+** (Edition 2024) — install via [rustup](https://rustup.rs)
- **macOS or Linux** — macOS for development via Lima, Linux for native `/dev/kvm`
- **Nix** (optional) — only needed for building microVM images

Run the bootstrap script on a fresh machine:

```bash
./scripts/dev-setup.sh
```

## Building and Running

```bash
# Build
just build

# Run CLI
just run -- --help

# Dev mode (auto-bootstraps Lima + Firecracker)
just run -- dev

# Release build (stripped, LTO)
just release-build
```

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

mvmctl supports four backends: Firecracker (native Linux), Apple Container (macOS 26+), Docker (universal fallback), and microvm.nix (NixOS QEMU). The `VmBackend` trait in `mvm-core` abstracts the lifecycle; `AnyBackend` in `mvm-runtime` dispatches at runtime. Auto-selection priority: KVM → Apple Container → Docker → Lima + Firecracker.

### Host vs. VM

All Linux operations (networking, Firecracker, cgroups) run inside the Lima VM on macOS <26:

```rust
// This runs a bash script inside the Lima VM (or natively on Linux with KVM)
mvm_runtime::shell::run_in_vm("ip link add br-tenant-1 type bridge")?;
```

On native Linux, `run_in_vm` runs directly without Lima. On macOS 26+, the Apple Container backend handles VM lifecycle natively.

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
# First-time setup (installs deps, creates Lima VM, default network)
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

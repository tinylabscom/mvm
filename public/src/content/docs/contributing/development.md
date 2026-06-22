---
title: Development Guide
description: Getting started as a contributor to mvm.
---

## Prerequisites

- **Rust 1.85+** (Edition 2024) — install via [rustup](https://rustup.rs)
- **macOS Apple Silicon or Linux** — macOS for development via Apple Container (26+) or libkrun (pre-26); Linux for native `/dev/kvm`. Intel Macs are not a supported local microVM host.
- **`zig` + `cargo-zigbuild`** — source-checkout contributors only; `crates/mvm-cli/build.rs` uses them to cross-compile the embedded host-VM binaries (`mvm-host-vm-init`, `mvm-egress-proxy`) as static `aarch64-unknown-linux-musl`. End-users running a downloaded `mvmctl` don't need them.
- **Nix** — not needed on the host. Nix evaluation and `nix build` run inside the builder VM.

### Do I need to install libkrun?

It depends on your machine. The builder VM (the Linux guest that runs
`nix build` inside `mvmctl build` / `up` / `dev`) auto-selects its host
VMM:

| Host | libkrun (`slp/krun/*`) needed? |
|---|---|
| macOS 26+ Apple Silicon | **No** — auto-detect picks the **Vz** backend (Apple Virtualization.framework, ships with the OS). `mvmctl dev up` only retries libkrun if the Vz path fails. |
| macOS 13–25 Apple Silicon | **Yes** — `brew install slp/krun/libkrun slp/krun/libkrunfw slp/krun/gvproxy`. |
| Linux + `/dev/kvm` | **No** — Firecracker runs directly. Swap `gvproxy` for `passt` from your distro package manager. |

`mvmctl doctor` reports the resolved choice on the `builder backend`
line (`<backend> — <source> — <availability>`) and emits install hints
for anything missing — run it first and follow what it says.

### Getting started

```bash
# Install zig + cargo-zigbuild if building from a source checkout (see above)
brew install zig && cargo install cargo-zigbuild

git clone https://github.com/tinylabscom/mvm.git
cd mvm
cargo build
cargo run -- doctor     # reports the builder backend + anything missing
cargo run -- dev        # auto-bootstrap + drop into the builder-VM shell
```

Or run the bootstrap script on a fresh machine:

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
builds: one shared config in `nix/images/kernel/base.nix` plus a
per-variant delta (`workload.nix` adds dm-verity; `builder.nix` adds
the nix-build sandbox + egress-lockdown bits). Because the config is
custom, `cache.nixos.org` has no substitute, so the first `dev up` on a
fresh machine compiles the kernel from source (3-10 min, memory-heavy).

`mvmctl build kernel build` makes that compile explicit and one-time, so
it stops hijacking your first `dev up`:

```bash
# Compile the builder kernel once into the cache + persistent nix store.
# The next `dev up` reuses it (substituted, not rebuilt).
just run -- build kernel build --which builder

# Or both kernels:
just run -- build kernel build --all
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
- Editing `base.nix` or a variant delta? Just re-run the command — a
  custom config always compiles locally; downloads only ever return the
  kernel that shipped with that exact `mvmctl` release. See ADR-046
  §"Amendment: kernel acquisition".

#### Iterating on the kernel config (slimming, adding a driver)

Changing `base.nix` / `workload.nix` / `builder.nix` and want to see the
effect? The loop is build → boot-smoke → measure:

```bash
# 1. Build the variant you touched (compiles your edited config in Stage 0).
just run -- build kernel build --which workload

# 2. Boot-smoke it — a kernel that builds isn't proof it boots. Boot a
#    throwaway VM and confirm the in-guest agent answers over vsock.
just run -- up --flake examples/sleeper --hypervisor libkrun --name smoke -d
just run -- machine boot-report smoke   # "control plane  ready" == good
just run -- machine stop smoke
```

Two sharp edges worth knowing:

- **A build that passes the config guard still has to boot.** After
  `make olddefconfig`, the build asserts every requested `enable` is
  still `=y` and fails loudly if one got dropped by a missing
  dependency — but that guard can't tell you a *disable* removed
  something the boot path needed. Only the boot-smoke proves that, so
  never skip step 2.
- **`enable` and `disable` are scoped.** A disable in the shared
  `base.nix` hits *both* kernels; if only the workload should drop a
  symbol (or only the builder needs one), put it in that variant's
  delta. (The builder kernel, for example, keeps netfilter for its
  egress lockdown while the workload drops it.)
- **You can't read the resolved `.config` locally** — Stage 0 hands the
  host a `vmlinux`, not the config. The `=y` symbol count + byte size
  come from the `kernel-build` CI lane, which uploads
  `workload-config-<arch>` and `kernel-metrics-<arch>.json`. Trigger it
  without a release via `gh workflow run kernel-build.yml`. The
  `check-kernel-config-budget` xtask gate fails CI if the `=y` count
  regresses past `KERNEL_Y_BUDGET`.

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

microVMs have no SSH. Interactive access is via `mvmctl machine console` which uses PTY-over-vsock:
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

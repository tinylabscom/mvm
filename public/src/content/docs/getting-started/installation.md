---
title: Installation
description: Install mvmctl on macOS or Linux.
---

## One-Liner

```bash
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
```

## Pin a Version

```bash
MVM_VERSION=v0.7.0 curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
```

## Install Model

The default install model is binary-first: install `mvmctl`, then run workloads
from your normal terminal. You do **not** need Nix on the host for normal use.

After installation, the shortest current image-backed path is:

```bash
mvmctl run --image alpine -- uname -a
```

For flake-backed builds, `mvmctl` starts or reuses the project builder VM and
runs Linux Nix work inside that VM. The host CLI stays the user-facing entry
point.

Inside that builder VM, Nix work is driven by a resident service,
`mvm-builderd`, over typed vsock requests — not a builder shell. You never run
or install it; `mvmctl` is the only command you invoke. `mvmctl doctor` reports
a "builder daemon" line so its readiness is observable. See
[Builder VM](/guides/builder-vm/#resident-builder-control-plane) for the host
control plane vs. builder execution plane split.

Portable artifacts are also intended to be host-Nix-free. A signed `.mvmpkg`
bundle can be verified and launched without rebuilding from source; source
checkouts and Nix flakes remain contributor/build inputs, not runtime
requirements for bundle operators.

## From Source

```bash
git clone https://github.com/tinylabscom/mvm.git
cd mvm
cargo build --release
cp target/release/mvmctl ~/.local/bin/
```

## Cargo Install

```bash
cargo install mvmctl
```

## Optional Nix Package

This is only for users who already choose to use Nix as an install
frontend. It is not the beginner path, and mvm does not require Nix on
the host for normal use.

The repo flake exposes a source-built host package:

```bash
nix run github:tinylabscom/mvm?dir=nix
```

For a local checkout:

```bash
cd mvm/nix
nix run .#mvmctl
```

The Nix package builds from the checkout and its committed `Cargo.lock`.
It does not download a project-published binary. Linux image builds still
run inside the builder VM; the optional Nix package is only a host CLI
install surface.

Linux Nix users who explicitly want native libkrun FFI linkage can build the
opt-in package:

```bash
cd mvm/nix
nix build .#mvmctl-native-libkrun
```

That package uses pinned, source-built upstream `libkrunfw` and `libkrun`
recipes. It is not the default package, and it does not change the binary-first
install model.

If a future package-manager expression installs release binaries, it must stay
separate from this source-built package and preserve release signature/checksum
verification.

## Self-Update

```bash
mvmctl update
```

## Prerequisites

- **macOS Apple Silicon** or **Linux with `/dev/kvm`** (x86_64 or aarch64)
- [Homebrew](https://brew.sh/) (macOS only -- mvmctl will install it if missing)

### Backend Auto-Detection

mvmctl automatically detects your platform at startup and selects the best VM backend:

| Platform | Backend | What happens |
|----------|---------|-------------|
| **Linux with `/dev/kvm`** | Firecracker | Runs directly on KVM. Smallest attack surface, fastest cold boot. |
| **macOS 26+ Apple Silicon** | Vz | Apple Virtualization.framework, bundled with the OS. No extra library install. |
| **macOS 13–25 Apple Silicon** | libkrun | In-process VMM via the Homebrew `slp/krun` trio. |

There is no Docker or container backend on the runtime path. A `qemu`
(microvm.nix) backend exists for local dev/test only and is never auto-selected.

You don't need Nix on the host. On first build, mvm bootstraps or reuses a Linux builder VM, runs Nix evaluation and `nix build` inside it, and extracts the rootfs back. You run `mvmctl build` from the host; you do not need to enter a dev shell first. See [Builder VM](/guides/builder-vm/) for the full model.

### First-Time Setup

After installation, run the setup wizard:

```bash
mvmctl init
```

This walks through platform detection, dependency installation (Firecracker on Linux; the `slp/krun` Homebrew trio for libkrun on macOS 13–25, nothing extra for Apple Virtualization.framework on macOS 26+), default network setup, and XDG directory creation. Use `--non-interactive` for scripted environments.

Running `mvmctl dev` or `mvmctl bootstrap` also handles setup automatically -- they detect your platform, select the backend, and stage the builder microVM image on first use. `mvmctl bootstrap` can also preload attested runtime and builder packs into the local pack cache when an operator supplies `MVM_BOOTSTRAP_RUNTIME_PACK_SOURCE` or `MVM_BOOTSTRAP_BUILDER_PACK_SOURCE` plus the required `MVM_BOOTSTRAP_PACK_POLICY_HASH`, `MVM_BOOTSTRAP_PACK_BACKEND`, and `MVM_BOOTSTRAP_PACK_CHANNELS` policy variables. Offline or mirror deployments can add `MVM_BOOTSTRAP_PACK_POLICY_MODE`, `MVM_BOOTSTRAP_PACK_CHANNEL_SIGNING_KEYS`, and `MVM_BOOTSTRAP_PACK_MIRROR_IDENTITY` to pin channel keys and mirror identity. Set `MVM_BOOTSTRAP_PACK_MIRROR_BASE` to a local or HTTPS mirror base when pack or revocation sources are relative names under an enterprise mirror. Use either `MVM_BOOTSTRAP_PACK_REVOCATIONS` for a local revocation file or `MVM_BOOTSTRAP_PACK_REVOCATIONS_SOURCE` for a local/HTTPS revocation source; bootstrap refuses both at once. Set `MVM_SKIP_PACK_PREFETCH=1` to skip that pack preload step while still running the normal builder-image bootstrap.

You can force a specific backend with `--hypervisor`:

```bash
mvmctl up --flake . --hypervisor firecracker  # Linux KVM
mvmctl up --flake . --hypervisor vz           # macOS 26+ Apple Silicon
mvmctl up --flake . --hypervisor libkrun      # macOS 13–25 Apple Silicon
mvmctl up --flake . --hypervisor qemu         # microvm.nix — dev/test only
```

Use `mvmctl doctor` to check which backends are available on your system.

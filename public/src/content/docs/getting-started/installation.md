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
MVM_VERSION=v0.16.1 curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
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

## Updating

`mvmctl env update` is the self-update command: it fetches the latest release
tarball and swaps the install in place. `--check` reports whether a newer
release exists without installing it, `--force` reinstalls even when already
current, and `--skip-verify` bypasses checksum verification (don't).

```bash
mvmctl env update --check
mvmctl env update
```

A source checkout updates the usual way — `git pull && cargo build --release`.
Cached build artifacts are refreshed separately with `mvmctl pack update <KIND>`
(`builder`, `runtime`, `dev-image`, or `extension`).

## Prerequisites

- **macOS Apple Silicon** or **Linux with `/dev/kvm`** (x86_64 or aarch64)
- [Homebrew](https://brew.sh/) — only on macOS 13–25, where libkrun is the
  default backend and comes from the third-party tap
  (`brew install slp/krun/libkrun slp/krun/libkrunfw`). macOS 26+ Apple Silicon
  defaults to HVF and needs no Homebrew at all. mvmctl does not install
  Homebrew for you.

### Backend Auto-Detection

mvmctl automatically detects your platform at startup and selects the best VM backend:

| Platform | Backend | What happens |
|----------|---------|-------------|
| **Linux with `/dev/kvm`** | Firecracker | Runs directly on KVM. Smallest attack surface, fastest cold boot. |
| **macOS 26+ Apple Silicon** | HVF | Hypervisor.framework, bundled with the OS; vsock-only. libkrun is the fallback. |
| **macOS 13–25 Apple Silicon** | libkrun | In-process VMM via the Homebrew `slp/krun` trio. |

There is no Docker or container backend on the runtime path. A `qemu`
(microvm.nix) backend exists for local dev/test only and is never auto-selected.

You don't need Nix on the host. On first build, mvm bootstraps or reuses a Linux builder VM, runs Nix evaluation and `nix build` inside it, and extracts the rootfs back. You run `mvmctl machine build` from the host; you do not need to enter a dev shell first. See [Builder VM](/guides/builder-vm/) for the full model.

### First-Time Setup

After installation, run host setup:

```bash
mvmctl bootstrap
```

This walks through platform detection, dependency installation (Firecracker on Linux; the `slp/krun` Homebrew trio for libkrun on macOS 13–25, nothing extra for the HVF backend on macOS 26+), default network setup, and XDG directory creation. Rerunning it is safe: it verifies warm artifacts and only
rebuilds or downloads what is missing.

Running `mvmctl bootstrap` -- or simply your first `mvmctl machine build` / `mvmctl machine run --flake ...` -- also handles setup automatically: mvm detects your platform, selects the backend, and stages the builder microVM image on first use.

You can force a specific backend with `--hypervisor`:

```bash
mvmctl machine run --flake . --hypervisor firecracker  # Linux KVM
mvmctl machine run --flake . --hypervisor hvf          # macOS 26+ Apple Silicon (default)
mvmctl machine run --flake . --hypervisor libkrun      # macOS 13–25 Apple Silicon
mvmctl machine run --flake . --hypervisor qemu         # microvm.nix — dev/test only
```

Use `mvmctl doctor` to check which backends are available on your system.

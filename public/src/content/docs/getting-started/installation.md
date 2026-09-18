---
title: Installation
description: Install mvmctl on macOS or Linux.
---

## One-Liner

```bash
curl -fsSL https://runmvm.com/install.sh | sh
```

## Pin a Version

```bash
curl -fsSL https://runmvm.com/install.sh | MVM_VERSION=v0.16.1 sh
```

## Where install.sh Puts Things

Each release is unpacked whole into its own directory, and the commands on
`PATH` reach it through a single `current` link:

```text
~/.local/lib/mvm/<n>-<version>/   mvmctl, its host binaries, assets/
~/.local/lib/mvm/current          -> <n>-<version>
~/.local/bin/mvmctl               -> ~/.local/lib/mvm/current/mvmctl
~/.local/bin/mvm-*                -> ~/.local/lib/mvm/current/mvm-*
```

Re-running `install.sh` upgrades: it stages and verifies the new release, then
switches `current` in one rename, so `mvmctl` and the host binaries it spawns
always come from the same release. If anything fails before the install is
reported — a checksum, a signature, codesign, or the new `mvmctl` not running —
`current` stays on (or returns to) the previous release. The three most recent
releases are kept; set `MVM_INSTALL_KEEP` to change that. `MVM_INSTALL_DIR` and
`MVM_INSTALL_LIB_DIR` move the two directories.

The library directory and each release directory carry a marker file
(`.mvm-lib`, `.mvm-release`), and nothing without one is ever treated as a
release, pruned or removed. `install.sh` refuses a library directory that
already holds files without the marker, and refuses to replace an entry in the
install dir that it did not create.

An install made by an older `install.sh`, with the binaries copied straight
into `~/.local/bin`, is preserved as the first release directory on the next
run, so that upgrade can roll back too.

## Uninstalling

```bash
curl -fsSL https://runmvm.com/uninstall.sh | sh
```

`mvmctl env uninstall` runs the same script. It refuses while a machine is
running, stops the per-tenant host-agent daemons (after confirming each
recorded PID runs an installed `mvm-host-agent`), and removes the `PATH`
entries, the `current` link and the marked release directories — nothing else
in `~/.local/bin`. An install from the older `install.sh` is removed by the
names that installer used: `mvmctl`, `mvm-hvf-supervisor`,
`mvm-libkrun-supervisor`, `mvm-network-endpoint` and `assets/`. The uninstaller
exits nonzero when it finds nothing to remove.

The check for running machines is answered by the installed `mvmctl`. Releases
before this uninstaller cannot answer it; the uninstaller then says so and asks
you to stop your machines and re-run with `--force`. Without a state directory
there is nothing to check, and no `--force` is needed.

The state directory (`~/.mvm`, or `MVM_HOME`) holds your machines, images, keys
and audit logs; the uninstaller asks before removing it when run interactively,
and otherwise keeps it unless you pass `--purge`. It removes it only when it is
recognisably mvm state — not `/`, not your home directory or any directory
above it, and, once any symlink is resolved, either a directory named `.mvm` or
one holding the host signing key or an audit chain — and checks that before
removing anything else, and again just before removing the state directory. A
state directory that is a symlink is unlinked; what it points at is left alone.
With `HOME` unset or empty, nothing is purged:

```bash
curl -fsSL https://runmvm.com/uninstall.sh | sh -s -- --purge
```

Pass the same `MVM_INSTALL_DIR` / `MVM_INSTALL_LIB_DIR` you installed with.
Homebrew and `cargo install` installs are removed with their own tools.

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

An `install.sh` install is upgraded by re-running `install.sh`, which moves
`mvmctl`, its host binaries and `assets/` together and can roll back. `env update`
refuses on such an install and says so, rather than overwrite binaries inside
the active release directory.

```bash
mvmctl env update --check
mvmctl env update
```

A source checkout updates the usual way — `git pull && cargo build --release`.
Cached build artifacts are refreshed separately with `mvmctl pack update <KIND>`
(`builder`, `runtime`, `dev-image`, or `extension`).

## Prerequisites

- **macOS 26+ on Apple Silicon** or **Linux with `/dev/kvm`** (x86_64 or aarch64)
- No Homebrew VMM package is required on macOS; the native HVF path ships with
  the operating system.

### Backend Auto-Detection

mvmctl automatically detects your platform at startup and selects the best VM backend:

| Platform | Backend | What happens |
|----------|---------|-------------|
| **Linux with `/dev/kvm`** | Firecracker | Runs directly on KVM. Smallest attack surface, fastest cold boot. |
| **macOS 26+ Apple Silicon** | HVF | Hypervisor.framework, bundled with the OS; vsock-only and no third-party VMM dependency. |

There is no Docker or container backend on the runtime path. A `qemu`
(microvm.nix) backend exists for local dev/test only and is never auto-selected.

You don't need Nix on the host. On first build, mvm bootstraps or reuses a Linux builder VM, runs Nix evaluation and `nix build` inside it, and extracts the rootfs back. You run `mvmctl machine build` from the host; you do not need to enter a dev shell first. See [Builder VM](/guides/builder-vm/) for the full model.

### First-Time Setup

After installation, run host setup:

```bash
mvmctl bootstrap
```

This walks through platform detection, dependency installation (Firecracker on Linux; nothing extra for the native HVF backend on macOS), default network setup, and XDG directory creation. Rerunning it is safe: it verifies warm artifacts and only
rebuilds or downloads what is missing.

Running `mvmctl bootstrap` -- or simply your first `mvmctl machine build` / `mvmctl machine run --flake ...` -- also handles setup automatically: mvm detects your platform, selects the backend, and stages the builder microVM image on first use.

You can force a specific backend with `--hypervisor`:

```bash
mvmctl machine run --flake . --hypervisor firecracker  # Linux KVM
mvmctl machine run --flake . --hypervisor hvf          # macOS 26+ Apple Silicon (default)
mvmctl machine run --flake . --hypervisor qemu         # microvm.nix — dev/test only
```

Use `mvmctl doctor` to check which backends are available on your system.

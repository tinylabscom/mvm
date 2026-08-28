---
title: "Install mvm on Linux"
description: "mvm on Linux is the Tier 1 production target — Firecracker + KVM, no virtualization wrapper, sub-200ms cold boot."
---

Linux is mvm's Tier 1 target. Verified boot (dm-verity rootfs + kernel-cmdline
roothash) applies to Firecracker/KVM cold boots. mvm launches Firecracker
directly — it does **not** wrap it in the Firecracker jailer, and it passes no
`--seccomp-filter`, so Firecracker runs with its built-in default filter rather
than a mvm-supplied "strict" tier. Do not infer a snapshot-clone latency
guarantee either: recovery tiers are backend-specific and are reported by
`mvmctl doctor`.

For the full host/backend matrix, see [Platform support](/reference/platform-support/).

## Prerequisites

You'll need:

- A CPU + kernel with **KVM** enabled. Most modern x86_64 / aarch64 hosts qualify; verify with:

  ```bash
  test -w /dev/kvm && echo "KVM accessible" || echo "KVM not accessible"
  ```

  If `/dev/kvm` exists but is `root`-only, add yourself to the `kvm` group: `sudo usermod -aG kvm "$USER"` (re-login required).
- **Rust 1.85+** if you build `mvmctl` from source.

You **do not need Nix on your host**. You run `mvmctl machine build` from the host, and mvm runs Nix evaluation and `nix build` through the project builder VM before extracting the resulting rootfs back to your host. See [Builder VM](/guides/builder-vm/) for the design.

## Install mvmctl

### One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
```

### Pin a version

```bash
MVM_VERSION=v0.16.1 curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
```

### From source

```bash
git clone https://github.com/tinylabscom/mvm.git
cd mvm
cargo build --release --bin mvmctl
cargo build --release -p mvm-hostd --bin mvm-network-endpoint
install -m 0755 \
  target/release/mvmctl \
  target/release/mvm-network-endpoint \
  ~/.local/bin/
```

### From crates.io

The GitHub release tarball is preferred for runtime use because it includes the
adjacent host helper binaries. `cargo install` installs only the `mvmctl` CLI and
is useful for CLI-only inspection or development.

```bash
cargo install mvmctl
```

## Verify

```bash
mvmctl doctor
```

`doctor` checks for `/dev/kvm` access, the cache directory permissions, and the active backend. On a healthy Linux + KVM host you'll see Firecracker selected as the auto-default. Host-side Nix is reported but not required.

## First microVM

```bash
mkdir my-app && cd my-app
mvmctl init .
mvmctl machine build
mvmctl machine run --manifest .
```

`mvmctl init` scaffolds an `mvm.toml` + `flake.nix` in your project. `mvmctl machine build` reads `mvm.toml` and builds the rootfs via Nix (using your flake's `mvm.lib.x86_64-linux.mkGuest` call); `mvmctl machine run --manifest .` boots it on Firecracker. Expected cold boot: ≤ 200ms.

(Bare `mvmctl run` is the *transient* verb and needs a command — `mvmctl run --image alpine -- uname -a`. Without one it exits with an error rather than booting your project.)

See [Building MicroVM Images](/guides/building-microvm-images) for the user-facing flake API.

## Troubleshooting

**"`/dev/kvm`: permission denied"** — your user isn't in the `kvm` group. `sudo usermod -aG kvm "$USER"` and start a new shell.

**"`/dev/kvm` exists but the run fails anyway"** — auto-select keys on `/dev/kvm` *existing*, not on your user being able to open it, so a `root`-only device still selects Firecracker and then fails at launch. There is no libkrun fallback on Linux: libkrun is selectable there only when you ask for it with `--hypervisor libkrun`, and it needs `/dev/kvm` too. Fix the group membership as above; `mvmctl doctor` reports what it resolved.

**Nix build is slow** — first builds pull from `cache.nixos.org` and `cache.flakehub.com`. Subsequent builds hit the builder VM's `/nix/store`, which mvm keeps warm across runs.

**Firecracker errors with "TooManyOpenFiles"** — bump the open-files ulimit: `ulimit -n 4096`. mvm sets a sensible default but very-high-density runs need headroom.

## Optional: host-side Nix for power users

mvm doesn't need Nix on the host — the builder VM handles mvm image builds. You may still want host-side Nix if you're:

- contributing to mvm itself and want a shared `/nix/store` between your editor's build commands and mvm's,
- already running a `nix-daemon` for other projects.

If you opt in, [Determinate Nix](https://determinate.systems/posts/determinate-nix-installer) is the easiest path:

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

The upstream NixOS installer also works:

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Installing host-side Nix does not change the normal `mvmctl machine build` contract: the CLI remains the host control plane, and the builder VM remains the image build boundary.

## Distro-specific notes

- **Ubuntu/Debian** — `apt install qemu-utils e2fsprogs` if you need `mkfs.ext4` for the [smoke test](https://github.com/tinylabscom/mvm/blob/main/tests/smoke_libkrun.rs).
- **Fedora/RHEL** — `dnf install e2fsprogs qemu-img`. Make sure SELinux isn't blocking `/dev/kvm` access (it usually isn't, but `audit2why` is your friend if it does).
- **Arch** — `pacman -S e2fsprogs qemu-img`. Already lean.
- **NixOS** — easiest path: `nix profile install github:tinylabscom/mvm?dir=nix#mvmctl`. The `?dir=nix` fragment matters: the repo-root flake exposes only `devShells` and `formatter`, so a bare `github:tinylabscom/mvm` has no package to install. KVM is enabled by default; `kvm` group membership is the only thing to verify.

---
title: "Install mvm on macOS"
description: "mvm on macOS supports Apple Silicon through Hypervisor.framework-backed local builder/runtime paths. Intel Macs are not a supported local microVM host."
---

mvm on macOS is supported on **Apple Silicon (M-series)**. The local builder/runtime path uses Apple's Hypervisor.framework via the HVF backend and libkrun-backed components. No Docker Desktop is required for the supported path.

For the full host/backend matrix, see [Platform support](/reference/platform-support/).

Intel Macs are not a supported local microVM host. Use a Linux machine with `/dev/kvm` or a remote Linux builder/runtime if you need first-class isolation from Intel macOS.

## Prerequisites

- Apple Silicon Mac.
- macOS 26+ for the HVF dev VM path.
- libkrun installed for libkrun-backed builder/runtime components.

You **do not need Nix on your Mac**. You run `mvmctl machine build` from macOS, and mvm runs Nix evaluation and `nix build` inside the Linux builder VM, then extracts the resulting rootfs back to the host. See [§"Linux builds on macOS"](#linux-builds-on-macos--zero-config-by-default) below for the design.

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
cargo build --release -p mvm-hostd \
  --bin mvm-hvf-supervisor \
  --bin mvm-libkrun-supervisor --features libkrun-sys
cargo build --release -p mvm-hostd --bin mvm-network-endpoint
install -m 0755 \
  target/release/mvmctl \
  target/release/mvm-hvf-supervisor \
  target/release/mvm-libkrun-supervisor \
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

`mvmctl` is a regular Mach-O binary on macOS — no codesigning surprises in the typical install path. Hypervisor.framework requires the host process to hold the `com.apple.security.hypervisor` entitlement; the install script handles ad-hoc signing automatically. If you build from source via `cargo`, the same entitlement is added by the build script.

## Linux Builds On macOS

macOS Nix can't build Linux derivations natively, and most Mac users don't have Nix installed at all. mvm handles both cases **without requiring host-side configuration**: on `mvmctl machine build`, the host CLI stages the selected flake as a builder job, the Linux builder VM runs `nix build`, and mvm copies the resulting kernel/rootfs artifacts back to the host cache. See [Builder VM](/guides/builder-vm/) for the full control-plane flow.

The builder VM is separate from the runtime VM. After the build completes, `mvmctl machine run` boots the already-built runtime image on the HVF backend (the macOS 26+ default). The build phase and boot phase can be benchmarked separately.

### Optional: host-side Nix for power users

Most users skip this section. You may want host-side Nix if you're contributing to mvm itself, want Nix for editor tooling, or already run `nix-darwin` for unrelated reasons. Host-side Nix is not required by `mvmctl machine build`; the builder VM remains the Linux build boundary for mvm images.

[Determinate Nix](https://determinate.systems/posts/determinate-nix-installer) is the easiest path:

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

If you configure [`nix-darwin`'s `linux-builder`](https://nix.dev/manual/nix/stable/installation/installing-binary), it can be useful for direct `nix build` commands that you run yourself. It is not required for `mvmctl machine build`.

## Verify

```bash
mvmctl doctor
```

`doctor` reports the active backend and libkrun availability. On an Apple Silicon Mac with macOS 26+, image builds auto-detect the HVF builder; if HVF fails to create its VM, mvm transparently retries with libkrun (the same auto-fallback that covers every builder entry point — `mvmctl bootstrap`, `machine build`, `machine run`). Explicit `--builder` / `MVM_BUILDER_BACKEND` overrides still win.

## First microVM

```bash
mkdir my-app && cd my-app
mvmctl init .
mvmctl run
```

`mvmctl init` scaffolds the project. On first `mvmctl run`, mvm bootstraps the builder VM if needed, runs `nix build` inside it, and boots the resulting rootfs with the selected macOS runtime backend. Expected runtime cold boot is measured after the image is already built. When developing from this source checkout, the builder VM image is local-build only; the cache is reused only when its source fingerprint matches `nix/images/builder-vm/{flake.nix,flake.lock}`, its recorded artifact digests still match the cached files, and its provenance summary matches the same source and artifact filename set. Cache misses, fingerprint drift, artifact drift, or provenance drift build from the local `nix/images/builder-vm/` flake using a local dev image as Stage 0, validate the staged artifacts, and only then promote them into the live cache. Run with `--verbose` to see the safe source-cache reason code, for example `hit`, `fingerprint_mismatch`, `artifact_digest_mismatch`, or `provenance_mismatch`. mvm will not download a published builder image to hide local flake changes.

## Troubleshooting

**"Hypervisor.framework: entitlement missing"** — re-codesign the binary with the entitlement: `codesign --entitlements assets/mvmctl.entitlements -f -s - ~/.local/bin/mvmctl`. The release binary ships pre-signed; this only matters if you've stripped entitlements or built from source without the build script's signing step.

**`nix build` fails with "a 'x86_64-linux' with features … is required"** — that is a direct host-side Nix command failing because macOS cannot build Linux derivations by itself. Use `mvmctl machine build --flake .` so the Linux build runs inside the builder VM. If you intentionally want direct `nix build` on macOS, configure [`nix-darwin`'s `linux-builder`](https://nix.dev/manual/nix/stable/installation/installing-binary).

**`mvmctl run` boots but `mvmctl machine console` fails to attach** — the `console` subcommand is only enabled for *accessible* images. If your `entrypoint.command = [ ... ]`, the build is *sealed* and console attach is rejected. Switch to `entrypoint.shell = "/bin/sh"` or pass `dev = true` in your `mkGuest` call. See [Building MicroVM Images](/guides/building-microvm-images).

**"libkrun shared library not found"** — install libkrun, then rerun the command. On Apple Silicon with Homebrew:

```bash
brew install libkrun
```

## Apple Silicon vs Intel notes

- **Apple Silicon (M1/M2/M3/M4 and newer)** — supported local path. HVF covers the dev VM, and libkrun backs builder/runtime components that need Hypervisor.framework directly.
- **Intel Macs** — unsupported for the local microVM path. Run mvm on a Linux KVM host, or use future remote/Windows-style builder work when it lands.

The HVF backend is the macOS 26+ Apple Silicon default and sole workload backend (Hypervisor.framework, vsock-only egress). libkrun is the macOS 13–25 default and is also treated as an Apple Silicon macOS path for mvm support purposes.

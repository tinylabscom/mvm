# mvm Quickstart

Get from zero to a running Firecracker microVM in under five minutes.

## Prerequisites

**macOS (Apple Silicon or Intel)**

- Homebrew (`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`)
- Xcode Command Line Tools (`xcode-select --install`)

**Linux (x86_64 or aarch64)**

- KVM enabled (`ls /dev/kvm` — if missing, enable virtualization in BIOS)
- A package manager: apt, dnf, or pacman

## Install mvm

From source (requires Rust 1.85+):

```bash
git clone https://github.com/anthropics/mvm.git
cd mvm
cargo install --path .
```

Or via cargo:

```bash
cargo install mvmctl
```

## Verify your environment

```bash
mvmctl doctor
```

This checks for required tools (cargo, limactl, firecracker), platform support, KVM access, Lima VM status, and available disk space. Fix any issues it reports before continuing.

For machine-readable output:

```bash
mvmctl doctor --json
```

## Bootstrap

One command installs Lima (macOS), Firecracker, downloads the kernel and rootfs:

```bash
mvmctl bootstrap
```

On re-run, already-completed steps are skipped automatically.

## Enter the development environment

```bash
mvmctl dev
```

This starts the Lima VM (if needed), installs Firecracker inside it, and drops you into a shell where `/dev/kvm` and `nix` are available.

## Build and run a microVM from a Nix flake

Create a template, build it, and launch:

```bash
# Create a template from a local flake
mvmctl template create my-app --flake ./my-flake --profile minimal

# Build the template (produces kernel + rootfs via Nix)
mvmctl template build my-app

# Launch a microVM from the built template
mvmctl run --flake ./my-flake
```

Or run directly from a flake (builds on first launch):

```bash
mvmctl run --flake ./my-flake --profile minimal
```

## Launch the default Ubuntu microVM

If you just want a quick VM without Nix:

```bash
mvmctl start
```

## Common commands

| Command | Description |
|---------|-------------|
| `mvmctl doctor` | Check environment health |
| `mvmctl bootstrap` | Full setup from scratch |
| `mvmctl setup` | Setup Lima + Firecracker (requires limactl) |
| `mvmctl setup --force` | Re-run all setup steps |
| `mvmctl dev` | Enter development environment |
| `mvmctl start` | Launch default Ubuntu microVM |
| `mvmctl run --flake .` | Build and run a Nix flake microVM |
| `mvmctl status` | Show VM status |
| `mvmctl stop` | Stop running microVM |
| `mvmctl shell` | Shell into the Lima VM |
| `mvmctl sync` | Build mvm from source inside Lima |
| `mvmctl template list` | List available templates |

## Known-good host matrix

| Platform | Architecture | Status |
|----------|-------------|--------|
| macOS 14+ (Sonoma) | Apple Silicon (aarch64) | Supported |
| macOS 14+ (Sonoma) | Intel (x86_64) | Supported |
| Ubuntu 22.04+ | x86_64 | Supported |
| Ubuntu 24.04+ | aarch64 | Supported |

## Troubleshooting

Run `mvmctl doctor` first — it identifies most common issues.

For detailed troubleshooting, see [troubleshooting.md](troubleshooting.md).

**Lima VM won't start:** `mvmctl destroy -y && mvmctl bootstrap`

**Firecracker not found:** `mvmctl setup --force`

**/dev/kvm not accessible:** On Linux, check `ls -la /dev/kvm` and add your user to the `kvm` group. On macOS, KVM runs inside the Lima VM automatically.

**Nix command not found:** Nix is installed inside the Lima VM, not on the host. Use `mvmctl shell` to access it.

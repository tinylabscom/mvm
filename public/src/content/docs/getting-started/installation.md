---
title: Installation
description: Install mvmctl on macOS or Linux.
---

## One-Liner

```bash
curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
```

## Pin a Version

```bash
MVM_VERSION=v0.6.0 curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
```

## From Source

```bash
git clone https://github.com/auser/mvm.git
cd mvm
cargo build --release
cp target/release/mvmctl ~/.local/bin/
```

## Cargo Install

```bash
cargo install mvmctl
```

## Self-Update

```bash
mvmctl update
```

## Prerequisites

- **macOS** (Apple Silicon or Intel) or **Linux** (x86_64 or aarch64)
- [Homebrew](https://brew.sh/) (macOS only -- mvmctl will install it if missing)

### Backend Auto-Detection

mvmctl automatically detects your platform at startup and selects the best VM backend:

| Platform | Backend | What happens |
|----------|---------|-------------|
| **Linux with `/dev/kvm`** | Firecracker | Runs directly on KVM. No Lima needed. |
| **macOS 26+** (Apple Silicon) | Apple Container | Uses Virtualization.framework. No Lima needed. |
| **Docker available** | Docker | Container-based fallback. Runs anywhere Docker does. |
| **macOS <26** | Lima + Firecracker | Lima VM provides `/dev/kvm`. Builds and Firecracker run inside Lima. |
| **Linux without `/dev/kvm`** | Lima + Firecracker | Lima VM as fallback (same as macOS <26). |

Running `mvmctl dev` or `mvmctl bootstrap` handles everything automatically -- it detects your platform, selects the backend, installs Lima only if needed, and sets up Nix and Firecracker in the right environment.

You can force a specific backend with `--hypervisor`:

```bash
mvmctl up --flake . --hypervisor apple-container
mvmctl up --flake . --hypervisor firecracker
mvmctl up --flake . --hypervisor docker
mvmctl up --flake . --hypervisor qemu    # microvm.nix
```

Use `mvmctl doctor` to check which backends are available on your system.

---
title: Installation
description: Install mvm on macOS or Linux.
---

## One-Liner

```bash
curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
```

## Pin a Version

```bash
MVM_VERSION=v0.3.6 curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
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
- [Homebrew](https://brew.sh/) (macOS only — mvm will install it if missing)

### Platform Detection

mvm automatically detects your platform at startup and adapts its setup:

| Platform | What happens |
|----------|-------------|
| **macOS** | Lima VM is installed to provide `/dev/kvm`. All builds and Firecracker run inside Lima. |
| **Linux with `/dev/kvm`** | Lima is skipped entirely. Builds and Firecracker run natively on the host. |
| **Linux without `/dev/kvm`** | Lima VM is installed as a fallback (same as macOS). Useful for WSL2 or cloud VMs without nested virtualization. |

Running `mvmctl bootstrap` or `mvmctl dev` handles everything automatically — it detects your platform, installs Lima only if needed, and sets up Nix and Firecracker in the right environment.

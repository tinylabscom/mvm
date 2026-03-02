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
MVM_VERSION=v0.3.0 curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
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
mvmctl upgrade
```

## Prerequisites

- **macOS** (Apple Silicon or Intel) or **Linux** with KVM
- [Homebrew](https://brew.sh/) (macOS only — mvm will install it if missing)

Running `mvmctl bootstrap` or `mvmctl dev` handles everything else automatically — Lima, Nix, and Firecracker are installed inside the VM.

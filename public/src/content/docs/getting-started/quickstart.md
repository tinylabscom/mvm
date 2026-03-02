---
title: Quick Start
description: Get a Firecracker microVM running in under 5 minutes.
---

## 1. Launch the Dev Environment

```bash
mvmctl dev
```

This single command handles everything:

1. Installs Lima (macOS) if not present
2. Creates and starts a Lima VM with nested virtualization
3. Installs Firecracker inside the Lima VM
4. Drops you into the Lima VM shell

Inside the Lima shell, your home directory (`~`) is mounted read/write — your project files are right there. Nix, Firecracker, and `/dev/kvm` are all available.

Exit the shell with `exit` or `Ctrl+D` — the Lima VM keeps running in the background.

:::note
On the first run, `mvmctl dev` downloads ~500MB of assets (Lima VM image). Subsequent runs start in seconds.
:::

## 2. Day-to-Day Commands

```bash
mvmctl status     # Check what's running (Lima VM, Firecracker, microVM)
mvmctl shell      # Open a shell in the Lima VM
mvmctl stop       # Stop the microVM (Lima VM stays running)
mvmctl destroy    # Tear down everything (Lima VM + all data)
```

## 3. Build and Run

Build a microVM image and run it in one command:

```bash
mvmctl run --flake github:org/app --profile minimal --cpus 2 --memory 1024
```

Or build separately:

```bash
mvmctl build --flake . --profile minimal --role worker
mvmctl start
```

## 4. Templates

Build a base image once and share it across machines:

```bash
mvmctl template create base-worker \
    --flake github:org/app \
    --profile minimal \
    --role worker \
    --cpus 2 --mem 1024

mvmctl template build base-worker
mvmctl run --template base-worker
```

## 5. Diagnostics

```bash
mvmctl doctor    # Check system dependencies and configuration
mvmctl vm ping   # Health-check running microVMs via vsock
```

## Next Steps

- [Your First MicroVM](/getting-started/first-microvm/) — write a Nix flake and boot it
- [CLI Commands](/reference/cli-commands/) — full command reference
- [Templates](/guides/templates/) — reusable base images
- [Troubleshooting](/guides/troubleshooting/) — common issues

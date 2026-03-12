---
title: Quick Start
description: Get a Firecracker microVM running in under 5 minutes.
---

## 1. Launch the Dev Environment

```bash
mvmctl dev
```

This single command detects your platform and handles everything:

**On macOS or Linux without KVM:**
1. Installs Lima if not present
2. Creates and starts a Lima VM with `/dev/kvm`
3. Installs Nix and Firecracker inside the Lima VM
4. Drops you into the Lima VM shell

**On Linux with `/dev/kvm`:**
1. Skips Lima entirely
2. Installs Nix and Firecracker natively on the host
3. Drops you into a dev shell

Inside the dev shell, your home directory (`~`) is mounted read/write (Lima) or directly available (native Linux) — your project files are right there. Nix, Firecracker, and `/dev/kvm` are all available.

Exit the shell with `exit` or `Ctrl+D` — the Lima VM (if used) keeps running in the background.

:::note
On macOS / Linux without KVM, the first run downloads ~500MB of assets (Lima VM image). On native Linux, setup is much faster. Subsequent runs start in seconds on all platforms.
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

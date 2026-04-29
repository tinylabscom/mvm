---
title: Quick Start
description: Get a microVM running in under 5 minutes.
---

## 1. Launch the Dev Environment

```bash
mvmctl dev
```

This single command detects your platform and handles everything:

**On macOS 26+ (Apple Silicon):**
1. Uses Apple Virtualization.framework directly -- no Lima needed
2. Drops you into a dev shell

**On macOS <26 or Linux without KVM:**
1. Installs Lima if not present
2. Creates and starts a Lima VM with `/dev/kvm`
3. Installs Nix and Firecracker inside the Lima VM
4. Drops you into the Lima VM shell

**On Linux with `/dev/kvm`:**
1. Skips Lima entirely
2. Installs Nix and Firecracker natively on the host
3. Drops you into a dev shell

**Docker fallback (any platform):**
1. If no hypervisor or KVM is available, falls back to Docker
2. Runs your workload in a container with pause/resume support

Inside the dev shell, your home directory (`~`) is mounted read/write (Lima) or directly available (native Linux) -- your project files are right there. Nix, Firecracker, and `/dev/kvm` are all available.

Exit the shell with `exit` or `Ctrl+D` -- the Lima VM (if used) keeps running in the background.

:::note
On macOS / Linux without KVM, the first run downloads ~500MB of assets (Lima VM image). On native Linux, setup is much faster. Subsequent runs start in seconds on all platforms.
:::

## 2. Day-to-Day Commands

```bash
mvmctl ls         # List running VMs (aliases: ps, status)
mvmctl dev shell  # Open a shell in the Lima VM
mvmctl down       # Stop all running VMs
mvmctl doctor     # Check system dependencies and configuration
mvmctl console vm # Interactive shell into a running VM (PTY-over-vsock)
```

## 3. Build and Run

Build a microVM image and run it in one command:

```bash
mvmctl up --flake . --cpus 2 --memory 1024
```

Run in background with port forwarding:

```bash
mvmctl up --flake . -d -p 8080:8080
```

Or build separately:

```bash
mvmctl build --flake . --profile minimal
mvmctl up --flake .
```

## 4. Templates

Build a base image once and share it across machines:

```bash
mvmctl template create base-worker \
    --flake . \
    --profile minimal \
    --role worker \
    --cpus 2 --mem 1024

mvmctl template build base-worker
mvmctl up --template base-worker
```

## 5. Image Catalog

Browse and build images without writing Nix flakes yourself:

```bash
mvmctl image list           # Browse available images
mvmctl image fetch minimal  # Build from catalog (creates template + Nix build)
mvmctl up --template minimal
```

## 6. Interactive Console

Access a running VM without SSH -- uses PTY-over-vsock:

```bash
mvmctl console myvm                    # Interactive shell
mvmctl console myvm --command "ls -la" # One-shot command
```

## 7. Sandboxed One-Shot Commands

`mvmctl exec` boots a fresh transient microVM, runs a single command, and tears
it down on exit -- like `docker run --rm`, but with a Firecracker microVM as
the sandbox. No `--flake` or `--template` needed; the bundled default image
boots automatically the first time.

```bash
mvmctl exec -- uname -a                            # bundled default image
mvmctl exec --add-dir .:/work -- ls /work          # share host dir, read-only
mvmctl exec --env DEBUG=1 -- env | grep DEBUG      # inject env vars
mvmctl exec --template my-tpl -- /bin/true         # registered template
```

When you reuse a registered template that has a captured snapshot, exec
restores from the snapshot instead of cold-booting -- typically sub-second.
See the [Sandboxed Exec](/guides/exec/) guide for details.

## 8. Named Networks

Create isolated networks for different projects:

```bash
mvmctl network create myproject
mvmctl up --flake . --network myproject
mvmctl network list
```

## 9. Diagnostics & Security

```bash
mvmctl doctor           # Check system dependencies, available backends
mvmctl logs vm1         # View guest console logs
mvmctl security status  # Security posture evaluation
mvmctl cache info       # Cache directory disk usage
```

## Next Steps

- [Your First MicroVM](/getting-started/first-microvm/) -- write a Nix flake and boot it
- [Sandboxed Exec](/guides/exec/) -- run a single command in a fresh microVM
- [CLI Commands](/reference/cli-commands/) -- full command reference
- [Templates](/guides/templates/) -- reusable base images
- [Troubleshooting](/guides/troubleshooting/) -- common issues

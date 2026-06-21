---
title: Quick Start
description: Get a microVM running in under 5 minutes.
---

:::tip[Looking for the shortest path to "it's running"?]
[First-Use Happy Paths](/getting-started/happy-paths/) lists a
three-command sequence for each mvm audience: OCI-image CLI users,
flake CLI users, Python SDK users, TypeScript SDK users, prebuilt bundle
operators, and `mvmctl dev` users. Each path is paired with
`mvmctl doctor --workflow <name>` so the preflight only flags blockers
your audience actually has.
:::

## 1. Run an OCI Image

The shortest current path is a one-shot microVM from an OCI image:

```bash
mvmctl machine run --image alpine -- uname -a
```

This pulls or reuses the cached image, records OCI provenance, boots a transient
microVM, runs the command, and tears the VM down. You do not need host Nix for
this path.

Use this when you want "run this command in a fresh microVM." Use the flake,
manifest, and dev-shell flows below when you are building a custom image or a
repeatable project environment.

For a scenario-led map of when to use each machine workflow, read
[Machine use cases](/guides/machine-use-cases/). Before depending on a backend
capability, read [Machine limitations](/guides/machine-limitations/).

For a named machine that survives across starts:

```bash
mvmctl machine create --name alpine-dev --image alpine
mvmctl machine start --name alpine-dev
mvmctl machine exec --name alpine-dev -- uname -a
mvmctl machine stop --name alpine-dev
```

## 2. Launch the Dev Environment

```bash
mvmctl dev
```

This single command detects your platform and handles everything. **Builds run in a builder microVM that mvm sets up automatically — you don't need Nix on your host.** The builder owns its own `/nix/store` and keeps it warm across builds. Where the builder VM runs depends on your platform:

**On Linux with `/dev/kvm`:**
1. Selects Firecracker as the runtime backend
2. Bootstraps the builder microVM on first build (one-time fetch); `nix build` runs inside it
3. Drops you into a dev shell

**On macOS 26+ Apple Silicon:**
1. Selects Apple Virtualization.framework (the `vz` backend, bundled with the OS)
2. Boots the builder microVM there; `nix build` runs inside it
3. Drops you into a dev shell

**On macOS 13–25 Apple Silicon:**
1. Selects libkrun (the in-process VMM from the `slp/krun` Homebrew trio)
2. Same builder microVM, hosted on libkrun
3. Drops you into a dev shell

mvm targets Apple Silicon on macOS and `/dev/kvm` on Linux. There is no Docker
or container runtime path; a host without a supported microVM backend surfaces a
backend-unavailable error rather than silently degrading.

Inside the dev shell your project directory is bind-mounted at `/work`. Exit with `exit` or `Ctrl+D` -- background services keep running.

:::note
Release binaries download the builder image (~200MB) and dev microVM image on first run. From a source checkout, `mvmctl dev up` builds from the in-repo flakes.
:::

## 3. Day-to-Day Commands

```bash
mvmctl ls         # List running VMs (aliases: ps, status)
mvmctl dev shell  # Open a shell in the dev microVM
mvmctl down       # Stop all running VMs
mvmctl doctor     # Check system dependencies and configuration
mvmctl console vm # Interactive shell into a running VM (PTY-over-vsock)
```

## 4. Build and Run

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

## 5. Manifests

A manifest is the project-local build contract. It sits next to `flake.nix`
and records the flake target plus runtime sizing:

```bash
mvmctl init base-worker --preset worker
cd base-worker
$EDITOR mvm.toml
mvmctl build
mvmctl up
```

Use `mvmctl manifest ls` and `mvmctl manifest info` to inspect built
manifest slots. See [Manifests](/guides/manifests/) for the full flow.

Image-backed manifests can also define a durable machine spec:

```toml
image = "alpine:3.20"
cpus = 2
mem = "512M"
```

```bash
mvmctl machine create --name alpine-dev --manifest ./mvm.toml
```

## 6. Image Catalog

Browse the bundled catalog and scaffold from a curated entry:

```bash
mvmctl catalog list                       # Browse available entries
mvmctl init my-app --catalog minimal      # Scaffold from a catalog entry
mvmctl build my-app                       # Build the manifest
mvmctl up my-app                          # Boot the VM
```

## 7. Interactive Console

Access a running VM without SSH -- uses PTY-over-vsock:

```bash
mvmctl console myvm                    # Interactive shell
mvmctl console myvm --command "ls -la" # One-shot command
```

## 8. Sandboxed One-Shot Commands

`mvmctl exec` boots a fresh transient microVM, runs a single command, and tears
it down on exit -- like `docker run --rm`, but with a Firecracker microVM as
the sandbox. No `--flake` or `--manifest` needed; the bundled default image
boots automatically the first time.

```bash
mvmctl exec -- uname -a                            # bundled default image
mvmctl exec --add-dir .:/work -- ls /work          # share host dir, read-only
mvmctl exec --env DEBUG=1 -- env | grep DEBUG      # inject env vars
mvmctl exec --manifest my-tpl -- /bin/true         # registered template
```

When you reuse a registered template that has a captured snapshot, exec
restores the captured state instead of re-provisioning from scratch, so
repeat runs skip the first-run setup cost.
See the [Sandboxed Exec](/guides/exec/) guide for details.

## 9. Named Networks

Create isolated networks for different projects:

```bash
mvmctl network create myproject
mvmctl up --flake . --network myproject
mvmctl network list
```

## 10. Diagnostics & Security

```bash
mvmctl doctor           # Deps, available backends, and security posture (one report)
mvmctl logs vm1         # View guest console logs
mvmctl cache info       # Cache directory disk usage
```

## Next Steps

- [Your First MicroVM](/getting-started/first-microvm/) -- write a Nix flake and boot it
- [Sandboxed Exec](/guides/exec/) -- run a single command in a fresh microVM
- [Machine use cases](/guides/machine-use-cases/) -- choose the right machine workflow
- [Machine limitations](/guides/machine-limitations/) -- explicit backend and feature limits
- [CLI Commands](/reference/cli-commands/) -- full command reference
- [Manifests](/guides/manifests/) -- reusable base images via `mvm.toml`
- [Troubleshooting](/guides/troubleshooting/) -- common issues

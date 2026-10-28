---
title: Quick Start
description: Prepare a prebuilt image, then run a local transient microVM.
---

:::tip[Looking for the shortest path to "it's running"?]
[First-Use Happy Paths](/getting-started/happy-paths/) lists a
short preparation-and-run sequence for each mvm audience: OCI-image CLI users,
flake CLI users, Python SDK users, TypeScript SDK users, prebuilt bundle
operators, and interactive-shell users. Each path is paired with
`mvmctl doctor --workflow <name>` so the preflight only flags blockers
your audience actually has.
:::

## 1. Run an OCI Image

Start with the [native local demo](/getting-started/native-demo/): no `mvmd`,
remote credentials, persistent volumes, or source build. Prepare the runtime
and capture a pinned image reference, then launch:

```bash
mvmctl doctor --workflow cli-run
mvmctl bootstrap
mvmctl image pull alpine
MVM_DEMO_IMAGE="$(mvmctl image inspect alpine --digest-ref)"
mvmctl machine run --name local-demo --profile dev \
  --image "${MVM_DEMO_IMAGE:?Run preparation in this terminal first}" \
  --cpus 1 --memory 256M --timeout 30 \
  -- /bin/sh -c 'printf "hello from a microVM\n"; /bin/uname -s'
```

`bootstrap` also creates the host snapshot key that warm standbys are
encrypted under, at `~/.mvm/keys/local.key`, when the host has none; keep a
copy of it.

Preparation owns downloads and materialization: `machine run` is cache-only,
and a missing image fails quickly and names the command that prepares it.
The named foreground run above is transient and cold; it tears down on exit
and requests no standby. The digest pin identifies prepared content; it is
not a publisher signature or production-policy approval.

For unnamed runs, the first cold boot also leaves one standby of the image
ready, so the next matching run claims it instead of booting and is held to
the 300 ms startup ceiling.
Standbys stay within a host memory cap and are released after 20 idle minutes.
To make even the first run warm, prepare a standby ahead of time with
`mvmctl pool warm 1 --image alpine`; `MVM_RESIDENCY=cold` turns standbys off.
You do not need host Nix for this path.

Use this when you want "run this command in a fresh microVM." Use the flake
and manifest flows below when you are building a custom image or a
repeatable project environment.

For a scenario-led map of when to use each machine workflow, read
[Machine use cases](/guides/machine-use-cases/). Before depending on a backend
capability, read [Machine limitations](/guides/machine-limitations/).

For a named machine that survives across starts:

```bash
# Create the spec, then start it
mvmctl machine create alpine-dev --image alpine
mvmctl machine start alpine-dev

# Or create and start in one command
mvmctl machine start alpine-dev --image alpine

mvmctl machine exec alpine-dev -- uname -a
mvmctl machine stop alpine-dev
```

## 2. Prepare the Builder VM (optional)

```bash
mvmctl bootstrap
```

`nix build` for a `--flake` source runs inside a **headless builder
VM** — a build engine, not something you get a shell into. It
auto-bootstraps the first time you run `mvmctl machine build` or
`mvmctl machine run --flake ...`; `mvmctl bootstrap` pre-fetches it
ahead of time so that first build isn't slowed by a cold-start fetch.
**Builds run in a builder microVM that mvm sets up automatically — you
don't need Nix on your host.** The builder owns its own `/nix/store`
and keeps it warm across builds. Where the builder VM runs depends on
your platform:

- **Linux with `/dev/kvm`:** auto-selects the QEMU builder backend;
  your built workloads boot on Firecracker.
- **macOS 26+ Apple Silicon:** auto-selects the HVF builder backend
  (Hypervisor.framework, vsock-only, no Homebrew or libkrun dependency).
  HVF errors surface directly rather than activating a hidden fallback.
- **macOS 13–25 Apple Silicon:** the signed release carries a libkrun preview
  with no Homebrew dependency. It is not auto-selected; pass
  `--hypervisor libkrun` for the workload. Packaged loading is verified, while
  the real guest-launch witness remains open.

mvm targets Apple Silicon on macOS and `/dev/kvm` on Linux. There is no Docker
or container runtime path; a host without a supported microVM backend surfaces a
backend-unavailable error rather than silently degrading.

`mvmctl doctor` reports the resolved builder backend and flags any missing
host dependencies. For an interactive shell, boot a workload instead — see
[Interactive Console](#7-interactive-console) below.

:::note
The builder image (~200MB) is downloaded and verified against the image lock
on first use. It is built locally only when an `mvm-images` checkout is
selected, through `MVM_IMAGES_DIR` or a clone beside this one: image
construction lives in that repository.
:::

## 3. Day-to-Day Commands

```bash
mvmctl machine ps # List every microVM (alias: ls)
mvmctl machine stop --all       # Stop all running VMs
mvmctl doctor     # Check system dependencies and configuration
mvmctl machine attach vm # Interactive shell into a running VM (PTY-over-vsock)
```

## 4. Build and Run

Build a microVM image and run it in one command:

```bash
mvmctl machine run --flake . --cpus 2 --memory 1024
```

Run persistently with signed ingress:

```bash
mvmctl machine run --flake . --name my-vm --port 8080:8080
```

Or build separately:

```bash
mvmctl machine build --flake . --profile minimal
mvmctl machine run --flake .
```

## 5. Manifests

A manifest is the project-local build contract. It sits next to `flake.nix`
and records the flake target plus runtime sizing:

```bash
mvmctl init base-worker --preset worker
cd base-worker
$EDITOR mvm.toml
mvmctl machine build
mvmctl machine run --manifest .
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
mvmctl machine create alpine-dev --manifest ./mvm.toml
```

## 6. Image Catalog

Browse the bundled catalog and scaffold from a curated entry:

```bash
mvmctl catalog list                       # Browse available entries
mvmctl init my-app --catalog minimal      # Scaffold from a catalog entry
mvmctl machine build my-app                       # Build the manifest
mvmctl machine run --manifest my-app                          # Boot the VM
```

## 7. Interactive Console

Access a running VM without SSH -- uses PTY-over-vsock:

```bash
mvmctl machine attach myvm                     # Interactive shell
mvmctl machine console myvm --command "ls -la" # One-shot command
```

## 8. Sandboxed One-Shot Commands

`mvmctl machine run -- <cmd>` boots a fresh transient microVM, runs a single
command, and tears it down on exit -- like `docker run --rm`, but with a
Firecracker microVM as the sandbox. Name a source with `--image`, `--flake`,
or `--manifest`.

```bash
mvmctl machine run --image alpine -- uname -a                    # OCI image, one-shot
mvmctl machine run --flake . --mount .:/work -- ls /work         # share host dir, read-only
mvmctl machine run --image alpine -e DEBUG=1 -- sh -c 'env | grep DEBUG' # inject env vars
mvmctl machine run --manifest my-tpl -- /bin/true                # registered template
```

When you reuse a registered template that has a captured snapshot, exec
restores the captured state instead of re-provisioning from scratch, so
repeat runs skip the first-run setup cost.
See the [Sandboxed Exec](/guides/exec/) guide for details.

## 9. Named Networks

Create isolated networks for different projects:

```bash
mvmctl network create myproject
mvmctl machine run --flake .
mvmctl network list
```

## 10. Diagnostics & Security

```bash
mvmctl doctor           # Deps, available backends, and security posture (one report)
mvmctl machine logs vm1         # View guest console logs
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

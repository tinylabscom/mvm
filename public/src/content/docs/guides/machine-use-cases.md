---
title: Machine use cases
description: Scenario-led guide for the mvmctl machine workflow.
---

`mvmctl machine` is the beginner-facing workflow for running OCI-backed
microVMs without writing a flake first. Start here when you want a small command
surface for day-to-day sandboxing, then move to the lower-level guides when you
need custom image builds or backend tuning.

Normal image-backed machine commands do not need host Nix. mvm uses the builder
boundary only when a workflow actually needs Linux build or evaluation work.

## Pick A Scenario

| Use this for | Start with | What it gives you |
| --- | --- | --- |
| Sandbox untrusted code | `mvmctl machine run --image alpine -- <cmd>` | Fresh transient microVM, command output, teardown on exit. |
| Run a command in an OCI image | `mvmctl machine run --image ghcr.io/org/app:tag -- <cmd>` | OCI provenance, cache reuse, admission, receipts, and audit. |
| Use a local image archive | `mvmctl machine run --image-archive ./image.tar -- <cmd>` | Offline-friendly image input through the same hardened unpack/admission path. |
| Keep a dev machine around | `mvmctl machine create dev --image alpine` | Durable spec plus `start`, `exec`, `shell`, `stop`, `inspect`, and `rm`. |
| Declare a repeatable machine | `mvmctl machine create dev --manifest ./mvm.toml` | TOML-backed image, sizing, network, volume, and dev-init settings. |
| Branch a running machine | `mvmctl machine fork dev --as dev-branch` | Snapshot a running VM and boot a fresh child with new identity and secrets. |
| Branch a saved checkpoint | `mvmctl machine restore ckpt-dev-123 --as dev-restore` | Restore a `vm_full` checkpoint into a fresh child VM with new identity and secrets. |
| Verify a portable artifact | `mvmctl machine check-artifact ./app.mvm --key ./publisher.pub` | Signature, hash, format, and host-architecture verification before admission. |

Portable artifact creation and `machine run <artifact>` are still preview
follow-ups in Plan 200. Until those commands land, use `machine check-artifact`
to verify admission posture and use the existing lower-level artifact tools for
advanced workflows.

## One-Shot Image Runs

Use one-shot runs when the result is the command output, not a retained machine:

```bash
mvmctl machine run --image alpine:3.20 -- uname -a
```

The first run may pull and materialize the image. Later runs can reuse cached
inputs when the image digest and policy inputs still match. Cache reuse never
skips admission or verification.

Networking is default-deny. Opt in explicitly:

```bash
mvmctl machine run --net --image alpine:3.20 -- nslookup example.com
mvmctl machine run --net --allow-host registry.npmjs.org --image alpine:3.20 -- \
  wget -q -O /dev/null https://registry.npmjs.org
```

Use digest-pinned image references for production or repeatable environments.

## Persistent Dev Machines

Use named machines when you want state across starts:

```bash
mvmctl machine create alpine-dev --image alpine:3.20 --net
mvmctl machine start alpine-dev
mvmctl machine exec alpine-dev -- apk add jq
mvmctl machine shell alpine-dev
mvmctl machine stop alpine-dev
```

The durable spec is stored under the mvm data directory, not in your source tree.
Mutable guest changes remain dev state. If a change should become a production
input, promote it back across the boundary as source, config, or an exported
artifact.

## mvm.toml Machines

Use a manifest when the machine should be repeatable:

```toml
image = "alpine:3.20"
cpus = 2
mem = "512M"
net = true
allow_hosts = ["registry.npmjs.org"]
```

```bash
mvmctl machine create js-dev --manifest ./mvm.toml
mvmctl machine start js-dev
```

Unknown manifest keys are rejected. That is intentional: typos should not
silently widen network, volume, or dev-init behavior.

## Fork and Restore

Use `machine fork` to branch a running VM into a fresh child, or `machine
restore` to branch an existing `vm_full` checkpoint. Both produce a new VM
identity and admit a new plan, so the child starts with fresh authority and
per-instance secrets; the parent carries no workload authority into the child.

```bash
# Snapshot a running machine and branch it
mvmctl machine fork alpine-dev --as alpine-dev-feature-x

# Auto-name with a branch slug
mvmctl machine fork alpine-dev --branch feature-x

# Branch from an existing checkpoint
mvmctl machine restore ckpt-alpine-dev-1720000000 --as alpine-dev-from-checkpoint
```

For explicit control over class selection or same-identity restore, the
lower-level `machine checkpoint` surface remains available.

## Read This Before Depending On A Capability

Machine UX intentionally keeps the first path small. Some capabilities are
unsupported, backend-specific, or future work. Read
[Machine limitations](/guides/machine-limitations/) before depending on network
protocol behavior, volume shapes, macOS signing or entitlement behavior, GPU availability,
or host/guest architecture support.

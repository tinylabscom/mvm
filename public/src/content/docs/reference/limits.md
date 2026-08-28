---
title: Limits & resources
description: CPU, memory, disk, network, and backend limits for local mvm workloads.
---

Resource limits come from the manifest, CLI overrides, backend support, and
host capacity. Do not treat a value as guaranteed just because the CLI accepts
it; the selected backend still has to support the shape.

## Manifest sizing

```toml
vcpus = 2
mem = "1024M"
data_disk = "0"
```

Use CLI overrides for local experimentation:

```sh
mvmctl machine run --flake ./my-app --cpus 4 --memory 2G
```

Commit the manifest values once the sizing is intentional.

## Backend limits

| Backend | Best for | Important limit |
| --- | --- | --- |
| Firecracker on Linux/KVM | Strongest local microVM isolation. | Requires `/dev/kvm` and Linux host support. |
| HVF / libkrun | macOS development and supported non-Linux paths. | Feature parity differs by macOS version and backend. |
| QEMU (TCG) | Linux dev/test without `/dev/kvm` (`--hypervisor qemu`). | Tier 2 dev/test; larger TCB, partial verified boot — not for production. |

Always verify the active posture with:

```sh
mvmctl doctor
```

## Files and volumes

Keep host mounts narrow. Use `mvmctl machine fs`, `mvmctl machine cp`, and declared volumes
instead of broad writable host shares when running untrusted code.

:::note[`machine fs` and `machine cp` are hidden verbs]
Both are marked `hide = true` in the CLI, so they work as documented but do not
appear in `mvmctl machine --help`.
:::

Declared volumes are `--mount host:guest[:SIZE][:ro|rw]` (`--volume` is an alias;
there is no `-v` short form — that is the global verbosity counter). The guest
path must live under `/data` or `/work`, and every mount is **read-only unless
you write `:rw`** — which itself needs `--profile dev` or `--profile permissive`.
A transient run's share is read-only under every profile.

Snapshots and cold-mode artifacts may contain guest memory, generated files,
and credentials present inside the guest. Treat them as sensitive state.

## Network

Network policy should start narrow and open only required destinations or
ports. Port forwarding is explicit:

```sh
mvmctl machine run --image alpine --name devbox --port 8080:8080
```

Prefer loopback host binds for local development unless public exposure is an
intentional part of the workflow.

## Operational guidance

- Leave CPU and memory headroom for the host and builder VM.
- Size disk for the Nix store, rootfs artifacts, snapshots, and logs.
- Use cleanup and manifest-prune commands for old build slots.
- Do not publish performance or cold-start claims without naming backend,
  artifact, host, and readiness boundary.

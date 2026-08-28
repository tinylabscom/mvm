---
title: Persistence, pause & resume
description: Keep or discard sandbox state intentionally.
---

State is a product decision. A sandbox can be disposable, long-running, paused, cold-stored, or backed by volumes. See [Lifecycle states](/working/lifecycle-states/) for the full state model.
For stateful agent and service workspaces, see [Persistent workspaces](/guides/persistent-workspaces/).

## What can persist

| State | Mechanism | Notes |
| --- | --- | --- |
| Files inside a running VM | VM runtime disk | Lost when the VM is destroyed unless captured or copied out. |
| Host-mounted files | Mount or copy workflow | Host exposure depends on mount mode and path selection. |
| Managed local volume | `mvmctl machine volume` | Encrypted at rest when locked. |
| Machine state | pause/resume or checkpoint create/restore | May contain memory, files, processes, and credentials present in the guest. |

## Pause and resume

```sh
mvmctl machine pause agent-sandbox
mvmctl machine resume agent-sandbox
```

Both verbs are hidden advanced operations — they work, but they do not appear in
`mvmctl machine --help` — and both default to `--hypervisor firecracker` and
drive the snapshot through Firecracker's control socket. See
[Snapshots](/working/snapshots/) for the separate live-memory, machine-state,
disk-only, standby, and cold-boot tiers. Use `mvmctl doctor` to see which tier
the selected backend advertises.

## Cold mode

Cold mode is the product posture where compute is released while an explicitly
supported recovery artifact is retained. See [Cold mode](/working/cold-mode/).

## Cleanup

```sh
mvmctl machine stop agent-sandbox
mvmctl machine sandbox gc
mvmctl env cleanup
```

Stopping compute does not automatically erase every artifact. Check volumes, snapshots, receipts, logs, and caches when the workflow needs stronger cleanup.

## Security notes

- Treat snapshots as sensitive state.
- Avoid preserving browser sessions or agent workspaces unless required.
- Lock managed volumes after use.
- Prefer explicit destroy/cleanup steps in tutorials and automation.

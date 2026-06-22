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
| Managed local volume | `mvmctl volume` | Encrypted at rest when locked. |
| Machine state | pause/resume or checkpoint create/restore | May contain memory, files, processes, and credentials present in the guest. |

## Pause and resume

```sh
mvmctl pause agent-sandbox
mvmctl resume agent-sandbox
```

The exact backend mechanics differ. See [Snapshots](/working/snapshots/) for Firecracker sealed snapshots and Vz machine-state files.

## Cold mode

Cold mode is the product posture where a sandbox is snapshotted, compute is released, and the sandbox can later be restored. See [Cold mode](/working/cold-mode/).

## Cleanup

```sh
mvmctl machine stop agent-sandbox
mvmctl sandbox gc
mvmctl cleanup
```

Stopping compute does not automatically erase every artifact. Check volumes, snapshots, receipts, logs, and caches when the workflow needs stronger cleanup.

## Security notes

- Treat snapshots as sensitive state.
- Avoid preserving browser sessions or agent workspaces unless required.
- Lock managed volumes after use.
- Prefer explicit destroy/cleanup steps in tutorials and automation.

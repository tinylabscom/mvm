---
title: Snapshots and cold mode
description: Pause a microVM into sealed state, create checkpoints, and restore later with explicit integrity checks.
---

Cold mode means a workload is not currently consuming a running guest, but it has recoverable state. In `mvm`, that state is represented by backend-specific snapshot and checkpoint artifacts.

## Current snapshot and checkpoint paths

| Path | Backend | Commands | Status |
| --- | --- | --- | --- |
| Sealed instance snapshot | Firecracker | `mvmctl pause`, `mvmctl resume`, `mvmctl snapshot ls`, `mvmctl snapshot rm` | Shipped for the Firecracker snapshot path. |
| Pool instance sleep | Firecracker pool lifecycle | internal pool lifecycle APIs | Implemented in pool lifecycle; public docs should stay tied to the CLI surface. |

Other backends may support stop/start without machine-state recovery. Do not assume snapshot or checkpoint support unless the active backend reports it and the docs name that backend explicitly.

## Firecracker pause and resume

Pause a running VM:

```sh
mvmctl pause agent-sandbox
```

`mvmctl pause` asks Firecracker to write `vmstate.bin` and `mem.bin` under the VM's instance snapshot directory, seals the sidecar with an epoch-bound HMAC envelope, and marks the VM as paused in the local registry.

Resume it:

```sh
mvmctl resume agent-sandbox
```

`mvmctl resume` verifies the sealed envelope before loading the state and clearing the paused flag. Replay of older sealed snapshots is refused by the epoch binding.

List and remove local sealed snapshots:

```sh
mvmctl snapshot ls
mvmctl snapshot rm agent-sandbox
```

## Other backends

Current macOS backends do not publish a user-facing full-memory checkpoint contract in the public docs. Until HVF or libkrun carries a documented restore path with explicit integrity semantics, treat cold-mode recovery as Firecracker-specific at the CLI/docs layer and name any backend-specific experiments separately.

## Security implications

- Snapshot files contain guest memory and runtime state. Treat them as sensitive.
- Restore integrity is backend-specific: Firecracker uses the sealed instance envelope.
- Deleting a snapshot removes the recovery artifact but does not by itself prove storage-level erasure.
- Snapshots can preserve credentials or derived tokens that existed inside the guest at snapshot time.

## Docs rule

When writing examples, name the backend. "Snapshot restore" is not a universal property of every `mvm` backend, and cold-mode behavior should not be used as a latency claim unless the benchmark states the backend, artifact, and readiness boundary.

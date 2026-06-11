---
title: Snapshots and cold mode
description: Pause a microVM into sealed state, create checkpoints, and restore later with explicit integrity checks.
---

Cold mode means a workload is not currently consuming a running guest, but it has recoverable state. In `mvm`, that state is represented by backend-specific snapshot and checkpoint artifacts.

## Current snapshot and checkpoint paths

| Path | Backend | Commands | Status |
| --- | --- | --- | --- |
| Sealed instance snapshot | Firecracker | `mvmctl pause`, `mvmctl resume`, `mvmctl snapshot ls`, `mvmctl snapshot rm` | Shipped for the Firecracker snapshot path. |
| Memory checkpoint (vm-full) | Vz | `mvmctl checkpoint create --class vm-full`, `mvmctl checkpoint restore`, `mvmctl checkpoint ls`, `mvmctl checkpoint rm` | Shipped on supported macOS versions. |
| Pool instance sleep | Firecracker pool lifecycle | internal pool lifecycle APIs | Implemented in pool lifecycle; public docs should stay tied to the CLI surface. |

Other backends may support stop/start without machine-state recovery. Do not assume snapshot or checkpoint support unless the active backend reports it.

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

## Vz memory checkpoints

On supported macOS hosts, Vz memory checkpoints capture full guest state:

```sh
mvmctl checkpoint create agent-sandbox --class vm-full
mvmctl checkpoint restore agent-sandbox --name <checkpoint-name>
```

`checkpoint create` pauses the VM, saves machine state and memory to the checkpoint directory, and records the content hash in the audit chain. `checkpoint restore` re-hashes the checkpoint content and records whether it matches the prior chain entry before restoring.

The restore proceeds even when the checkpoint hash is not in the local chain or has drifted, because operators may transfer checkpoints between hosts. The audit entry labels that result so the operator can review it.

List and remove checkpoints:

```sh
mvmctl checkpoint ls
mvmctl checkpoint rm agent-sandbox --name <checkpoint-name>
```

Fork a checkpoint to a new identity (new VM name, same state):

```sh
mvmctl checkpoint fork agent-sandbox --name <checkpoint-name> --into new-sandbox
```

## Security implications

- Snapshot files contain guest memory and runtime state. Treat them as sensitive.
- Restore integrity is backend-specific: Firecracker uses the sealed instance envelope; Vz uses audit-chain hash comparison.
- Deleting a snapshot removes the recovery artifact but does not by itself prove storage-level erasure.
- Snapshots can preserve credentials or derived tokens that existed inside the guest at snapshot time.

## Docs rule

When writing examples, name the backend. "Snapshot restore" is not a universal property of every `mvm` backend, and cold-mode behavior should not be used as a latency claim unless the benchmark states the backend, artifact, and readiness boundary.

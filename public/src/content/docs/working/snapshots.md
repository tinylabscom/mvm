---
title: Snapshots and cold mode
description: Pause a microVM into sealed state, create checkpoints, and restore later with explicit integrity checks.
---

Cold mode means a workload is not currently consuming a running guest, but it has recoverable state. In `mvm`, that state is represented by backend-specific snapshot and checkpoint artifacts.

## Recovery paths and current status

| Path | Meaning | Current status |
| --- | --- | --- | --- |
| Live-memory snapshot/restore | Restore guest RAM plus VMM state. | Not advertised by the selectable workload runners. `resume --warm` refuses with a typed error when the selected backend cannot honor it. |
| Save/restore machine state | Restore serialized VMM state without claiming live-memory fidelity. | No selectable backend currently advertises this tier. |
| Disk-only CoW warm start | Reboot from a copy-on-write disk/overlay artifact without restoring RAM. | The raw libkrun substrate has this primitive, but no selectable workload runner advertises it yet. |
| Prelaunched supervisor standby | Pre-pay supervisor/setup latency before attaching a workload. | Separate from snapshots; the raw libkrun substrate has the primitive, but no selectable workload runner advertises it yet. |
| Cold boot | Boot immutable artifacts from scratch. | Supported baseline recovery path. |

Other backends may support stop/start without machine-state recovery. Do not
assume a recovery tier unless the active backend reports it in
`mvmctl doctor`.

## Sealed instance snapshots

The `pause`/plain `resume` commands use the sealed instance-snapshot envelope
when that lifecycle is available for the selected backend. They do not imply
that the backend supports live-memory warm start.

Pause a running VM:

```sh
mvmctl machine pause agent-sandbox
```

`mvmctl machine pause` asks the backend snapshot transport to write `vmstate.bin` and
`mem.bin` under the VM's instance snapshot directory, seals the sidecar with
an epoch-bound HMAC envelope, and marks the VM as paused in the local registry.

Resume it:

```sh
mvmctl machine resume agent-sandbox
```

`mvmctl machine resume` verifies the sealed envelope before loading the state and
clearing the paused flag. Replay of older sealed snapshots is refused by the
epoch binding. `mvmctl machine resume --warm` is a distinct live-memory request and
fails closed when the selected backend cannot honor that tier.

List and remove local sealed snapshots:

```sh
mvmctl machine snapshot ls
mvmctl machine snapshot rm agent-sandbox
```

## Full-VM memory checkpoints

Full-VM memory checkpoints capture full guest state. They are currently unavailable through the selectable workload runners; request them only when `mvmctl doctor` reports a compatible backend and capability:

```sh
mvmctl machine checkpoint create agent-sandbox --class vm-full
mvmctl machine checkpoint restore agent-sandbox --name <checkpoint-name>
```

`checkpoint create` pauses the VM, saves machine state and memory to the checkpoint directory, and records the content hash in the audit chain. `checkpoint restore` re-hashes the checkpoint content and records whether it matches the prior chain entry before restoring.

The restore proceeds even when the checkpoint hash is not in the local chain or has drifted, because operators may transfer checkpoints between hosts. The audit entry labels that result so the operator can review it.

List and remove checkpoints:

```sh
mvmctl machine checkpoint ls
mvmctl machine checkpoint rm agent-sandbox --name <checkpoint-name>
```

Fork a checkpoint to a new identity (new VM name, same state):

```sh
mvmctl machine checkpoint fork agent-sandbox --name <checkpoint-name> --into new-sandbox
```

## Security implications

- Snapshot files contain guest memory and runtime state. Treat them as sensitive.
- Restore integrity is backend-specific: Firecracker uses the sealed instance envelope; full-VM checkpoints use audit-chain hash comparison.
- Deleting a snapshot removes the recovery artifact but does not by itself prove storage-level erasure.
- Snapshots can preserve credentials or derived tokens that existed inside the guest at snapshot time.

## Docs rule

When writing examples, name the backend. "Snapshot restore" is not a universal property of every `mvm` backend, and cold-mode behavior should not be used as a latency claim unless the benchmark states the backend, artifact, and readiness boundary.

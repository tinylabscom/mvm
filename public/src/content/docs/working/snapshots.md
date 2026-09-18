---
title: Snapshots and cold mode
description: Pause a microVM into sealed state, create checkpoints, and restore later with explicit integrity checks.
---

Cold mode means a workload is not currently consuming a running guest, but it has recoverable state. In `mvm`, that state is represented by backend-specific snapshot and checkpoint artifacts.

The `machine` verbs on this page (`pause`, `resume`, `snapshot`, `checkpoint`) are
hidden advanced operations: they work, but they do not appear in
`mvmctl machine --help`.

## Recovery paths and current status

| Path | Meaning | Current status |
| --- | --- | --- |
| Live-memory snapshot/restore | Restore guest RAM plus VMM state. | Not advertised by the selectable workload runners. `resume --warm` refuses with a typed error when the selected backend cannot honor it. |
| Save/restore machine state | Restore serialized VMM state without claiming live-memory fidelity. | Advertised by `hvf` and `apple-container`. `firecracker`, `libkrun`, `qemu`, and `wasm` all report `unsupported`. |
| Disk-only CoW warm start | Reboot from a copy-on-write disk/overlay artifact without restoring RAM. | The raw libkrun substrate has this primitive, but no selectable workload runner advertises it yet. |
| Prelaunched supervisor standby | Pre-pay supervisor/setup latency before attaching a workload. | Separate from snapshots; advertised by `firecracker` and `hvf`, and by no other selectable runner. |
| Cold boot | Boot immutable artifacts from scratch. | Supported baseline recovery path. |

Other backends may support stop/start without machine-state recovery. Do not
assume a recovery tier unless the active backend reports it in
`mvmctl doctor`.

## Sealed instance snapshots

The `pause`/plain `resume` commands use the sealed instance-snapshot envelope.
They do not imply that the backend supports live-memory warm start. Both verbs
default to `--hypervisor firecracker` and drive the snapshot through
Firecracker's control socket, so this lifecycle is a Firecracker path in
practice.

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

Full-VM memory checkpoints capture full guest state. They require a backend whose snapshot tier is `save-restore` or better — today `hvf` and `apple-container`; `firecracker`, `libkrun`, and `qemu` refuse with an explicit tier error. Check `mvmctl doctor` for the authoritative capability on this host:

```sh
mvmctl machine checkpoint create agent-sandbox --class vm-full
mvmctl machine checkpoint restore <checkpoint-id>
```

`checkpoint create` pauses the VM, saves machine state and memory to the checkpoint directory, and records the content hash in the audit chain. `checkpoint restore` re-hashes the checkpoint content and checks the record against the signed audit chain before restoring.

Restore fails closed. A checkpoint whose content has drifted, whose record disagrees with the signed chain, or that carries no signed creation entry is refused rather than restored. `checkpoint restore` and a `vm_full` fork also refuse a checkpoint for any tenant other than the one whose signed chain recorded its creation, because its saved memory is that tenant's data. The recorded tenant comes from the signed entry. The tenant it is compared with is the one the caller runs as (`MVM_TENANT` or the configured tenant), which the caller chooses. So this check stops a checkpoint from being restored into another tenant by mistake; it is not an authenticated boundary. Warm-pool claims are exempt: a pool parent is a boot that never ran a workload and carries no plan, tenant, secrets or volumes, so its memory holds no tenant's data.

On `hvf`, guest memory is not copied back into the restored VM. The RAM image is cloned into a private file in the VM's state directory, which must be on a local filesystem. The clone is opened read-only and its name removed, then it is hashed against the recorded digest, and the supervisor maps that same descriptor copy-on-write. The image is read once, to hash it. A page enters the restored VM's memory only when the guest touches it, and a page becomes private to that VM only when the guest writes it. Editing or replacing the checkpoint after verification does not reach the restored guest, because the guest maps the clone, not the checkpoint. Other users cannot write the clone either. This does not protect against a process running as your own user: in the moment between creating the clone and removing its name, such a process can open it for writing. That is outside the current threat model, because the VM supervisor already runs as your user, unsandboxed, and can read the host signing key. Each restore gets its own clone, so restored VMs share no memory pages with each other, even within one tenant. An encrypted RAM image is refused: mapping ciphertext as memory would boot noise, and decrypting it to disk would defeat the encryption. On a filesystem that cannot clone files, the image is copied byte for byte on every restore, which costs a full write of the guest's memory. Checkpoints taken before this layout (with guest RAM inside the frame file) are refused with a message asking you to capture them again.

List and remove checkpoints:

```sh
mvmctl machine checkpoint ls
mvmctl machine checkpoint rm <checkpoint-id>
```

`rm` refuses a checkpoint that a live or parked agent session resumes from, or that another stored checkpoint was forked from — restoring that descendant walks its parent chain and would fail once the parent is gone. Remove descendants first. `mvmctl cache prune` follows the same rule: it keeps every ancestor of a checkpoint it keeps.

Fork a checkpoint to a new identity (new VM name, same state):

```sh
mvmctl machine checkpoint fork <checkpoint-id> --new-id new-sandbox
```

## Security implications

- Snapshot files contain guest memory and runtime state. Treat them as sensitive.
- Restore integrity is backend-specific: Firecracker uses the sealed instance envelope; full-VM checkpoints use audit-chain hash comparison.
- Deleting a snapshot removes the recovery artifact but does not by itself prove storage-level erasure.
- Snapshots can preserve credentials or derived tokens that existed inside the guest at snapshot time.

## Docs rule

When writing examples, name the backend. "Snapshot restore" is not a universal property of every `mvm` backend, and cold-mode behavior should not be used as a latency claim unless the benchmark states the backend, artifact, and readiness boundary.

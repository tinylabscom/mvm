---
title: Cold-mode recovery
description: Pause, save, restore, and wake sandboxes from backend-specific snapshot state.
---

Cold mode lets a sandbox stop consuming a running VM while keeping recoverable state.

`pause` and `resume` are hidden advanced single-VM operations. Explicit checkpoint capture and restore use the `machine checkpoint` interface.

## Firecracker sealed pause/resume

```sh
cargo run -- machine pause agent-sandbox
cargo run -- machine resume agent-sandbox
```

The sealed instance snapshot is managed by `pause` and `resume`; there is no
public named-snapshot list command. Use `machine checkpoint ls` for explicit,
chain-anchored checkpoints.

Firecracker pause/resume writes sealed instance state and verifies it before resume. This is the local `mvm` primitive.

## Full-VM memory checkpoints

```sh
cargo run -- machine checkpoint create agent-sandbox --class vm-full
cargo run -- machine checkpoint restore <checkpoint-id>
```

`checkpoint restore` takes the checkpoint's own id, not the VM name.

Full-VM checkpoints capture full machine state. Current selectable runners report `live-memory` for Firecracker on KVM and `save-restore` for `hvf` and `apple-container`; `libkrun`, `qemu`, and `wasm` report `unsupported`. Check `mvmctl doctor` for the backend and capability on your host before relying on one. The checkpoint metadata digest (including the snapshot-store ID when present) is bound into the signed audit chain, and restore verifies it against that chain before loading saved state.

## Security checklist

- Snapshot artifacts may contain guest memory, files, credentials, tokens, and browser/session state.
- Restore support is backend-specific.
- A restore is not a security boundary; it is a lifecycle transition.
- Deleting a snapshot is not the same as proving physical erasure.
- Published latency numbers must state backend, artifact, and readiness boundary.

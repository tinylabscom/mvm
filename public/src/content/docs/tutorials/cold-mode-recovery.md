---
title: Cold-mode recovery
description: Pause, save, restore, and wake sandboxes from backend-specific snapshot state.
---

Cold mode lets a sandbox stop consuming a running VM while keeping recoverable state.

Every verb on this page is an advanced single-VM op reached through `machine`. They work, but they are hidden from `machine --help`.

## Firecracker sealed pause/resume

```sh
cargo run -- machine pause agent-sandbox
cargo run -- machine snapshot ls
cargo run -- machine resume agent-sandbox
```

Firecracker pause/resume writes sealed instance state and verifies it before resume. This is the local `mvm` primitive.

## Full-VM memory checkpoints

```sh
cargo run -- machine checkpoint create agent-sandbox --class vm-full
cargo run -- machine checkpoint restore <checkpoint-id>
```

`checkpoint restore` takes the checkpoint's own id, not the VM name.

Full-VM checkpoints capture full machine state. Among the selectable workload runners only `hvf` and `apple-container` support save/restore; `firecracker`, `libkrun`, `qemu`, and `wasm` do not. Check `mvmctl doctor` for the backend and capability on your host before relying on one. `mvm` records the checkpoint content hash in the audit chain when the launch plan and host signer are available, and restore records whether the content matched the prior chain entry.

## Security checklist

- Snapshot artifacts may contain guest memory, files, credentials, tokens, and browser/session state.
- Restore support is backend-specific.
- A restore is not a security boundary; it is a lifecycle transition.
- Deleting a snapshot is not the same as proving physical erasure.
- Published latency numbers must state backend, artifact, and readiness boundary.

---
title: Cold-mode recovery
description: Pause, save, restore, and wake sandboxes from backend-specific snapshot state.
---

Cold mode lets a sandbox stop consuming a running VM while keeping recoverable state.

## Firecracker sealed pause/resume

```sh
cargo run -- pause agent-sandbox
cargo run -- snapshot ls
cargo run -- resume agent-sandbox
```

Firecracker pause/resume writes sealed instance state and verifies it before resume. This is the local `mvm` primitive.

## Other backends

Current public docs do not publish a user-facing full-memory checkpoint flow for the active macOS backends. When restore support is documented for another backend, the tutorial must name the backend and its integrity evidence instead of implying universal checkpoint recovery.

## Security checklist

- Snapshot artifacts may contain guest memory, files, credentials, tokens, and browser/session state.
- Restore support is backend-specific.
- A restore is not a security boundary; it is a lifecycle transition.
- Deleting a snapshot is not the same as proving physical erasure.
- Published latency numbers must state backend, artifact, and readiness boundary.

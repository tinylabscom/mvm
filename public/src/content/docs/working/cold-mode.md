---
title: Cold mode
description: How mvm presents paused, sleeping, and snapshot-restored sandboxes.
---

Cold mode is the product-level lifecycle state for a sandbox that is not running but can be recovered from saved state.

In `mvm`, cold mode maps to backend-specific snapshot mechanisms. It is a lifecycle state, not a separate runtime.

## mvm model

```text
Running microVM
  -> pause/save snapshot
  -> cold state on disk
  -> resume/restore
  -> Running microVM
```

The runtime primitive is `mvm`: it knows how to talk to the backend, write or verify the snapshot artifact, and restore the guest. The exact artifact depends on the backend.

## What users need to know

| Question | Answer |
| --- | --- |
| Is cold state free? | No. It consumes storage and may contain sensitive guest state. |
| Is restore universal? | No. Backend support differs. |
| Is restore a security boundary? | No. It is a lifecycle feature; isolation still comes from the microVM/backend and policy layers. |
| Can cold mode be fast? | It can be faster than a fresh build-plus-boot path, but published numbers must state backend and readiness boundary. |

## Required docs language

Use "cold mode" for the product state. Use backend-specific terms for implementation:

- Firecracker sealed pause/resume.
- Full-VM machine-state save/restore (advertised by `hvf` and `apple-container`; check `mvmctl doctor` before requesting it).
- Pool Sleeping/Running restore.
Avoid implying that every backend supports every cold-mode operation.

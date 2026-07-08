---
title: Verified boot
description: Rootfs integrity posture and backend-specific verification limits.
---

Verified boot is the claim that a guest boots the artifact that admission
approved. In `mvm`, that evidence is backend-specific and must be described
with its limits.

## What is verified

- The build path records artifact identity.
- Launch admission binds the selected artifact into the execution plan.
- Supported rootfs formats can carry integrity metadata.
- Audit records connect build, admission, launch, snapshot, and restore events.

## What varies by backend

| Backend | Posture |
| --- | --- |
| Firecracker on Linux/KVM | Strongest target for dm-verity/root hash enforcement. |
| Apple Hypervisor.framework / libkrun | Useful microVM isolation, but verified-boot evidence differs by backend support. |
| QEMU (Linux, dev/test) | Partial verified-boot support; Tier 2 dev/test, not a production target. |

Use [Matryoshka model](/security/matryoshka/) for the tier matrix before making
a user-facing claim.

## Snapshots and restore

Snapshots are separate from first boot. Firecracker sealed pause/resume and any future backend-specific machine-state restore path have their own integrity evidence. A restore is a lifecycle transition, not a new security boundary.

## Documentation rule

Say exactly which backend and artifact path you mean. Avoid writing "verified
boot is always on" unless the referenced backend, artifact type, and test
evidence prove that exact statement.

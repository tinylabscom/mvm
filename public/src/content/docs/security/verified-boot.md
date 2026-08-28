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

## Universal initramfs activation

Workloads that attach the universal initramfs boot a static `mvm-guest-agent`
as `/init`. The kernel cmdline carries no roothash tokens. The guest PID 1
waits fail-closed for a signed `ActivateEnvironment` over vsock, mounts the
dm-verity rootfs and runtime overlay from fixed block slots, pivots into the
verified root, and drops to the workload UID before serving operational RPCs.
See [Boot flow](/architecture/boot-flow/) for the full sequence.

## What varies by backend

| Backend | Posture |
| --- | --- |
| Firecracker on Linux/KVM | Strongest target for dm-verity/root hash enforcement. |
| HVF / libkrun | Useful microVM isolation, but verified-boot evidence differs by backend support. |
| QEMU (Linux, dev/test) | Partial verified-boot support; Tier 2 dev/test, not a production target. |

Use [Matryoshka model](/security/matryoshka/) for the tier matrix before making
a user-facing claim.

## Snapshots and restore

Snapshots are separate from first boot. Firecracker sealed pause/resume has its
own integrity evidence. Full-VM machine-state save/restore is advertised by HVF
— the macOS 26+ auto-detect default — and by `apple-container`, which boots
through the same supervisor; libkrun, QEMU, and Firecracker report it
unsupported. The incremental live-memory tier is advertised only by the
test-support mock. `mvmctl doctor` is the authoritative capability check, and a
request a backend does not advertise fails closed. A restore is a lifecycle
transition, not a new security boundary.

## Documentation rule

Say exactly which backend and artifact path you mean. Avoid writing "verified
boot is always on" unless the referenced backend, artifact type, and test
evidence prove that exact statement.

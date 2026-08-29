# Warm standby image claim repair

**Status:** IN PROGRESS  
**Issue:** #3002
Backing: shipped-source  
Validation: check-sprint-append

## Problem

The documented live witness expected its first `machine run` to seed warm
capacity even though transient teardown deliberately no longer replenishes the
pool. On HVF, an explicitly warmed OCI launch also selected the mutable
virtiofs directory root, while standby compatibility and claim admission bind
the immutable ext4 image digest. The shape was therefore rejected before a
claim and the live scenario could never observe a warm launch.

## Decision

Warm-targeted launches use the block image. That makes the guest boot the same
bytes named by the pool key, captured into the parent checkpoint, and bound by
the admitted plan. Zero-pool development launches keep the faster virtiofs-root
path. The live scenario provisions capacity explicitly with `pool warm` before
asserting a claim on both HVF and Firecracker.

## Tasks

- [x] Add a failing unit regression for warm-targeted OCI root selection.
- [x] Keep warm-targeted launches on the image-bound block root while retaining
      virtiofs for zero-pool development launches.
- [x] Replace the obsolete implicit-replenish setup in the live BDD with an
      explicit `pool warm 1 --image alpine` precondition.
- [x] Pass host workspace tests, check, formatting, Clippy, gated compilation,
      and repository policy gates.
- [ ] Pass the macOS/HVF and Linux/Firecracker documented-surface witnesses.
- [ ] Merge the issue-closing PR through the merge queue and confirm #3002 is
      closed by the merge.

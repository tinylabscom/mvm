# Warm standby image claim repair

**Status:** IN PROGRESS
**Issue:** #3002
Backing: shipped-source
Validation: check-sprint-append

## Problem

The documented live witness expected its first `machine run` to seed warm
capacity even though transient teardown deliberately no longer replenishes the
pool. On HVF, an explicitly warmed OCI launch uses the dev tier's read-only
virtiofs root, but the eligibility gate excluded that root shape before looking
for a compatible parent. The default macOS tier therefore paid to maintain a
pool that its ordinary image launches could never claim.

## Decision

Root strategy is part of the exact standby compatibility key. HVF parents keep
the same read-only virtiofs OCI tree that ordinary dev launches already boot;
Firecracker and sealed launches keep the block root. A parent can only satisfy
a claimant using the same strategy, image digest, kernel, sizing, and egress
enablement. The live scenario explicitly runs `pool warm` against the suite's
artifact-warm home, then compares transient request state with a pre-run
baseline so shared runner state cannot hide a leak or force a cold rebuild.

## Tasks

- [x] Add a failing unit regression for an HVF virtiofs image launch excluded
      from warm eligibility.
- [x] Model block and virtiofs roots in the persisted compatibility key, with a
      block default for records written before the field existed.
- [x] Preserve HVF's working virtiofs dev root while preventing it from matching
      a block-backed parent in either direction.
- [x] Replace the obsolete implicit-replenish setup in the live BDD with an
      explicit `pool warm 1 --image alpine` precondition in the artifact-warm
      live home, with baseline-relative request-state cleanup.
- [x] Pass host workspace tests, check, formatting, Clippy, gated compilation,
      and repository policy gates.
- [x] Replace the probabilistic signed-audit substring assertion exposed by the
      eBPF lane with exact verification of the authenticated stream labels.
- [ ] Pass the macOS/HVF and Linux/Firecracker documented-surface witnesses.
- [ ] Merge the issue-closing PR through the merge queue and confirm #3002 is
      closed by the merge.

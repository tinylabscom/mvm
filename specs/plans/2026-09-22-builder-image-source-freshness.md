# Builder image source freshness

Backing: shipped-source
Validation: check-sprint-append

Issue: #3524

**Status: IN PROGRESS**

## Goal

Prevent a source-checkout builder job from booting a cached builder image made
from older Nix inputs or older embedded host binaries. The configured cache and
the host-wide cache used to seed isolated worktrees must obey the same source
fingerprint decision as `mvmctl bootstrap`; installed release binaries with no
source checkout keep their artifact-only cache contract.

## Work

- [x] Add test-first regressions for a stale configured cache, a stale shared
      seed, and a release cache with no source fingerprint.
- [x] Reuse the Stage 0 fingerprint resolver, including its embedded
      host-binary identities, at the VMM-neutral cache-loader boundary.
- [x] Treat a source-fingerprint mismatch or missing marker as a cache miss
      before returning a configured image or copying a shared image.
- [x] Let an unembedded contributor binary delegate the authoritative
      readiness decision to its embedded bootstrap helper; do not change
      library embedders or installed binaries without a source checkout.
- [x] Fail closed when the source-checkout helper preflight is skipped or
      declines, rather than loading a cache whose fingerprint was not checked.
- [x] Pass focused tests, workspace check/tests, zero-warning Clippy,
      formatting, gated-target checks, and all repository policy gates.
- [ ] Deliver the issue-closing change through the protected merge queue.

## Security invariants

- A source-built image is admitted only when its recorded fingerprint matches
  the Nix inputs and host-binary bytes the current bootstrap would install.
- A shared cache is still digest-verified before its bytes enter an isolated
  worktree cache.
- Release artifacts do not acquire a source-tree trust dependency; their
  existing digest/provenance checks remain authoritative.
- A library embedder never gains permission to spawn `mvmctl` or a bootstrap
  helper.

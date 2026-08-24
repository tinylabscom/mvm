# Merge-queue throughput

Backing: preview
Validation: none

**Status:** IN PROGRESS

## Goal

Return the merge queue's successful tail to the actual validation critical path
and raise sustained throughput without dropping Rust, policy, architecture,
kernel, or Nix coverage. Keep cache writes behind a trusted default-branch
boundary and preserve the stable required-check names used by branch
protection.

## Evidence

On 2026-08-14, 37 completed merge-group CI runs had a 39-minute median,
96-minute p90, and 123-minute maximum successful duration. Six runs failed.
The longest executing lane in a representative 123-minute run took 39 minutes;
the remainder was runner admission delay. The 12-second CI scope job waited
about 35 minutes while an independent Nix job acquired a runner first, delaying
every Rust lane that depended on scope.

The repository is in a GitHub Free organization, has no repository-level
self-hosted runners, and is limited to 20 standard hosted jobs. Two speculative
merge groups currently fan out into CI, architecture, and kernel workflows,
which is enough to saturate that pool before ordinary pull-request work.

## Work

- [x] Add structural regression coverage for scope-first scheduling,
      architecture/kernel consolidation, trusted workspace-cache writes, and
      Nix binary-cache installation.
- [x] Make the shared CI scope classify Rust, Nix, architecture, and kernel
      inputs; keep every expensive merge-group lane behind that short gate.
- [x] Fold the architecture invariant into the existing required policy lane
      and publish the existing `Invariant` check name from that real lane.
- [x] Move pull-request and merge-group kernel checks into the main CI graph,
      while leaving release/manual kernel artifact publication in the dedicated
      workflow and preserving both required architecture-specific check names.
- [x] Seed workspace-crate Cargo artifacts and Nix outputs only from the trusted
      default-branch cache warmer; restore them in validation jobs.
- [x] Remove duplicated feature-test work and validate the optimized workflow
      shape with actionlint and focused tests.
- [x] Move the `aarch64-no-kvm-smoke` job out of the merge queue. The cold
      QEMU TCG path can take hours, and making it a required gate serialized
      every merge. It remains in `ci-full.yml` (nightly + manual dispatch) so
      the path is still exercised, and the structural tests assert it no longer
      blocks the `Test` aggregate.
- [ ] Run formatting, workspace check, the complete workspace test suite, and
      Linux all-target Clippy.
- [ ] Land the workflow change through the merge queue, then update and read
      back the live queue policy: use `HEADGREEN`, batch two validated entries
      with a five-minute bound, and raise speculative width only to the level
      supported by the measured post-consolidation runner demand.
- [ ] Record post-change timings and the organization-owner-only capacity
      boundary in the sprint and refactor rollups.

## Safety boundaries

- Pull-request and merge-group code never receives a cache credential or a
  writable default-branch cache scope.
- Required behavior remains transitively owned by `Lint`, `Test`, `Invariant`,
  the two kernel contexts, and the Nix check.
- Paid plan changes, organization runner creation, and billing changes are not
  repository operations and require an organization owner.
- Speculative width is not increased to four on the current 20-job pool: the
  2026-08-11 incident proved that configuration can time out valid checks and
  create self-amplifying work. Width may rise only after consolidation
  measurements or an owner-provided capacity increase.

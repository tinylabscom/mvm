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

On 2026-09-29, four successful pull-request CI runs took 65, 80, 112, and 120
minutes even though their longest executing job took only 20-24 minutes. Each
run allocated 11 substantive lanes and consumed 132-150 runner-minutes. A
representative 65-minute run waited 19 minutes for the 12-second scope job,
then rebuilt `cargo-zigbuild` for 7-9 minutes in each of two feature lanes; its
zero-second Lint aggregate waited another five minutes for runner admission.
A successful merge-group run consumed 204 runner-minutes across 15 substantive
lanes. Fourteen open pull requests were competing for the same 20-job pool.

On 2026-09-30, the latest 100 merged pull requests took 5h25m at the median and
20h50m at p90 from creation to merge. Head validation itself took 62 minutes at
the median even though its longest common job took 22 minutes. In 23 successful
merge-group runs, jobs started 4.7 minutes after the workflow at the median and
46.6 minutes at p90; the six-second required aggregates waited as long as
80-87 minutes. The same expensive matrix ran first on the pull-request commit
and then on the integrated merge-group commit.

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
- [x] Restore the trusted-main Rust cache before installing the embedded-host
      toolchain in both PR feature lanes. The cache already carries
      `~/.cargo/bin`, so the pinned `cargo-zigbuild` install can reuse the
      trusted binary instead of compiling it for 7-9 minutes per lane.
- [x] Remove the broad 25-30 GB runner cleanup from the focused eBPF lane. Its
      measured run spent 4m14s deleting unrelated preinstalled tools, then only
      3m37s on both toolchain setup and its one-object/one-crate validation.
- [x] Move the `aarch64-no-kvm-smoke` job out of the merge queue. The cold
      QEMU TCG path can take hours, and making it a required gate serialized
      every merge. It remains in `ci-full.yml` (nightly + manual dispatch) so
      the path is still exercised, and the structural tests assert it no longer
      blocks the `Test` aggregate.
- [x] Trial compile-free pull-request admission with the expensive matrix only
      on the integrated merge-group commit. Reverted after deterministic policy
      and BDD failures repeatedly reached the queue and contaminated entries
      behind them; code PRs now run the complete deterministic matrix before
      admission and the merge group remains the final integration witness.
- [x] Trial two speculative entries building. Returned to one during reliability
      stabilization: GitHub may build later entries on cumulative speculative
      heads, so a failure in front can still make unrelated entries appear red.
      Reconsider width only from measured clean-queue rebuild and wait data.
- [x] Move the documented live BDD lifecycle to nightly Extended CI after live
      queue runs spent 27-40 minutes inside it. Keep hermetic BDD and the
      bounded locked-image boot witness in the merge gate.
- [x] Remove source image, runtime-overlay and reproducibility builds from the
      merge gate. mvm-images owns those canonical builds; the source-override
      path remains available as a manual diagnostic.
- [x] Make `Test` the single required Actions context and remove the redundant
      `Lint` aggregate runner; `Test` directly owns every lint result.
- [x] Restore the trusted Nix store through the restore-only cache action on
      merge refs; only the trusted main warmer writes a reusable cache.
- [x] Add a bounded PR preflight: run the real policy/invariant lane before
      queue admission, ShellCheck changed scripts, and execute the embedded
      helper recipe regression. The focused checks remain alongside the restored
      full PR matrix, and the merge-group matrix remains authoritative for the
      exact integration commit.
- [x] Require the stable `Test` context against current `main`, build one queue
      entry at a time, and merge one PR per group while the queue is stabilized.
      Keep all required and recommended verification; optimize lane internals,
      cache reuse, and runner admission rather than deleting coverage.
- [ ] Run formatting, workspace check, the complete workspace test suite, and
      Linux all-target Clippy.
- [ ] Land the workflow change through the merge queue. The live stabilization
      policy has been read back as `HEADGREEN`, one entry building, one entry
      per merge, no minimum-entry wait, and strict required checks.
- [ ] Record post-change PR and merge-group timings after this ordering change
      lands; compare p50/p90 wall time, scope admission, and total
      runner-minutes against the 2026-09-29 sample above.

## Safety boundaries

- Pull-request and merge-group code never receives a cache credential or a
  writable default-branch cache scope.
- Required behavior remains transitively owned by the single `Test` context,
  which validates lint, policy, architecture, test, boot and scoped Nix results.
- Paid plan changes, organization runner creation, and billing changes are not
  repository operations and require an organization owner.
- Speculative width is not increased to four on the current 20-job pool: the
  2026-08-11 incident proved that configuration can time out valid checks and
  create self-amplifying work. Width may rise only after consolidation
  measurements or an owner-provided capacity increase.

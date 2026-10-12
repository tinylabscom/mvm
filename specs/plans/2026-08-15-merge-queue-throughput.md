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

On 2026-10-05, the queue had 40 entries and the live ruleset had drifted back
to two speculative builds. One code-scoped merge-group run peaked around 14
hosted runners, so two groups requested roughly 28 against the organization's
20-runner limit before pull-request workflows were counted. GitHub marked jobs
it could not acquire after repeated attempts as cancelled; the required
aggregate correctly surfaced those infrastructure cancellations as `Checks
failed` on #4048, #4051, and #4044. The tests themselves were not the failure.

On 2026-10-10, median pull-request CI was 58-106 minutes, against 2-6 minutes
on 2026-10-01 and 2026-10-02. #3971 had moved the whole matrix onto pull
requests, and #4117 then reduced the merge group to scope classification. A
representative uncontended run (38099555037) had a 33-minute aarch64 lane, a
26-minute `Lint feature coverage`, and a workspace suite whose shards could
not start until the archive job finished an 8-minute nextest filter listing.
Contended runs started lanes up to 40 minutes late. With the queue now
batched (three groups building, up to five entries each), the #4117 shape also
meant batched PRs were never tested together.

## Policy since 2026-10-10: fast gate on the PR, full matrix in the queue

A pull request runs the fast gate; the merge queue runs everything.

| Lane | Pull request | Merge queue |
|---|---|---|
| Lint core (`cargo fmt --all`, clippy `--all-targets`, BDD target clippy) | yes | yes |
| Lint feature combinations (clippy over the unified non-default features, verifier-absent, `mvm-sdk` no-defaults) | yes | yes |
| Invariant (actionlint, `xtask check-all`, script gates) | yes | yes |
| Windows compile check | yes | yes |
| Build workspace tests + Test workspace (x86_64 shards) | yes | yes |
| Feature test suites (default, test-support, embed-host-bins) | — | yes |
| Workspace extras (doctests, man pages, nextest filter validation) | — | yes |
| aarch64 workspace suite | — | yes |
| Release-profile witness, musl confinement, eBPF, Linux coverage | — | yes |
| BDD conformance (with the live PS-11 witness) | — | yes |
| Boot latency ceiling, Nix flake check | — | yes |

How this differs from #3893, which #3971 reverted: #3893 made PR admission
compile-free, so a change that did not compile, failed clippy, or broke a unit
test was first discovered in a merge group, where it marked every entry built
on top of it red. The fast gate keeps exactly those failures on the PR: every
workspace test target is compiled (including the Linux-gated ones and the BDD
runner) and the unit suite runs before admission. What moves to the queue is
the slow integration evidence — other architectures, other profiles and libcs,
live witnesses, feature *test* suites — whose failures are rarer and are, by
nature, properties of the merged tree.

How this differs from #4117: the queue no longer reuses the PR's result. With
batching, the PR's proof was for a commit that never merges; the queue's run is
for the one that does.

The `Test` aggregate enforces both tiers by event: a full-matrix lane that runs
on a pull request is refused, as is any lane that skips in the queue. Merge
groups no longer share a concurrency key, because the queue builds several at
once. The queue-policy guard admits exactly two shapes: the singleton queue (one
building, one per group, no wait) and the batched one (`ALLGREEN`, three
building, up to five per group, minimum one, five-minute wait). Both stay
admitted so the ruleset switch and this workflow change can land in either
order without failing every queue run.

A runner picker (`Pick runners`) sends the x86_64 workspace suite to the idle
self-hosted KVM box when `RUNNER_PICKER_TOKEN` can see one, and to hosted
runners otherwise. It never fails a run and never selects the box for a
pull request from a fork. Routing is opt-in through the repository variable
`RUNNER_PICKER_WORKSPACE=true`: the box's first run took 34 minutes (12.6 of
them in the nextest filter listing) and failed three tests that pass hosted
(`registry_pack::tests::verified_payload_refuses_a_symlink_even_when_its_target_matches`,
`checkpoint::gc::tests::captures_racing_a_prune_always_link_a_verified_object`,
`bundle_push_emits_bundle_push_and_the_printed_reference_fetches`).
- [ ] Fix the self-hosted box's three failing tests and drop the filter listing
      from its shard, then set `RUNNER_PICKER_WORKSPACE=true`.

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
- [x] Run the complete deterministic proof before queue admission, including
      platform, feature, workspace, architecture, release, Linux, eBPF, Nix,
      boot, policy, and BDD verification. Keep merge-group execution to
      fail-closed scope classification and the required aggregate so the queue
      does not allocate a second copy of the full graph.
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
      helper recipe regression. These checks now sit inside the complete PR
      proof; the singleton merge group verifies the synthetic commit's scope and
      required aggregate without repeating every lane.
- [x] Require the stable `Test` context against current `main`, build one queue
      entry at a time, and merge one PR per group while the queue is stabilized.
      Keep all required and recommended verification; optimize lane internals,
      cache reuse, and runner admission rather than deleting coverage.
- [x] Stop Extended CI from taking the merge queue's runners. On 2026-10-05 a
      feature-branch dispatch held 15 jobs while a merge group's 13 waited, and
      groups that take 22 minutes on an idle pool took 50-97. `ci-full.yml`
      now runs one run at a time in a global concurrency group, and its jobs
      run as five serial tracks with the live BDD matrix one leg at a time:
      about five hosted runners instead of about 22. The SDK dry-run, whose
      matrices live in the called publish workflows, runs last and alone.
- [x] Fail in the scope job before fan-out when the live queue ruleset exceeds
      the `1/1/0` build/merge/wait runner budget.
- [x] Split CI into a pull-request fast gate and a full merge-queue matrix, let
      the queue batch (`ALLGREEN`, 3 building, 5 per group, 5-minute wait), and route the workspace suite to an idle
      self-hosted runner when one is visible. See the policy section above.
- [ ] Replace the broad `code` boolean with dependency-aware component scopes
      derived from the workspace graph. Each specialized lane should run for its
      owning component and reverse dependencies, failing closed on unknown paths.
      This is the safe route to more queue throughput without deleting checks.
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
- Speculative width was one until 2026-10-10. The 2026-10-05 incident showed
  width two exceeding capacity for code-scoped groups, and that remains the risk
  of the current three-group width: a group whose jobs cannot acquire runners
  shows up as `Checks failed`. Watch for infrastructure cancellations in queue
  runs, and narrow the width before deleting coverage.

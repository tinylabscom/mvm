# Plan 284 — CI lint and merge-queue latency

**Status: Complete**

## Goal

Reduce pull-request and merge-queue latency without weakening the required
Rust, policy, feature-gated, or Nix coverage.

The baseline is GitHub Actions run `30664687885`: `Lint (fmt + clippy +
policy)` occupied a runner for 36 minutes. Clippy and policy finished after
roughly 13 minutes; the remaining time was dominated by feature-test rebuilds.
The final `test-support` command repeated 8,610 tests after the Test job had
already run 8,595. The same lint job then uploaded a 4.44 GB `target/` cache.
GitHub scopes pull-request and merge-queue caches to their generated refs, so
sibling runs cannot restore those archives; the repository has no default-
branch cache for them to inherit. In addition, `mvm-cli` placed nested Cargo
targets below its feature-specific `OUT_DIR`, rebuilding the same embedded
binaries for clippy, `test-support`, and example feature fingerprints.

## Tasks

- [x] Add a structural regression test that pins the optimized CI shape.
- [x] Replace the workspace-wide `test-support` rerun with the library tests
      for `mvm-runtime`, `mvm-client`, and `mvm-cli`, the root
      `audit_emissions_live` integration test, and an explicit compile check
      for the required `verification_loop` example.
- [x] Remove the branch-scoped `target/` caches from the PR workflow and remove
      the lint-only disk purge they required.
- [x] Share `mvm-cli`'s nested embedded-binary and auxiliary-helper target
      across feature fingerprints while keeping it isolated from the outer
      Cargo target lock.
- [x] Move the `xtask` man-page feature tests from Lint to the required Test
      job, where the test-profile `mvm-cli` graph is already warm.
- [x] Keep the removed MCP server and its smoke lane out of CI while optimizing
      the remaining required jobs.
- [x] Measure the targeted feature lane locally: 2,718 tests plus the required
      example check completed in 7m27s, versus 13m38s and 8,610 tests for the
      sampled workspace-wide command.
- [x] Validate workflow syntax, the full xtask suite, formatting, workspace
      tests/check, and Linux all-target clippy.
- [x] Record the first post-change Actions timings and decide separately
      whether cross-branch sccache storage or larger runners are justified.

## First GitHub Actions result

Pull-request run `30682895396` passed on the exact branch commit. Test waited
19m07s for a runner and executed for 27m31s. Lint waited 21m10s and executed
for 37m36s; its targeted `test-support` step took 23m23s. The reduced test set
removed duplicate work, but the cold-run critical path did not improve over the
36-minute baseline because a small number of `mvm-cli` and live audit tests
still dominate that lane.

Do not add a cross-branch compiler cache without a trusted write boundary.
Faster or additional hosted-runner capacity is justified by the observed
19–21 minute runner waits; repository-scoped credentials cannot inspect or
change that organization-level allocation.

## Acceptance gates

- The CI workflow parses under `actionlint`.
- `xtask`'s CI-shape regression is green.
- The default workspace test lane remains unchanged.
- Every source location gated by `feature = "test-support"` is owned by one of
  the explicitly tested packages, and the feature-gated example is compiled.
- Two `mvm-cli` build-script `OUT_DIR`s in the same profile resolve to one
  nested target, so later feature variants reuse the embedded-binary graph.
- Man-page feature coverage remains required but does not rebuild the
  test-profile CLI graph on Lint's critical path.
- The removed MCP server and its former required-check lane remain absent.
- `cargo test --workspace`, `cargo check --workspace`, and Linux
  `cargo clippy --workspace --all-targets -- -D warnings` pass.

## Security posture

No active required behavioral gate is removed. The mock backend remains
test-only, and Nix closure checks remain required in the merge queue. Removing
branch-local build archives also reduces the cache-poisoning and stale-artifact
surface; a future shared compiler cache must be written only from a trusted
default-branch or external cache boundary.

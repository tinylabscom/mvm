# Plan 280 — CI lint and merge-queue latency

**Status: In progress**

## Goal

Reduce pull-request and merge-queue latency without weakening the required
Rust, policy, feature-gated, MCP, or Nix coverage.

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
- [x] Run the MCP stdio roundtrip inside the already-warm Test job for merge-
      queue and manual runs. Retain the historical required-check name as a
      skipped compatibility job so the branch rule does not need an unsafe
      transition window.
- [x] Measure the targeted feature lane locally: 2,718 tests plus the required
      example check completed in 7m27s, versus 13m38s and 8,610 tests for the
      sampled workspace-wide command.
- [ ] Validate workflow syntax, the full xtask suite, formatting, workspace
      tests/check, and Linux all-target clippy.
- [ ] Record the first post-change Actions timings and decide separately
      whether cross-branch sccache storage or larger runners are justified.

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
- MCP still executes before a merge, but no separate runner is allocated for
  its compatibility check.
- `cargo test --workspace`, `cargo check --workspace`, and Linux
  `cargo clippy --workspace --all-targets -- -D warnings` pass.

## Security posture

No required behavioral gate is removed. The mock backend remains test-only,
MCP continues to exercise its real JSON-RPC subprocess boundary, and Nix
closure checks remain required in the merge queue. Removing branch-local build
archives also reduces the cache-poisoning and stale-artifact surface; a future
shared compiler cache must be written only from a trusted default-branch or
external cache boundary.

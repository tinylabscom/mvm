# CI queue consolidation

Backing: shipped-source
Validation: check-sprint-append

**Status:** COMPLETE

## Goal

Reduce pull-request and merge-queue latency and runner fan-out without letting
path scoping or non-required witness jobs weaken exact merge-group validation.

## Measured baseline

- A code-changing pull request publishes up to twenty check runs after the
  feature-coverage split. The split itself is beneficial: three parallel jobs
  replaced a 35-minute serial lane and reduced the required critical path to
  roughly 23 minutes.
- `test-support` and `Test workspace` are now the two approximately 21-minute
  lanes. `check-nextest-groups` spends about five minutes issuing four test
  listings for two duplicated filters.
- The repository Actions cache is at 10.63 GB across 4,550 entries. The trusted
  main-branch Rust workspace entry is about 338 MiB; merge-ref Nix entries make
  up most of the object count.
- The merge queue uses `HEADGREEN`. A two-entry group merged while the earlier
  entry's required Nix job was still running because the head entry classified
  only its delta from the preceding queue entry and reported Nix out of scope.

## Work

- [x] Classify a merge-group head against the target branch rather than only
      the preceding queue entry, with a fail-closed fallback.
- [x] Make the required `Test` aggregate own Nix evaluation, tree-built guest
      boot, and the published-image boot ceiling. Keep Nix and the tree-built
      guest witness parallel after live timing proved serialization slower.
- [x] Stop the non-required Website workflow from consuming a runner on every
      merge-group event; retain its pull-request path gate.
- [x] Warm the `test-support` feature graph from trusted `main` and restore it
      under a dedicated cache key in pull-request and queue validation.
- [x] Deduplicate identical nextest override filters before invoking
      `cargo nextest list`.
- [x] Run workflow structure tests, actionlint, xtask tests, workspace tests,
      workspace check, formatting, and zero-warning Clippy.
- [x] Record the first live pull-request and merge-group timings, then decide
      whether combining additional short lanes improves the 20-runner capacity
      boundary without lengthening the critical path.
- [x] After the workflow lands, reduce classic branch protection to the stable
      `Lint (fmt + clippy + policy)` and `Test` aggregate contexts.

## Safety invariants

- Required checks validate the exact merge-group head, including every queued
  pull request represented by that head.
- No pull-request or ephemeral merge ref writes a trusted Rust cache entry.
- A skipped scoped lane is accepted only when the aggregate proves that the
  corresponding scope is out of range.
- Boot and Nix witnesses either feed a required aggregate or do not claim to
  gate merging.

## Validation

- `actionlint` passes for the three changed workflows.
- The executable aggregate matrix passes for pull requests, in-scope and
  out-of-scope merge groups, and deliberate lane failures.
- `cargo nextest run --workspace --all-targets` passes all 13,192 selected
  tests; 22 live or measurement tests remain intentionally skipped.
- `cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and
  `cargo fmt --all -- --check` pass.
- Two direct `cargo test --workspace` attempts exposed independent existing
  harness-concurrency artifacts after the test bodies passed; each failed
  target passed immediately in isolation. The configured nextest groups are
  the authoritative CI execution and completed cleanly.
- Pull-request run `34470355947` completed in 23m58s. All substantive jobs
  started immediately after scope classification; `Test` was green after
  20m11s, while the cold `test-support` lane set the full-run tail at 22m49s.
- Merge-group run `34472528030` completed in 29m12s and classified the exact
  queue head against `main`. Website did not run, and `Test` did not publish
  until Nix, both boot witnesses, both kernels, and the complete test matrix
  were green.
- The first folded Nix/guest run made Nix the 28m49s critical path. The prior
  parallel run completed Nix in 21m48s and the tree-built guest in 22m28s, so
  the final layout restores those jobs to parallel execution while retaining
  both as explicit `Test` dependencies. Runner capacity was not the limiter:
  every queue worker began within five seconds of scope completion.
- Classic branch protection now requires exactly `Lint (fmt + clippy + policy)`
  and `Test`, down from six direct contexts.
- Main cache-warm run `34475187048` populated the dedicated `test-support`
  cache successfully in 9m43s; the next pull request is the first live restore
  measurement.

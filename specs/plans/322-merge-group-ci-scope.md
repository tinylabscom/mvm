# Plan 322 — Scope merge-group Rust CI to behavior-changing diffs

**Status:** COMPLETE

## Problem

Every merge-queue entry currently allocates six expensive Rust runners even
when its synthetic merge commit changes only prose, plans, or the website. The
required Rust aggregates then take roughly 30–40 minutes to become conclusive,
while those lanes have no affected Rust behavior to validate. Runner admission
for that unnecessary work also delays code-bearing entries.

The Nix, kernel, policy, and architecture gates already own broader or separate
input surfaces. They remain independent and fail closed.

## Work

- [x] Add one fail-closed classifier for pull-request and merge-group SHA
      ranges, with manual dispatch forcing the full matrix.
- [x] Gate compiler lint, feature coverage, workspace tests, release-profile
      witnesses, Linux/conformance coverage, and eBPF coverage on paths that
      can change compiled or generated behavior.
- [x] Keep policy checks running for every diff, and keep Nix's independent
      required-check classifier unchanged.
- [x] Make the stable `Lint (fmt + clippy + policy)` and `Test` aggregates
      accept only deliberate `skipped` results while still failing on scope,
      policy, cancellation, or lane failure.
- [x] Pin the workflow shape with regression coverage and validate action
      syntax, formatting, workspace compilation/tests, and all-target Clippy.

## Safety boundary

An unknown event or a failed diff never skips validation. Manual dispatch runs
everything. Rust sources, manifests, tests, generators, BDD features, schemas,
models, build scripts, CI actions, test configuration, and the scripts invoked
by CI all select the full Rust matrix. Required aggregate names do not change.

The Nix gate is intentionally not coupled to the new classifier: its existing
independent scope remains the authority for everything the flakes evaluate or
build, so a Rust-scope mistake cannot turn the required Nix context green.

## Expected effect

Code-bearing changes retain the current full coverage. Prose/site-only entries
run the classifier, policy, existing Nix scope, architecture, kernel scope, and
stable aggregate reporters, but avoid six cold Rust jobs. In the queue sampled
on 2026-08-11, two of ten waiting entries matched that fast path.

## Validation

`actionlint`, formatting, workspace compilation, all-target Clippy, and all
499 `xtask` tests pass. The serialized workspace suite passed every test except
one transient host-agent restart assertion; its exact test passed immediately
on an isolated rerun.

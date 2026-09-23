# Issue #3315 — composable ext4 build options

Status: validation complete; ready for delivery

## Outcome

`mvm-fs::ext4` exposes one dense writer, `build_image`, and one sparse writer,
`emit_image`. Both accept the existing `BuildOptions` parameter object; the
parallel `build_image_with_options` and `emit_image_with_options` entry points
are removed.

Callers that want deterministic zero UUID and volume-name fields now state
that choice with `BuildOptions::default()`. Callers that stamp image metadata
continue to pass their configured options without an intermediate wrapper.

## Regression coverage

- the existing option-stamping test exercises `build_image` directly and
  verifies the configured UUID and volume name in the superblock;
- the existing dense-versus-streamed equivalence and sink-error tests exercise
  `emit_image` directly;
- workspace compilation covers every downstream writer caller;
- the public-function-name gate is ratcheted from 59 to 57 remaining sibling
  pairs and treats `mvm-fs/src/ext4/mod.rs` as cleared.

## Validation

- test-first compile — failed as expected because the canonical functions did
  not yet accept `BuildOptions`;
- `cargo test -p mvm-fs ext4::tests` — 16 focused ext4 tests passed;
- `cargo check --workspace` — passed;
- `cargo clippy --workspace --all-targets -- -D warnings` — passed;
- `just check-gated` — passed for Linux cross-target and BDD feature targets;
- `cargo run -q -p xtask -- check-all` — 74 repository gates passed;
- `just bdd` — 67 features and 265 scenarios completed with 264 passed and
  one declared skip;
- `cargo test --workspace -- --test-threads=1` — every unit and integration
  suite passed. The combined command then encountered a transient missing
  `mvm_sdk` rlib while starting `mvm-build` doctests; an isolated rebuild of
  that doctest passed, followed by a clean
  `cargo test --workspace --doc -- --test-threads=1` run;
- `cargo fmt --all --check` — passed;
- `cargo run -q -p xtask -- check-public-function-names` — 57 sibling pairs
  remain and five modules are cleared.

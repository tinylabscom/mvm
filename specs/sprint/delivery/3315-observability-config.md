# Issue #3315 — composable observability initialization

Status: validated; ready for merge queue

## Outcome

`mvm-observability` no longer exposes parallel `init` and
`init_with_filter` functions. `ObservabilityConfig` starts with the workspace
filter, composes a caller-specific fallback filter, and installs the tracing
subscriber. The common `init(LogFormat)` entry point remains as the
standard-default convenience.

The CLI now expresses verbosity through the configuration builder. `RUST_LOG`
still wins inside the shared filter resolver, and invalid caller filters still
fall back without panicking.

## Regression coverage

- the configuration defaults to `DEFAULT_FILTER` without changing the selected
  output format;
- composing a caller filter preserves both the supplied directive and format;
- the public-function-name gate is ratcheted from 65 to 64 remaining sibling
  pairs and treats `mvm-observability/src/logging.rs` as cleared.

## Validation

- `cargo test -p mvm-observability logging::tests::observability_config`
  — 2 passed;
- `cargo test -p mvm-observability` — 46 unit tests, 2 OTLP exit tests,
  2 OTLP export tests, 10 span-timing tests, and 4 overhead tests passed;
- `cargo test -p mvm-cli logging::tests` — 3 passed;
- `cargo fmt --all --check` — passed;
- `cargo check --workspace` — passed;
- `cargo clippy --workspace --all-targets -- -D warnings` — passed;
- `just check-gated` — macOS and Linux-gated targets passed;
- `cargo run -p xtask -- check-all` — all 74 repository gates passed;
- `just bdd` — 256 scenarios (255 passed, 1 declared skip) and 982
  steps (981 passed, 1 declared skip);
- `cargo test --workspace -- --test-threads=1` — full serialized workspace
  rerun passed after rebuilding one stale doctest dependency artifact.

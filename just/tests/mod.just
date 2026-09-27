set working-directory := "../.."

# Run tests with sccache caching the workspace crates.
# Usage: just tests::cached [FILTER]
#   FILTER: optional test filter expression
cached FILTER="":
    #!/usr/bin/env bash
    set -euo pipefail
    @command -v sccache >/dev/null || { echo "sccache not found — install with: cargo install sccache"; exit 1; }
    if [ -n "{{ FILTER }}" ]; then
    RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 cargo nextest run --workspace -E 'test({{ FILTER }})' 2>&1 | tee target/nextest/last-run.log
    else
    RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 cargo nextest run --workspace 2>&1 | tee target/nextest/last-run.log
    fi
    @sccache --show-stats

# Run tests matching a filter expression (alias for test with filter)
# Usage: just test-filter FILTER
# Run a single crate's tests
# Usage: just tests::crate CRATE
#   CRATE: crate name to test
crate CRATE:
    ./scripts/require-nextest.sh
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }}

# Run tests under the `ci` profile: no retries, slow-test warnings, and a
# JUnit report at target/nextest/ci/junit.xml carrying pass/fail structure
# only (no captured test output — see .config/nextest.toml).
# Usage: just tests::ci [FILTER]
#   FILTER: optional test filter expression
ci FILTER="":
    ./scripts/require-nextest.sh
    if [ -n "{{ FILTER }}" ]; then
    ./scripts/cargo-fast.sh nextest run --workspace --profile ci -E 'test({{ FILTER }})'
    else
    ./scripts/cargo-fast.sh nextest run --workspace --profile ci
    fi

# Run tests with cargo test (fallback if nextest not installed)
# Usage: just tests::cargo [FILTER]
#   FILTER: optional test filter expression
cargo FILTER="":
    if [ -n "{{ FILTER }}" ]; then
    ./scripts/cargo-fast.sh test --workspace -E 'test({{ FILTER }})'
    else
    ./scripts/cargo-fast.sh test --workspace
    fi

# Doctests. nextest does NOT run doctests, so `just test` skips them;
# this is the companion that keeps doc-fence coverage gated.
doc:
    ./scripts/cargo-fast.sh test --workspace --doc

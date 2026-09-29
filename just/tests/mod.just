set working-directory := "../.."

# Run tests matching a filter expression (alias for test with filter)
# Usage: just test-filter FILTER
# Run a single crate's tests
# Usage: just tests::crate CRATE
#   CRATE: crate name to test
crate CRATE:
    ./scripts/require-nextest.sh
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }}

# Run one crate's tests filtered by test name during the debugging loop.
# Usage: just tests::scoped CRATE [FILTER]
scoped CRATE FILTER="":
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/require-nextest.sh
    if [ -n "{{ FILTER }}" ]; then
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }} -E 'test({{ FILTER }})'
    else
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }}
    fi

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

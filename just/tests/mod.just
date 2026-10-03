set working-directory := "../.."

# Usage: just tests::crate CRATE
#   CRATE: crate name to test

# Run a single crate's tests
crate CRATE:
    ./scripts/require-nextest.sh
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }}

# Usage: just tests::scoped CRATE [FILTER]

# Run one crate's tests filtered by test name during the debugging loop
scoped CRATE FILTER="":
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/require-nextest.sh
    if [ -n "{{ FILTER }}" ]; then
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }} -E 'test({{ FILTER }})'
    else
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }}
    fi

# No retries, slow-test warnings, and a JUnit report at
# target/nextest/ci/junit.xml carrying pass/fail structure only (no captured
# test output — see .config/nextest.toml).
# Usage: just tests::ci [FILTER]
#   FILTER: optional nextest filter expression

# Run all tests under the nextest `ci` profile
ci FILTER="":
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/require-nextest.sh
    if [ -n "{{ FILTER }}" ]; then
    ./scripts/cargo-fast.sh nextest run --workspace --profile ci -E 'test({{ FILTER }})'
    else
    ./scripts/cargo-fast.sh nextest run --workspace --profile ci
    fi

# `cargo test` takes a plain substring filter, not a nextest `-E` expression.
# Usage: just tests::cargo [FILTER]
#   FILTER: optional test-name substring

# Run all tests with cargo test (fallback if nextest is not installed)
cargo FILTER="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{ FILTER }}" ]; then
    ./scripts/cargo-fast.sh test --workspace -- '{{ FILTER }}'
    else
    ./scripts/cargo-fast.sh test --workspace
    fi

# nextest does NOT run doctests, so `just test` skips them; this is the
# companion that keeps doc-fence coverage gated.

# Run the workspace doctests
doc:
    ./scripts/cargo-fast.sh test --workspace --doc

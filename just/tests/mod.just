set working-directory := "../.."

# Show available subcommands
[private]
default:
    @just --list tests

# Usage: just tests::crate CRATE
#   CRATE: crate name to test

# Run a single crate's tests
crate CRATE:
    ./scripts/require-nextest.sh
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }}

# Usage: just tests::scoped CRATE [FILTER] [--lib | --test NAME]

# Run one crate's tests, optionally limiting compilation to one target
[positional-arguments]
scoped CRATE FILTER="" *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/require-nextest.sh
    crate="$1"
    filter="$2"
    shift 2
    args=(nextest run -p "$crate" "$@")
    if [ -n "$filter" ]; then
      args+=(-E "test($filter)")
    fi
    exec ./scripts/cargo-fast.sh "${args[@]}"

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

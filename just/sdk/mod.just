set working-directory := "../.."

# Usage: just sdk::build [lang]
#   lang: sdk name (python, typescript) or "all" (default)

# Build the publishable SDK artifacts without building the Rust workspace
build LANG="all":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ LANG }}" in
      all)
        just sdk::build-python
        just sdk::build-typescript
        ;;
      python|typescript)
        just "sdk::build-{{ LANG }}"
        ;;
      *)
        echo "unknown SDK language: {{ LANG }} (expected all, python, or typescript)" >&2
        exit 1
        ;;
    esac

# Build the Python SDK wheel and sdist
build-python:
    uv build crates/mvm-sdk/sdks/python --out-dir crates/mvm-sdk/sdks/python/dist

# Build the TypeScript SDK
build-typescript:
    npm --prefix crates/mvm-sdk/sdks/typescript run build

# Run once after a fresh clone or whenever package-lock.json changes.

# Install TypeScript SDK dependencies locally
install-typescript:
    npm --prefix crates/mvm-sdk/sdks/typescript ci

# Neither SDK suite is a cargo target, so `cargo nextest run --workspace` does
# not touch them and a Rust-only gate leaves the hand-written half of each
# SDK — the subprocess wrappers, the argv builders, the refusal paths —
# unproven.
# Usage: just sdk::test [lang]
#   lang: sdk name (python, typescript) or "all" (default)

# Run the language SDKs' own unit suites
test LANG="all":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ LANG }}" in
      all)
        just sdk::test-python
        just sdk::test-typescript
        ;;
      python|typescript)
        just "sdk::test-{{ LANG }}"
        ;;
      *)
        echo "unknown SDK language: {{ LANG }} (expected all, python, or typescript)" >&2
        exit 1
        ;;
    esac

# `--extra schema` installs pydantic; without it the eight
# `derive_schema` tests fail on an ImportError rather than being skipped.

# Run the Python SDK's unit suite
test-python:
    uv run --directory crates/mvm-sdk/sdks/python --group dev --extra schema pytest -q

# Run the TypeScript SDK's unit suite
test-typescript: install-typescript
    npm --prefix crates/mvm-sdk/sdks/typescript run test

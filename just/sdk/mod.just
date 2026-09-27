# Build the publishable SDK artifacts without building the full Rust workspace.
# Usage: just sdk::build [lang]
#   lang: sdk name (python, typescript) or "all" (default)
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

# Build a single language SDK.
build-python:
    uv build crates/mvm-sdk/sdks/python --out-dir crates/mvm-sdk/sdks/python/dist

build-typescript:
    npm --prefix crates/mvm-sdk/sdks/typescript run build


# Install TypeScript SDK dependencies locally. Run once after a fresh clone or
# whenever package-lock.json changes.
install-typescript:
    npm --prefix crates/mvm-sdk/sdks/typescript ci
# Run the language SDKs' own unit suites. Neither is a cargo target, so
# `cargo nextest run --workspace` does not touch them and a Rust-only gate
# leaves the hand-written half of each SDK — the subprocess wrappers, the
# argv builders, the refusal paths — unproven.
# Usage: just sdk::test [lang]
#   lang: sdk name (python, typescript) or "all" (default)
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
test-python:
    uv run --directory crates/mvm-sdk/sdks/python --group dev --extra schema pytest -q

test-typescript: install-typescript
    npm --prefix crates/mvm-sdk/sdks/typescript run test

#!/bin/bash
set -euo pipefail

# Deploy guard — verifies release integrity before publishing to crates.io.
#
# Checks:
#   1. Workspace version exists
#   2. Current commit is tagged with v{version}
#   3. All crates use version.workspace = true (no hardcoded versions)
#   4. Inter-crate dependency versions match workspace version
#   5. Workspace builds and passes clippy

# Check if we're in the workspace root
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Must run from workspace root"
    exit 1
fi

FOUND_ERROR=0

# 1. Get workspace version
WORKSPACE_VERSION=$(grep -A 5 '^\[workspace\.package\]' Cargo.toml | grep '^version' | head -1 | cut -d '"' -f 2)
if [ -z "$WORKSPACE_VERSION" ]; then
    echo "Error: Could not extract workspace version from Cargo.toml"
    exit 1
fi
echo "Workspace version: ${WORKSPACE_VERSION}"

# 2. Check if current commit is tagged with this version
TAG_NAME="v${WORKSPACE_VERSION}"
CURRENT_TAG=$(git tag --points-at HEAD 2>/dev/null || true)

if [[ ! " ${CURRENT_TAG} " =~ " ${TAG_NAME} " ]]; then
    echo "Error: Current commit is not tagged with ${TAG_NAME}"
    echo "Tags at HEAD: ${CURRENT_TAG:-<none>}"
    echo "  Fix: git tag ${TAG_NAME} && git push origin ${TAG_NAME}"
    exit 1
fi

echo "Verified: HEAD is tagged with ${TAG_NAME}"

# 3. Check all crates inherit version from workspace
if [ ! -d "crates" ]; then
    echo "Error: crates directory not found"
    exit 1
fi

# Crates excluded from the workspace-version requirement. These are versioned
# independently (e.g. not yet published to crates.io, or on a separate cadence).
EXCLUDED_CRATES=(
    "mvm-apple-container"
)

is_excluded() {
    local crate_name="$1"
    for excluded in "${EXCLUDED_CRATES[@]}"; do
        if [ "$crate_name" = "$excluded" ]; then
            return 0
        fi
    done
    return 1
}

echo "Checking for hardcoded versions in crates..."

for cargo_toml in crates/*/Cargo.toml; do
    if [ ! -f "$cargo_toml" ]; then
        continue
    fi
    crate_name=$(basename "$(dirname "$cargo_toml")")
    if is_excluded "$crate_name"; then
        echo "  - skipping $crate_name (independent versioning)"
        continue
    fi
    # Match only the [package].version line, not dependency version entries.
    if awk '/^\[package\]/{p=1; next} /^\[/{p=0} p && /^version *= */{found=1; exit} END{exit !found}' "$cargo_toml"; then
        echo "Error: Hardcoded [package].version found in $cargo_toml"
        awk '/^\[package\]/{p=1; next} /^\[/{p=0} p && /^version *= */{print}' "$cargo_toml"
        FOUND_ERROR=1
    fi
done

if [ $FOUND_ERROR -ne 0 ]; then
    echo "All published crates must use 'version.workspace = true'"
    exit 1
fi

echo "Verified: All published crates use workspace version"

# 4. Check inter-crate dependency versions match workspace version
echo "Checking inter-crate dependency versions..."

# Check [workspace.dependencies] entries for mvm-* crates
while IFS= read -r line; do
    dep_version=$(echo "$line" | sed -n 's/.*version *= *"\([^"]*\)".*/\1/p')
    if [ -n "$dep_version" ] && [ "$dep_version" != "$WORKSPACE_VERSION" ]; then
        echo "Error: Version mismatch in workspace dependencies"
        echo "  Found: $line"
        echo "  Expected version: ${WORKSPACE_VERSION}"
        FOUND_ERROR=1
    fi
done < <(grep -E '^mvm-[a-z]+ *= *\{.*version' Cargo.toml || true)

# Check that subcrate deps use .workspace = true (not hardcoded versions)
for cargo_toml in crates/*/Cargo.toml; do
    if [ ! -f "$cargo_toml" ]; then
        continue
    fi
    while IFS= read -r line; do
        dep_version=$(echo "$line" | sed -n 's/.*version *= *"\([^"]*\)".*/\1/p')
        if [ -n "$dep_version" ]; then
            echo "Error: Hardcoded inter-crate version in $cargo_toml (use .workspace = true)"
            echo "  Found: $line"
            FOUND_ERROR=1
        fi
    done < <(grep -E '^mvm-[a-z]+ *= *\{.*version' "$cargo_toml" || true)
done

if [ $FOUND_ERROR -ne 0 ]; then
    echo "Inter-crate dependency versions must match workspace version ${WORKSPACE_VERSION}"
    exit 1
fi

echo "Verified: All inter-crate dependencies use version ${WORKSPACE_VERSION}"

# 5. Verify workspace compiles and passes clippy
echo "Running cargo clippy..."
if ! cargo clippy --workspace -- -D warnings 2>&1; then
    echo "Error: Clippy check failed"
    exit 1
fi
echo "Verified: Clippy passes"

echo ""
echo "Deploy guard passed!"

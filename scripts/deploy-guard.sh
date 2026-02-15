#!/bin/bash
set -euo pipefail

# Check if we're in the workspace root
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Must run from workspace root"
    exit 1
fi

# 1. Get workspace version
WORKSPACE_VERSION=$(grep -m 1 "^version = " Cargo.toml | cut -d '"' -f 2)
echo "Workspace version: ${WORKSPACE_VERSION}"

# 2. Check if current commit is tagged with this version
TAG_NAME="v${WORKSPACE_VERSION}"
CURRENT_TAG=$(git tag --points-at HEAD)

if [[ ! " ${CURRENT_TAG} " =~ " ${TAG_NAME} " ]]; then
    echo "Error: Current commit is not tagged with ${TAG_NAME}"
    echo "Tags at HEAD: ${CURRENT_TAG}"
    exit 1
fi

echo "Verified: HEAD is tagged with ${TAG_NAME}"

# 3. Check all crates inherit version from workspace
# We use `cargo metadata` to check versions, but a simple grep check might be enough if we enforce `version.workspace = true`
# Let's check if any Cargo.toml in crates/ has a hardcoded version instead of workspace
echo "Checking for hardcoded versions in crates..."

# Check if crates directory exists
if [ ! -d "crates" ]; then
    echo "Error: crates directory not found"
    exit 1
fi

echo "Checking for hardcoded versions in crates..."
FOUND_ERROR=0

for cargo_toml in crates/*/Cargo.toml; do
    if [ -f "$cargo_toml" ]; then
        if grep -q "^version = " "$cargo_toml"; then
            echo "Error: Hardcoded version found in $cargo_toml"
            grep "^version = " "$cargo_toml"
            FOUND_ERROR=1
        fi
    fi
done

if [ $FOUND_ERROR -ne 0 ]; then
    echo "All crates must use 'version.workspace = true'"
    exit 1
fi

echo "Verified: All crates use workspace version"

echo "Deploy guard passed!"

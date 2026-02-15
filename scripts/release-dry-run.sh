#!/bin/bash
set -u pipefail

# Check if we're in the workspace root
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Must run from workspace root"
    exit 1
fi

echo "Running cargo publish --dry-run for all crates in dependency order..."
echo "Note: Dependent crates may fail if base crates are not yet on crates.io."

FAILED_CRATES=()

CRATES=(
    mvm-core
    mvm-guest
    mvm-build
    mvm-runtime
    mvm-coordinator
    mvm-agent
    mvm-cli
    mvm
)

for CRATE in "${CRATES[@]}"; do
    echo "----------------------------------------------------------------"
    echo "Checking ${CRATE}..."
    if cargo publish -p "${CRATE}" --dry-run --allow-dirty --no-verify; then
        echo "✅ ${CRATE} passed dry-run"
    else
        echo "⚠️ ${CRATE} failed dry-run (likely due to unpublished dependencies)"
        FAILED_CRATES+=("${CRATE}")
    fi
done

echo "----------------------------------------------------------------"
if [ ${#FAILED_CRATES[@]} -eq 0 ]; then
    echo "All crates passed dry-run!"
else
    echo "Summary of failures (expected for fresh release):"
    for FAILED in "${FAILED_CRATES[@]}"; do
        echo " - ${FAILED}"
    done
    echo "Note: Failures are expected if dependencies are only local."
fi

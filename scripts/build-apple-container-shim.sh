#!/usr/bin/env bash
# Build the Apple Containerization shim and install it (codesigned with the
# virtualization entitlement) into the mvm cache the backend resolves:
#   <MVM_HOME>/cache/apple-container/bin/mvm-container-shim
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_root="${MVM_HOME:-$HOME/.mvm}/cache/apple-container"

cd "$repo_root/swift/mvm-container-shim"
swift build -c release --product mvm-container-shim

mkdir -p "$cache_root/bin"
cp .build/release/mvm-container-shim "$cache_root/bin/mvm-container-shim"
codesign --entitlements "$repo_root/assets/mvmctl.entitlements" -f -s - \
  "$cache_root/bin/mvm-container-shim"

echo "apple-container shim installed at $cache_root/bin/mvm-container-shim"

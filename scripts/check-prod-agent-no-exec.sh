#!/usr/bin/env bash
# Runtime guest-agent boundary regression gate.
#
# The guest agent is one universal artifact. This gate exercises the actual
# request policy and signed-grant enforcement instead of inspecting optimized
# symbol tables. It also runs the detached handler test, proving that the
# DevOnly implementation is present and functional when a Dev profile and
# grant admit it.

set -euo pipefail

echo "::group::Guest-agent runtime profile and grant conformance"
cargo test --locked -p mvm-agentd --lib --all-targets
echo "::endgroup::"

echo "::group::Universal DevOnly handler behavior"
cargo test --locked -p mvm-agentd --bin mvm-guest-agent --all-targets run_detached
echo "::endgroup::"

echo "Guest-agent runtime boundary passed: sealed profiles reject DevOnly verbs,
signed ProdSafe grants cannot authorize them, and the universal DevOnly handler
is compiled and functional."

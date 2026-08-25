#!/usr/bin/env bash
# Plan 76 Phase 1 / Phase 8 (partial) — sealed-prod vsock allowlist
# regression gate.
#
# The `cargo test ... -- --exact <name>` invocation exits 0 when no
# tests match the filter — so if any of the named tests are renamed
# or deleted, a naive `cargo test` step would silently report
# "0 passed" and turn the lane green. This script wraps cargo test
# with a count assertion: it fails if the expected number of tests
# does not run AND pass, which catches deletions and renames in
# addition to the classifier widening the SealedProd allowlist.
#
# The gate locks both profile classification and the signed-grant intersection
# that protects DevOnly verbs in the universal guest-agent artifact.

set -euo pipefail

# Test names locked by plan 76 Phase 1. Adding a test to this list
# requires updating EXPECTED_GUEST_COUNT / EXPECTED_CONTRACT_COUNT to
# match.
GUEST_TESTS=(
  "vsock::request_policy::tests::test_request_class_coverage_matches_sealed_prod_allowlist"
  "vsock::request_policy::tests::test_sealed_prod_rejects_dev_only_verbs"
  "vsock::request_policy::tests::test_sealed_prod_accepts_prod_safe_verbs"
  "vsock::response::tests::test_unsupported_in_profile_response_roundtrip"
)
EXPECTED_GUEST_COUNT=${#GUEST_TESTS[@]}

CONTRACT_TESTS=(
  "policy::security::tests::test_security_policy_defaults"
  "policy::security::tests::test_security_policy_missing_profile_field_is_sealed_prod"
  "policy::security::tests::test_security_policy_dev_defaults_carries_dev_profile"
  "policy::security::tests::test_agent_profile_serde_kebab_case"
)
EXPECTED_CONTRACT_COUNT=${#CONTRACT_TESTS[@]}

run_locked_tests() {
  local crate="$1"
  local expected="$2"
  shift 2
  local tests=("$@")
  local log
  log=$(mktemp)
  trap 'rm -f "$log"' RETURN

  echo "── ${crate}: asserting ${expected} sealed-prod tests pass"
  if ! cargo test -p "${crate}" --lib --no-fail-fast -- --exact "${tests[@]}" \
    >"${log}" 2>&1; then
    cat "${log}"
    echo "❌ cargo test failed for ${crate}"
    return 1
  fi
  cat "${log}"

  # Count lines like `test foo::bar::baz ... ok` for the tests we
  # asked for. `--exact` filters mean nothing else can match, so
  # `wc -l` of " ... ok$" lines == expected count iff every named
  # test ran and passed.
  local actual
  actual=$(grep -cE ' \.\.\. ok$' "${log}" || true)
  if [[ "${actual}" != "${expected}" ]]; then
    echo
    echo "❌ ${crate}: expected exactly ${expected} sealed-prod tests, got ${actual}"
    echo "   A locked test was likely renamed or deleted. Update"
    echo "   scripts/check-sealed-prod-allowlist.sh to match — but"
    echo "   first justify in the PR description why widening or"
    echo "   relaxing the SealedProd surface is intentional."
    return 1
  fi
}

run_locked_tests mvm-agentd "${EXPECTED_GUEST_COUNT}" "${GUEST_TESTS[@]}"
run_locked_tests mvm-contract "${EXPECTED_CONTRACT_COUNT}" "${CONTRACT_TESTS[@]}"

echo
echo "✅ Sealed-prod vsock allowlist locked: ${EXPECTED_GUEST_COUNT} mvm-agentd + ${EXPECTED_CONTRACT_COUNT} mvm-contract tests pass."

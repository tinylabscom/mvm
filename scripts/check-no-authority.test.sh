#!/usr/bin/env bash
# Exercises check-no-authority.sh against a fake `cargo` and `nm`, so the
# canary and absence logic is verified on every PR (security.yml, which runs
# the real build, has no pull_request trigger).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/target/release"

printf '#!/bin/sh\nexit 0\n' > "$fixture/bin/cargo"
printf '#!/bin/sh\ncat "$FAKE_NM_SYMBOLS"\n' > "$fixture/bin/nm"
chmod +x "$fixture/bin/cargo" "$fixture/bin/nm"

run() { # run <target> <symbols-file>
  (cd "$fixture" && PATH="$fixture/bin:$PATH" FAKE_NM_SYMBOLS="$2" \
    "$repo_root/scripts/check-no-authority.sh" "$1") >"$fixture/out" 2>&1
}
expect_pass() { run "$1" "$2" || { cat "$fixture/out"; echo "FAIL: $3" >&2; exit 1; }; }
expect_fail() {
  if run "$1" "$2"; then cat "$fixture/out"; echo "FAIL: $3" >&2; exit 1; fi
  grep -q "$4" "$fixture/out" || { cat "$fixture/out"; echo "FAIL: $3 (wrong reason)" >&2; exit 1; }
}

printf '%s\n' 'mvm_guest_agent::handle_run_entrypoint' >"$fixture/agent-clean"
printf '%s\n' 'mvm_guest_agent::handle_run_entrypoint' \
  'mvm_hostd::admit_for_run' >"$fixture/agent-authority"
printf '%s\n' 'mvm_core::protocol::host_signer::Wire' \
  'mvm_guest_agent::handle_run_entrypoint' >"$fixture/agent-wire-type"
printf '%s\n' 'unrelated_symbol' >"$fixture/stripped"
printf '%s\n' 'mvm_builderd::serve' >"$fixture/builderd-clean"
printf '%s\n' 'mvm_builderd::serve' 'mvm_build::load_host_signing_key' \
  >"$fixture/builderd-authority"

expect_pass guest-agent "$fixture/agent-clean" "a clean agent passes"
expect_pass guest-agent "$fixture/agent-wire-type" \
  "mvm_core's host_signer wire-type module is not signing authority"
expect_fail guest-agent "$fixture/agent-authority" "agent with admit_for_run fails" \
  "admit_for_run"
expect_fail guest-agent "$fixture/stripped" "a stripped agent fails vacuously-true" \
  "stripped"
expect_pass builderd "$fixture/builderd-clean" "a clean builderd passes"
expect_fail builderd "$fixture/builderd-authority" \
  "builderd with load_host_signing_key fails" "load_host_signing_key"
expect_fail builderd "$fixture/stripped" "a stripped builderd fails" "stripped"
if "$repo_root/scripts/check-no-authority.sh" bogus >/dev/null 2>&1; then
  echo "FAIL: an unknown target must be refused" >&2; exit 1
fi
echo "ok: check-no-authority canary, absence and target selection"

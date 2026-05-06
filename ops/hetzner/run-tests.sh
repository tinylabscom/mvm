#!/usr/bin/env bash
# Run the mvm test suite on a real Linux+KVM host.
#
# Designed for the Hetzner test box provisioned by ops/hetzner/cloud-init.yaml,
# but works on any Ubuntu 24.04+ host that has Rust + Firecracker + Nix
# installed (use cloud-init.yaml as a checklist).
#
# Stops at the first failure so the operator sees what broke without
# scrolling. Pass `--continue` to power through.
#
# Idempotent. Safe to re-run.

set -euo pipefail

# shellcheck source=/dev/null
[ -f "$HOME/.mvm-test.env" ] && source "$HOME/.mvm-test.env"
# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

cd "$HOME/mvm"

stop_on_fail=1
if [ "${1:-}" = "--continue" ]; then
  stop_on_fail=0
  shift
fi

run() {
  local label="$1"
  shift
  echo
  echo "==> $label"
  if "$@"; then
    echo "    ok"
  else
    local rc=$?
    echo "    FAIL ($rc)"
    [ "$stop_on_fail" = "1" ] && exit "$rc"
  fi
}

run "fmt"                cargo fmt --all -- --check
run "workspace clippy"   cargo clippy --workspace --all-targets -- -D warnings
run "workspace test"     cargo test --workspace --no-fail-fast
run "seccomp functional" cargo test -p mvm-guest --test seccomp_apply
run "cargo deny"         cargo deny check
run "cargo audit"        cargo audit --ignore RUSTSEC-2025-0057 \
                                      --ignore RUSTSEC-2024-0384 \
                                      --ignore RUSTSEC-2025-0119 \
                                      --ignore RUSTSEC-2023-0071 \
                                      --ignore RUSTSEC-2024-0370 \
                                      --ignore RUSTSEC-2026-0009

echo
echo "==> all checks complete"

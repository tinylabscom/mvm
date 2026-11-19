#!/usr/bin/env bash
#
# Tests for prune-targets.sh: it must delete only idle worktree targets, and
# only with --apply. The costly mistakes are deleting a build someone is
# running, deleting the shared guest target, and deleting on a dry run.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
SCRIPT="$PWD/scripts/prune-targets.sh"

tmp=$(cd "$(mktemp -d)" && pwd -P) # lsof reports real paths; /var is a symlink on macOS
cleanup() { [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT
failures=0

mkdir -p "$tmp/main/.git"
git init -q "$tmp/main"
W="$tmp/.worktrees"
for d in idle live fresh shared-guest-target; do mkdir -p "$W/$d/target/debug"; echo x > "$W/$d/target/debug/f"; done
mkdir -p "$W/idle/.mvm-test/target"; echo x > "$W/idle/.mvm-test/target/f"
mkdir -p "$tmp/main/target"; echo x > "$tmp/main/target/f"
# Age everything except "fresh" far past the idle window.
find "$W/idle" "$W/live" "$W/shared-guest-target" "$tmp/main/target" -exec touch -t 202001010000 {} +

(cd "$W/live" && exec sleep 60) & pid=$!
sleep 1

check() { # name, command...
    local name=$1; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; failures=$((failures + 1)); fi
}
run() { (cd "$tmp/main" && "$SCRIPT" --base "$tmp" "$@") 2>&1; }
has() { echo "$out" | grep -q "$1"; }
refuses_bad_hours() { local rc=0; run --hours abc > /dev/null || rc=$?; [ "$rc" -eq 2 ]; }

out=$(run)
check "dry run lists idle target" has 'would.*idle/target'
check "dry run deletes nothing" test -d "$W/idle/target"
check "live-process worktree kept" has 'keep  live-process.*live/target'
check "recent write kept" has 'keep  written<24h.*fresh/target'

run --apply > /dev/null
check "apply removes idle target" test ! -d "$W/idle/target"
check "apply removes idle .mvm-test target" test ! -d "$W/idle/.mvm-test/target"
check "apply keeps live target" test -d "$W/live/target"
check "apply keeps fresh target" test -d "$W/fresh/target"
check "apply keeps shared-guest-target" test -d "$W/shared-guest-target/target"
check "apply keeps main checkout target" test -d "$tmp/main/target"
check "bad --hours refused" refuses_bad_hours

[ "$failures" -eq 0 ] || { echo "$failures failed"; exit 1; }
echo "all passed"

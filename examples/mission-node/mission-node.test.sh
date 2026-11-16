#!/usr/bin/env bash
# Hermetic test of mission-node.sh: a fake client records its calls, so the
# script's sequence, recipients and tier are checked without a VM.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "$work/client" <<'S'
#!/bin/sh
echo "$*" >> "${CALLS:?}"
[ "${FAKE_REFUSES:-0}" = 1 ] && exit 1
exit 0
S
chmod +x "$work/client"
# The outbound attempt must not depend on the test host's network: a fake wget
# records the attempt and fails, as it does in a guest with no egress.
mkdir "$work/bin"
# shellcheck disable=SC2016
printf '#!/bin/sh\necho "wget $*" >> "${CALLS:?}"\nexit 1\n' > "$work/bin/wget"; chmod +x "$work/bin/wget"

# The script ends in an endless wait by design; stop it once it says it is done.
run() {
  PATH="$work/bin:$PATH" CALLS="$work/calls" MISSION_CLIENT="$work/client" MISSION_STEP_SECS=0 "$@" sh "$here/mission-node.sh" > "$work/out" 2>&1 &
  local pid=$! end=$((SECONDS + 10))
  until grep -q "waiting to be contained" "$work/out" 2>/dev/null; do
    [ "$SECONDS" -lt "$end" ] || { kill "$pid" 2>/dev/null; fail "the script never reached the end: $(cat "$work/out")"; }
    sleep 0.1
  done
  { pkill -P "$pid"; kill "$pid"; wait "$pid"; } 2>/dev/null || true
}

: > "$work/calls"; run env
expected=$'send --local aircraft-observation-1\nsend --local --to ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff exfiltrate-to-someone-else\nwget -T 4 -q -O- http://example.com\nsend --local left-unread-in-the-old-workload'
[ "$(cat "$work/calls")" = "$expected" ] || fail "unexpected calls: $(cat "$work/calls")"
grep -q "the outbound connection failed" "$work/out" || fail "the outbound attempt was not made: $(cat "$work/out")"

# A refused or failed send is reported and does not stop the schedule.
: > "$work/calls"; run env FAKE_REFUSES=1
[ "$(grep -c '^send' "$work/calls")" = 3 ] || fail "a refused send stopped the schedule: $(cat "$work/calls")"
grep -q "could not stage" "$work/out" || fail "a failed send was not reported"

# Production tier only: the legacy spool must never be used by this workload.
! grep -E '^send' "$work/calls" | grep -qv '^send --local'  || fail "a send did not use the local-durable tier"
echo "ok"

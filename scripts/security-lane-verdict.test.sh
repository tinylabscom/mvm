#!/usr/bin/env bash
#
# Tests for security-lane-verdict.sh.
#
# The regression these exist for is a false negative, so the cases that
# matter are the ones that must REPORT. A watcher that never reports is
# indistinguishable from a green tree, which is precisely how two timed-out
# mutation shards and one outright failure went unnoticed nightly.
#
# The job fixtures below are the real conclusions of the runs named in each
# case, taken from repos/tinylabscom/mvm/actions/runs/{id}/jobs.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
VERDICT=scripts/security-lane-verdict.sh

failures=0

# jobs <conclusion:count> ... -> a jobs payload with those conclusions
jobs() {
  local out=() concl n i
  for spec in "$@"; do
    concl="${spec%%:*}"
    n="${spec##*:}"
    for ((i = 0; i < n; i++)); do
      out+=("{\"name\":\"$concl-$i\",\"conclusion\":\"$concl\",\"html_url\":\"u\"}")
    done
  done
  printf '{"jobs":[%s]}' "$(
    IFS=,
    echo "${out[*]}"
  )"
}

# expect <reports|silent|skips> <description> <jobs-json>
expect() {
  local want="$1" desc="$2" payload="$3" out status got
  set +e
  out="$(printf '%s' "$payload" | "$VERDICT")"
  status=$?
  set -e

  if [ "$status" -eq 3 ]; then
    got=skips
  elif [ "$status" -ne 0 ]; then
    got="exit-$status"
  elif [ -n "$out" ]; then
    got=reports
  else
    got=silent
  fi

  if [ "$got" = "$want" ]; then
    echo "ok   — $desc"
  else
    echo "FAIL — $desc: expected $want, got $got"
    [ -n "$out" ] && echo "       output: $out"
    failures=$((failures + 1))
  fi
}

# The regression. Security run 32448509693 (nightly, 2026-08-21): the
# mvm-hostd 2of4 and 4of4 mutation shards were killed at timeout-minutes.
# Actions concluded the RUN cancelled because of them, and the old inline
# guard exited on that before ever looking at a job.
expect reports "a timed-out shard among successes is reported" \
  "$(jobs success:29 cancelled:2)"

# Same run family, 32429533885 (2026-08-20): a real failure rode along with
# the timed-out shard and was suppressed by the same guard.
expect reports "an outright failure is not masked by a cancelled sibling" \
  "$(jobs success:29 failure:1 cancelled:1)"

expect reports "a plain failure is reported" "$(jobs success:30 failure:1)"
expect reports "timed_out is reported where Actions does emit it" \
  "$(jobs success:30 timed_out:1)"

# The case the old guard was protecting, and the only one worth skipping:
# an operator cancelled the run, so no job reached a verdict. Blaming every
# lane for that would train the reader to ignore the issue.
expect skips "an operator cancelling the whole run yields no verdict" \
  "$(jobs cancelled:31)"

expect skips "a run that never started anything yields no verdict" '{"jobs":[]}'

# Green must stay green, or the tracking issue never closes.
expect silent "an all-green run reports nothing" "$(jobs success:31)"

# A skipped job is not a failure: several lanes are conditional.
expect silent "skipped jobs alongside successes are not failures" \
  "$(jobs success:20 skipped:11)"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed"
  exit 1
fi
echo "all cases passed"

#!/usr/bin/env bash
#
# Decide what a finished `Security` run has to say, from its per-job
# conclusions.
#
# Split out of security-lane-watch.yml so the decision can be tested. It
# was wrong for as long as it lived inline, and in a way no assertion on
# the workflow text would have caught: the two halves contradicted each
# other. The job selection deliberately counts `cancelled`, because Actions
# reports a job killed by its own `timeout-minutes` that way and a mutation
# shard that never finishes is exactly the red this lane exists to surface.
# But a guard above it exited early whenever the *run* concluded
# `cancelled` — and Actions concludes the run `cancelled` when any single
# job does. So the one case the selection was written for could never reach
# it. Security run 32429533885 (2026-08-20) carried 29 successes, one
# outright `failure` and one timed-out shard; the guard dropped all of it.
#
# Reads the jobs array (`repos/{}/actions/runs/{}/jobs`) on stdin. Prints
# the failing set as markdown list items, and exits:
#
#   0 — a verdict was collected. Empty stdout means every job was green.
#   3 — no verdict to collect: nothing ran to completion, which is what an
#       operator cancelling the whole run looks like. Reporting that set as
#       failing would blame every lane for a human's keystroke; reporting it
#       as green would close the tracking issue on evidence nobody gathered.
set -euo pipefail

jobs_json="$(cat)"

# A run that collected at least one real verdict is a run worth reading,
# whatever its aggregate conclusion says.
decided=$(printf '%s' "$jobs_json" |
  jq '[.jobs[] | select(.conclusion == "success" or .conclusion == "failure")] | length')

if [ "$decided" -eq 0 ]; then
  exit 3
fi

printf '%s' "$jobs_json" |
  jq -r '.jobs[]
         | select(.conclusion == "failure" or .conclusion == "timed_out"
                  or .conclusion == "cancelled")
         | "- \(.name) — [log](\(.html_url))"'

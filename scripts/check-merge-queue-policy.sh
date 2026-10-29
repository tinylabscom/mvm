#!/usr/bin/env bash
set -euo pipefail

policy=${1:?"usage: check-merge-queue-policy.sh <ruleset.json>"}

includes=$(jq -cer '.conditions.ref_name.include' "$policy")
excludes=$(jq -cer '.conditions.ref_name.exclude' "$policy")
rule_count=$(jq -er '[.rules[] | select(.type == "merge_queue")] | length' "$policy")
builds=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.max_entries_to_build' "$policy")
merge_max=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.max_entries_to_merge' "$policy")
wait=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.min_entries_to_merge_wait_minutes' "$policy")

grouping=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.grouping_strategy' "$policy")
merge_min=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.min_entries_to_merge' "$policy")

# Keep the ref conditions canonical rather than trying to interpret GitHub's
# ref-pattern language. An extra include or any exclusion can silently remove
# `main` from the supposedly protective ruleset.
#
# Exactly two queue shapes are admitted:
#
#   singleton  1 building, 1 per group, no wait. The shape the queue ran while
#              merge groups reused the pull request's proof.
#   batched    ALLGREEN, 3 building, 1-5 per group (minimum 1), no wait (a
#              5-minute wait is still admitted so the ruleset can move first
#              or last). Safe only because every pull request passed the fast
#              gate on its head; the queue re-runs only the compile and lint
#              lanes (Lint core, Build workspace tests) against the integrated
#              commit; the rest of ci.yml and the slow lanes in ci-main.yml
#              run after the merge, on a push to main.
#
# Both stay admitted so that switching the live ruleset and landing a workflow
# change can happen in either order without failing every queue run.
shape=
if [ "$builds" = 1 ] && [ "$merge_max" = 1 ] && [ "$wait" = 0 ]; then
  shape=singleton
elif [ "$grouping" = ALLGREEN ] && [ "$builds" = 3 ] && [ "$merge_max" = 5 ] \
  && [ "$merge_min" = 1 ] && { [ "$wait" = 0 ] || [ "$wait" = 5 ]; }; then
  shape=batched
fi
if [ "$includes" != '["~DEFAULT_BRANCH"]' ] || [ "$excludes" != '[]' ] \
  || [ "$rule_count" != 1 ] || [ -z "$shape" ]; then
  echo "::error::Merge queue policy drifted: include=$includes exclude=$excludes merge_rules=$rule_count grouping=$grouping max_entries_to_build=$builds max_entries_to_merge=$merge_max min_entries_to_merge=$merge_min wait_minutes=$wait."
  echo "::error::Required: include=[\"~DEFAULT_BRANCH\"], exclude=[], merge_rules=1, and either singleton (build 1, merge 1, wait 0) or batched (ALLGREEN, build 3, merge 5, min 1, wait 0 or 5)."
  exit 1
fi

echo "Merge queue policy is the $shape shape."

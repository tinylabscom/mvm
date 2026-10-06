#!/usr/bin/env bash
set -euo pipefail

policy=${1:?"usage: check-merge-queue-policy.sh <ruleset.json>"}

includes=$(jq -cer '.conditions.ref_name.include' "$policy")
excludes=$(jq -cer '.conditions.ref_name.exclude' "$policy")
rule_count=$(jq -er '[.rules[] | select(.type == "merge_queue")] | length' "$policy")
builds=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.max_entries_to_build' "$policy")
merge_max=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.max_entries_to_merge' "$policy")
wait=$(jq -er '.rules[] | select(.type == "merge_queue") | .parameters.min_entries_to_merge_wait_minutes' "$policy")

# Keep this canonical rather than trying to interpret GitHub's ref-pattern
# language. An extra include or any exclusion can silently remove `main` from
# the supposedly protective ruleset.
if [ "$includes" != '["~DEFAULT_BRANCH"]' ] || [ "$excludes" != '[]' ] \
  || [ "$rule_count" != 1 ] || [ "$builds" != 1 ] \
  || [ "$merge_max" != 1 ] || [ "$wait" != 0 ]; then
  echo "::error::Merge queue policy drifted: include=$includes exclude=$excludes merge_rules=$rule_count max_entries_to_build=$builds max_entries_to_merge=$merge_max wait_minutes=$wait."
  echo "::error::Required: include=[\"~DEFAULT_BRANCH\"], exclude=[], merge_rules=1, queue=1/1/0."
  exit 1
fi

echo "Merge queue policy matches the hosted-runner budget."

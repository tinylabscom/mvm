#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
check="$repo_root/scripts/check-merge-queue-policy.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/good.json" <<'JSON'
{
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [{
    "type": "merge_queue",
    "parameters": {
      "grouping_strategy": "HEADGREEN",
      "max_entries_to_build": 1,
      "max_entries_to_merge": 1,
      "min_entries_to_merge": 1,
      "min_entries_to_merge_wait_minutes": 0
    }
  }]
}
JSON

bash "$check" "$tmp/good.json"

expect_refusal() {
  local name=$1
  local filter=$2
  jq "$filter" "$tmp/good.json" >"$tmp/$name.json"
  if bash "$check" "$tmp/$name.json" >/dev/null 2>&1; then
    echo "expected policy refusal for $name" >&2
    exit 1
  fi
}

expect_acceptance() {
  local name=$1
  local filter=$2
  jq "$filter" "$tmp/good.json" >"$tmp/$name.json"
  if ! bash "$check" "$tmp/$name.json" >/dev/null 2>&1; then
    echo "expected policy acceptance for $name" >&2
    exit 1
  fi
}

BATCHED='(.rules[] | select(.type == "merge_queue") | .parameters) |= (.grouping_strategy = "ALLGREEN" | .max_entries_to_build = 3 | .max_entries_to_merge = 5 | .min_entries_to_merge = 1 | .min_entries_to_merge_wait_minutes = 5)'
expect_acceptance batched "$BATCHED"
expect_acceptance batched-no-wait "$BATCHED"' | (.rules[] | select(.type == "merge_queue") | .parameters).min_entries_to_merge_wait_minutes = 0'

expect_refusal excluded-main '.conditions.ref_name.exclude = ["refs/heads/main"]'
expect_refusal excluded-by-glob '.conditions.ref_name.exclude = ["refs/heads/*"]'
expect_refusal extra-include '.conditions.ref_name.include += ["refs/heads/release"]'
# Singleton neighbours: widening one knob without the rest is neither shape.
expect_refusal two-builds '(.rules[] | select(.type == "merge_queue") | .parameters).max_entries_to_build = 2'
expect_refusal batched-merge-unbatched-build '(.rules[] | select(.type == "merge_queue") | .parameters).max_entries_to_merge = 5'
expect_refusal delayed-singleton '(.rules[] | select(.type == "merge_queue") | .parameters).min_entries_to_merge_wait_minutes = 5'
# Batched neighbours: every knob of the batched shape is load-bearing.
expect_refusal batched-headgreen "$BATCHED"' | (.rules[] | select(.type == "merge_queue") | .parameters).grouping_strategy = "HEADGREEN"'
expect_refusal batched-four-builds "$BATCHED"' | (.rules[] | select(.type == "merge_queue") | .parameters).max_entries_to_build = 4'
expect_refusal batched-six-per-group "$BATCHED"' | (.rules[] | select(.type == "merge_queue") | .parameters).max_entries_to_merge = 6'
expect_refusal batched-min-two "$BATCHED"' | (.rules[] | select(.type == "merge_queue") | .parameters).min_entries_to_merge = 2'
expect_refusal batched-long-wait "$BATCHED"' | (.rules[] | select(.type == "merge_queue") | .parameters).min_entries_to_merge_wait_minutes = 10'
expect_refusal batched-excluded-main "$BATCHED"' | .conditions.ref_name.exclude = ["refs/heads/main"]'
expect_refusal duplicate-rule '.rules += [.rules[0]]'

echo "merge queue policy guard tests passed"

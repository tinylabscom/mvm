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
      "max_entries_to_build": 1,
      "max_entries_to_merge": 1,
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

expect_refusal excluded-main '.conditions.ref_name.exclude = ["refs/heads/main"]'
expect_refusal excluded-by-glob '.conditions.ref_name.exclude = ["refs/heads/*"]'
expect_refusal extra-include '.conditions.ref_name.include += ["refs/heads/release"]'
expect_refusal two-builds '(.rules[] | select(.type == "merge_queue") | .parameters.max_entries_to_build) = 2'
expect_refusal batched-merge '(.rules[] | select(.type == "merge_queue") | .parameters.max_entries_to_merge) = 5'
expect_refusal delayed-merge '(.rules[] | select(.type == "merge_queue") | .parameters.min_entries_to_merge_wait_minutes) = 5'
expect_refusal duplicate-rule '.rules += [.rules[0]]'

echo "merge queue policy guard tests passed"

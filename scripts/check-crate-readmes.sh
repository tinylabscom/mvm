#!/usr/bin/env bash
set -euo pipefail

workspace_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
minimum_lines=20
failures=0
manifest_count=0

if ! command -v rg >/dev/null 2>&1; then
  echo "check-crate-readmes: ripgrep (rg) is required" >&2
  exit 1
fi

while IFS= read -r manifest; do
  [[ -n "$manifest" ]] || continue
  manifest_count=$((manifest_count + 1))

  if [[ "$manifest" == "Cargo.toml" ]]; then
    readme="README.md"
  else
    readme="${manifest%/Cargo.toml}/README.md"
  fi

  if [[ ! -f "$workspace_root/$readme" ]]; then
    echo "missing README: $manifest requires $readme" >&2
    failures=$((failures + 1))
    continue
  fi

  line_count=$(wc -l < "$workspace_root/$readme" | tr -d ' ')
  if ((line_count < minimum_lines)); then
    echo "README is not detailed: $readme has $line_count lines; minimum is $minimum_lines" >&2
    failures=$((failures + 1))
  fi
done < <(
  cd "$workspace_root"
  rg --files \
    --glob 'Cargo.toml' \
    --glob '!target/**' \
    --glob '!.mvm-test/**' \
    | sort
)

if ((manifest_count == 0)); then
  echo "check-crate-readmes: no Cargo.toml files found under $workspace_root" >&2
  exit 1
fi

if ((failures > 0)); then
  echo "check-crate-readmes: $failures documentation failure(s) across $manifest_count crates" >&2
  exit 1
fi

echo "check-crate-readmes: all $manifest_count Cargo crates have detailed adjacent READMEs"

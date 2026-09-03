#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-crate-readmes.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p "$fixture_root/crates/complete" "$fixture_root/crates/missing"
printf '[workspace]\n' > "$fixture_root/Cargo.toml"
printf '[package]\nname = "complete"\nversion = "0.0.0"\n' \
  > "$fixture_root/crates/complete/Cargo.toml"
printf '[package]\nname = "missing"\nversion = "0.0.0"\n' \
  > "$fixture_root/crates/missing/Cargo.toml"

write_detailed_readme() {
  local path="$1"
  : > "$path"
  for line in {1..20}; do
    printf 'documentation line %s\n' "$line" >> "$path"
  done
}

write_detailed_readme "$fixture_root/README.md"
write_detailed_readme "$fixture_root/crates/complete/README.md"

if bash "$checker" "$fixture_root" >/dev/null 2>&1; then
  echo "expected a missing crate README to fail the check" >&2
  exit 1
fi

printf 'too short\n' > "$fixture_root/crates/missing/README.md"
if bash "$checker" "$fixture_root" >/dev/null 2>&1; then
  echo "expected a short crate README to fail the detail check" >&2
  exit 1
fi

write_detailed_readme "$fixture_root/crates/missing/README.md"
bash "$checker" "$fixture_root" >/dev/null

echo "check-crate-readmes self-test passed"

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p \
  "$fixture/crates/generated/node_modules/dependency" \
  "$fixture/nix" \
  "$fixture/scripts" \
  "$fixture/public" \
  "$fixture/examples"

printf '%s\n' 'git+ssh://generated-dependency' \
  > "$fixture/crates/generated/node_modules/dependency/metadata.txt"

MVM_NO_SSH_ROOT="$fixture" "$repo_root/scripts/check-no-ssh.sh"

printf '%s\n' 'launch sshd' > "$fixture/crates/guest.rs"
if MVM_NO_SSH_ROOT="$fixture" "$repo_root/scripts/check-no-ssh.sh" \
  > "$fixture/stdout" 2> "$fixture/stderr"; then
  echo "expected a tracked-source-shaped SSH token to be rejected" >&2
  exit 1
fi

grep -q 'crates/guest.rs:1:launch sshd' "$fixture/stderr"
echo "ok: generated dependencies are ignored and source SSH tokens are rejected"

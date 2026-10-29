#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/repo/nix"
printf '{}\n' >"$tmp/repo/nix/flake.nix"
export HOOK_TEST_ROOT="$tmp/repo" HOOK_NIX_CALLED="$tmp/nix-called"

# Exercise a staged Nix-only change without modifying a real Git index.
cat >"$tmp/bin/git" <<'SH'
#!/bin/sh
case "$*" in
  'diff --cached --quiet') exit 1 ;;
  'diff --cached --name-only --diff-filter=ACMR')
    printf 'nix/flake.nix\n' ;;
  'diff --cached --name-only --diff-filter=ACM')
    printf 'nix/flake.nix\n' ;;
  'rev-parse --show-toplevel') printf '%s\n' "$HOOK_TEST_ROOT" ;;
  *) printf 'unexpected git invocation: %s\n' "$*" >&2; exit 1 ;;
esac
SH
cat >"$tmp/bin/nix" <<'SH'
#!/bin/sh
printf 'called\n' >>"$HOOK_NIX_CALLED"
exit 1
SH
chmod +x "$tmp/bin/git" "$tmp/bin/nix"
ln -s "$(command -v grep)" "$tmp/bin/grep"

(
  cd "$tmp/repo"
  PATH="$tmp/bin" /bin/bash "$repo_root/.githooks/pre-commit"
)
if [ -e "$HOOK_NIX_CALLED" ]; then
  echo 'pre-commit invoked host Nix for a staged Nix file' >&2
  exit 1
fi

# The same staged change must also work with no Nix executable installed.
rm "$tmp/bin/nix"
(
  cd "$tmp/repo"
  PATH="$tmp/bin" /bin/bash "$repo_root/.githooks/pre-commit"
)
echo 'pre-commit: staged Nix files work with and without host Nix'

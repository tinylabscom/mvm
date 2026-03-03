#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify-release-version.sh --version X.Y.Z [--changelog PATH]

Validates release version consistency:
1) CHANGELOG contains section: ## [X.Y.Z] - YYYY-MM-DD
2) All Cargo.toml package versions match X.Y.Z

Options:
  --version X.Y.Z   Target release version (required)
  --changelog PATH  Changelog file (default: CHANGELOG.md)
  --help            Show this help text
USAGE
}

version=""
changelog="CHANGELOG.md"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --changelog)
      changelog="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$version" ]]; then
  echo "--version is required" >&2
  exit 1
fi

if [[ ! -f "$changelog" ]]; then
  echo "Changelog not found: $changelog" >&2
  exit 1
fi

if ! grep -Eq "^## \\[$version\\] [—-] [0-9]{4}-[0-9]{2}-[0-9]{2}$" "$changelog"; then
  echo "Missing changelog release section for version $version in $changelog" >&2
  echo "Expected format: ## [$version] — YYYY-MM-DD" >&2
  exit 1
fi

failures=0

# Check workspace-level version in root Cargo.toml
workspace_version="$(
  awk '
    /^\[workspace\.package\]/ {in_ws=1; next}
    /^\[/ && in_ws {in_ws=0}
    in_ws && $1=="version" && $2=="=" {
      gsub(/"/, "", $3);
      print $3;
      exit
    }
  ' Cargo.toml
)"
if [[ -n "$workspace_version" && "$workspace_version" != "$version" ]]; then
  echo "Version mismatch: Cargo.toml [workspace.package] has $workspace_version (expected $version)" >&2
  failures=1
fi

# Check each crate's version (skip crates using version.workspace = true)
while IFS= read -r cargo_toml; do
  pkg_version="$(
    awk '
      /^\[package\]/ {in_pkg=1; next}
      /^\[/ && in_pkg {in_pkg=0}
      in_pkg && /version\.workspace/ { print "workspace"; exit }
      in_pkg && $1=="version" && $2=="=" {
        gsub(/"/, "", $3);
        print $3;
        exit
      }
    ' "$cargo_toml"
  )"

  # Crates using version.workspace = true inherit from [workspace.package]
  if [[ "$pkg_version" == "workspace" ]]; then
    continue
  fi

  if [[ -n "$pkg_version" && "$pkg_version" != "$version" ]]; then
    echo "Version mismatch: $cargo_toml has $pkg_version (expected $version)" >&2
    failures=1
  fi
done < <(rg --files -g 'Cargo.toml')

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi

echo "PASS: changelog + Cargo package versions validated for $version"

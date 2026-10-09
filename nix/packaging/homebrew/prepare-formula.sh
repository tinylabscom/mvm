#!/bin/bash
# Authenticate a promoted stable release before rendering a tap candidate.
set -euo pipefail
[[ $# == 2 ]] || { echo "usage: prepare-formula.sh TAG OUTPUT_DIRECTORY" >&2; exit 1; }
tag="$1"
out="$2"
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  { echo "expected a stable CLI tag" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
repository=tinylabscom/mvm
gh api "repos/$repository/releases/tags/$tag" |
  jq -e --arg tag "$tag" \
    '.tag_name == $tag and .draft == false and .prerelease == false and (.published_at != null)' >/dev/null
mkdir -p "$out"
gh release download "$tag" --repo "$repository" \
  --pattern checksums-sha256.txt --pattern checksums-sha256.txt.bundle --dir "$out"
cosign verify-blob --bundle "$out/checksums-sha256.txt.bundle" \
  --certificate-identity "https://github.com/$repository/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$out/checksums-sha256.txt"
sh "$here/render-formula.sh" "${tag#v}" "$out/checksums-sha256.txt" "$out/mvmctl.rb"

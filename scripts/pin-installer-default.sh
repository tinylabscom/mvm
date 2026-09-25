#!/bin/sh
# Pin install.sh's offline fallback — DEFAULT_VERSION, and the archive hash per
# target that lets a fresh host trust that release before it has any verifier —
# to a promoted CLI release.
#
#   pin-installer-default.sh [--check] <tag | --newest> [installer]
#
# The installer normally installs the newest promoted release it finds through
# the releases API; the pin is what it installs when that API cannot be
# reached. So the pin must name a release a new user can actually run: a full
# release, never a prerelease. The release workflow publishes every tag as a
# prerelease and promotes a stable one only after a fresh install of it has
# booted a microVM, so "not a prerelease" is that evidence.
#
# The hashes come from the release's checksum manifest, and only after the
# manifest's signature verifies under the release workflow's identity for that
# exact tag: they become a trust anchor for every fresh install, so they are
# never copied from anything unauthenticated.
#
#   --newest   pin the newest promoted CLI release publishing every target
#   --check    change nothing; exit 1 unless the installer already carries
#              exactly this pin
#
# The only writer of those lines: the release PR (`just release`) and the
# site deployment both call this. Needs an authenticated `gh` and `cosign`.
set -eu

usage() {
  sed -n '6p' "$0" | sed 's/^# *//' >&2
  exit 2
}

CHECK=0
if [ "${1:-}" = "--check" ]; then
  CHECK=1
  shift
fi
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
REQUESTED="$1"
INSTALLER="${2:-$(cd "$(dirname "$0")/.." && pwd -P)/install.sh}"

die() { printf 'pin-installer-default: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

[ -f "$INSTALLER" ] || die "no installer at $INSTALLER"
need gh
need cosign

# The installer downloads from the repository it names, so that is where the
# pin must come from — not from whichever repository this runs in.
REPO="$(sed -n 's/^REPO="\(.*\)"$/\1/p' "$INSTALLER")"
[ -n "$REPO" ] || die "$INSTALLER names no REPO"

# Target triple and the installer variable carrying its archive hash.
TARGETS="aarch64-apple-darwin:DEFAULT_ARCHIVE_SHA256_AARCH64_APPLE_DARWIN
x86_64-unknown-linux-gnu:DEFAULT_ARCHIVE_SHA256_X86_64_UNKNOWN_LINUX_GNU
aarch64-unknown-linux-gnu:DEFAULT_ARCHIVE_SHA256_AARCH64_UNKNOWN_LINUX_GNU"

if [ "$REQUESTED" = "--newest" ]; then
  # `gh --jq` rather than a separate jq: one fewer tool on a maintainer's host.
  # shellcheck disable=SC2016 # a jq program, not shell
  TAG="$(gh api "repos/$REPO/releases?per_page=100" --jq '
    [ .[]
      | select(.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))
      | select((.draft | not) and (.prerelease | not))
      | select([.assets[].name] as $names
          | all("aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu";
                ("mvmctl-" + . + ".tar.gz") as $archive | any($names[]; . == $archive)))
      | .tag_name ]
    | sort_by(ltrimstr("v") | split(".") | map(tonumber))
    | last // empty')" || die "could not list the releases of $REPO"
  [ -n "$TAG" ] || die "$REPO has no promoted CLI release publishing every target"
else
  TAG="$REQUESTED"
fi

printf '%s\n' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' \
  || die "the installer default must be a stable vMAJOR.MINOR.PATCH tag, got: $TAG"

state="$(gh release view "$TAG" --repo "$REPO" --json isDraft,isPrerelease \
  --jq 'if .isDraft then "draft" elif .isPrerelease then "prerelease" else "promoted" end')" \
  || die "$REPO has no release $TAG"
[ "$state" = "promoted" ] \
  || die "$TAG is still a $state: only a release the workflow promoted after its first-run smoke may be the installer default"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
gh release download "$TAG" --repo "$REPO" --pattern 'checksums-sha256.txt*' --dir "$work" \
  || die "could not download the checksum manifest of $TAG"
[ -f "$work/checksums-sha256.txt" ] || die "$TAG publishes no checksums-sha256.txt"
[ -f "$work/checksums-sha256.txt.bundle" ] \
  || die "$TAG publishes no signature for its checksum manifest, so its archive hashes cannot be authenticated"
cosign verify-blob \
  --bundle "$work/checksums-sha256.txt.bundle" \
  --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$work/checksums-sha256.txt" >/dev/null 2>&1 \
  || die "the checksum manifest of $TAG is not signed by its release workflow"

# The pin as the installer should carry it, one assignment per line.
{
  printf 'DEFAULT_VERSION="%s"\n' "$TAG"
  printf '%s\n' "$TARGETS" | while IFS=: read -r target variable; do
    digest="$(awk -v archive="mvmctl-$target.tar.gz" '$2 == archive { print $1 }' "$work/checksums-sha256.txt")"
    printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' \
      || die "$TAG has no valid SHA-256 for mvmctl-$target.tar.gz"
    printf '%s="%s"\n' "$variable" "$digest"
  done
} > "$work/pin"
[ "$(wc -l < "$work/pin")" -eq 4 ] || die "could not read a hash for every target of $TAG"

while IFS= read -r line; do
  name="${line%%=*}"
  current="$(grep -E "^$name=\"[^\"]*\"$" "$INSTALLER" || true)"
  [ -n "$current" ] || die "$INSTALLER has no $name line to pin"
  if [ "$CHECK" = 1 ]; then
    [ "$current" = "$line" ] || die "$INSTALLER carries $current, expected $line"
  else
    sed -e "s|^$name=\"[^\"]*\"$|$line|" "$INSTALLER" > "$work/installer"
    cat "$work/installer" > "$INSTALLER"
    grep -qxF "$line" "$INSTALLER" || die "could not write $line into $INSTALLER"
  fi
done < "$work/pin"

if [ "$CHECK" = 1 ]; then
  printf 'ok   %s pins %s, a promoted release, with its signed archive hashes\n' "$INSTALLER" "$TAG"
else
  printf 'pinned %s to %s\n' "$INSTALLER" "$TAG"
fi

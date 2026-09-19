#!/bin/sh
# Resolve which published releases the installer compat lanes run against.
#
#   matrix.sh compat  <installer> <count> <runner>:<target>...
#   matrix.sh upgrade <installer> <count> <runner>:<target>...
#   matrix.sh latest  <target>...
#
# Reads the GitHub releases API response on stdin — one array, or several
# concatenated as `gh api --paginate` prints them — and prints JSON for a job
# matrix. The list is never kept by hand: a release counts when its tag starts
# with `v`, it is not a draft, and it publishes both `checksums-sha256.txt` and
# the `mvmctl-<target>.tar.gz` archive install.sh downloads. That leaves out the
# `boot-image/*` tags, the early `mvm-*`-named archives, and the tags that
# carry no assets at all.
#
# compat   the newest <count> releases per platform, one matrix entry each.
#          `strict` is true for the installer's own baked default release and
#          anything published after it: the one-liner installs that release,
#          so it must install. An older release may be refused, but only for a
#          reason its own archive explains (see lib.sh).
# upgrade  one entry per platform whose `releases` walks those same releases
#          oldest to newest, and whose `tolerated` names the non-strict ones.
# latest   a JSON array: the newest full release carrying every named target,
#          plus the newest prerelease when it is newer still — what users get
#          today, and what they are about to get.
set -eu

usage() {
  sed -n '3,6p' "$0" >&2
  exit 2
}

[ "$#" -ge 1 ] || usage
mode="$1"
shift

releases="$(jq -s 'add // []')"

# Releases carrying the archive for $1, newest first.
candidates() {
  printf '%s' "$releases" | jq -c --arg target "$1" '
    [ .[]
      | select((.tag_name | startswith("v")) and (.draft | not))
      | select(any(.assets[]?; .name == "checksums-sha256.txt"))
      | select(any(.assets[]?; .name == ("mvmctl-" + $target + ".tar.gz")))
      | {tag: .tag_name, published: .published_at, prerelease: .prerelease} ]
    | sort_by(.published, .tag) | reverse'
}

baked_default() {
  default="$(sed -n 's/^DEFAULT_VERSION="\(.*\)"$/\1/p' "$1")"
  [ -n "$default" ] || { echo "$1 has no DEFAULT_VERSION" >&2; exit 1; }
  printf '%s' "$default"
}

# The newest <count> candidates for a platform, each marked strict or not.
platform_releases() {
  platform_default="$1"
  platform_count="$2"
  platform_target="$3"
  list="$(candidates "$platform_target")"
  if [ "$(printf '%s' "$list" | jq --arg d "$platform_default" 'any(.[]; .tag == $d)')" != "true" ]; then
    echo "warning: baked default $platform_default publishes no mvmctl-$platform_target.tar.gz; treating every release as strict" >&2
  fi
  printf '%s' "$list" | jq -c --arg d "$platform_default" --argjson n "$platform_count" '
    (map(.tag) | index($d)) as $at
    | [ to_entries[]
        | select(.key < $n)
        | {release: .value.tag, strict: ($at == null or .key <= $at)} ]'
}

split_platform() {
  case "$1" in
    *:*) RUNNER="${1%%:*}"; TARGET="${1#*:}" ;;
    *) echo "platform must be <runner>:<target>, got: $1" >&2; exit 2 ;;
  esac
}

case "$mode" in
  compat|upgrade)
    [ "$#" -ge 3 ] || usage
    installer="$1"
    count="$2"
    shift 2
    case "$count" in ''|*[!0-9]*|0) echo "count must be a positive whole number, got: $count" >&2; exit 2 ;; esac
    default="$(baked_default "$installer")"
    include="[]"
    for platform in "$@"; do
      split_platform "$platform"
      picked="$(platform_releases "$default" "$count" "$TARGET")"
      if [ "$(printf '%s' "$picked" | jq length)" -eq 0 ]; then
        echo "no published release carries mvmctl-$TARGET.tar.gz" >&2
        exit 1
      fi
      if [ "$mode" = "compat" ]; then
        include="$(printf '%s' "$include" | jq -c --argjson picked "$picked" \
          --arg runner "$RUNNER" --arg target "$TARGET" \
          '. + [ $picked[] | {runner: $runner, target: $target, release, strict} ]')"
      else
        include="$(printf '%s' "$include" | jq -c --argjson picked "$picked" \
          --arg runner "$RUNNER" --arg target "$TARGET" \
          '. + [ { runner: $runner, target: $target,
                   releases: ($picked | reverse | map(.release) | join(" ")),
                   tolerated: ($picked | map(select(.strict | not) | .release) | join(" ")) } ]')"
      fi
    done
    printf '%s' "$include" | jq -c '{include: .}'
    ;;
  latest)
    [ "$#" -ge 1 ] || usage
    common=""
    for target in "$@"; do
      tags="$(candidates "$target")"
      if [ -z "$common" ]; then
        common="$tags"
      else
        common="$(printf '%s' "$common" | jq -c --argjson other "$tags" \
          '[ .[] | select(.tag as $t | any($other[]; .tag == $t)) ]')"
      fi
    done
    printf '%s' "$common" | jq -c '
      (map(select(.prerelease | not)) | first) as $stable
      | (first) as $newest
      | [ $stable, (if $newest != null and $newest.prerelease then $newest else null end) ]
      | map(select(. != null) | .tag)
      | if length == 0 then error("no published release carries every target") else . end'
    ;;
  *) usage ;;
esac

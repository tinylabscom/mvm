#!/usr/bin/env bash
# Delete idle cargo target dirs across every worktree of this repo.
#
# Each worktree builds its own full target/ (and .mvm-test/target for the
# test lane), tens to hundreds of GiB apiece, and nothing removes them when
# the worktree is finished. This reclaims them. Dry run unless --apply.
#
#   --apply      delete (default: list what would go)
#   --hours N    a target is idle when nothing in it changed for N hours (24)
#   --base DIR   directory holding the checkout and its sibling .worktrees/
#                (default: the parent of the main checkout)
#
# Kept: a target whose worktree has a process with it as cwd (a build or an
# agent session), one written to inside the idle window, shared-guest-target
# (other builds point at it), and the main checkout's own target/.
# bash 3.2 safe (macOS).
set -euo pipefail

hours=24 apply=0 base=""
while [ $# -gt 0 ]; do
    case "$1" in
        --apply) apply=1 ;;
        --hours) hours=${2:?--hours needs a number}; shift ;;
        --base) base=${2:?--base needs a directory}; shift ;;
        -h | --help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
case "$hours" in '' | *[!0-9]*) echo "--hours must be a whole number" >&2; exit 2 ;; esac

if [ -z "$base" ]; then
    common=$(git rev-parse --path-format=absolute --git-common-dir)
    main=$(dirname "$common")
    base=$(dirname "$main")
else
    main="$base/$(basename "$(git rev-parse --path-format=absolute --git-common-dir | xargs dirname)")"
fi
[ -d "$base" ] || { echo "no such directory: $base" >&2; exit 2; }

wt_re='^(.*/(\.worktrees|worktrees)/[^/]+)(/.*)?$'
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Worktree roots that some process has as its cwd.
lsof -d cwd -Fn 2>/dev/null | grep '^n' | cut -c2- | grep -E '/(\.worktrees|worktrees)/' \
    | sed -E "s#$wt_re#\1#" | sort -u > "$tmp/live" || true

: > "$tmp/cands"
for dir in "$base/.worktrees" "$main/.worktrees" "$main/.delta/worktrees" "$main/.claude/worktrees"; do
    [ -d "$dir" ] || continue
    find "$dir" -maxdepth 4 -type d -name target -prune 2>/dev/null >> "$tmp/cands" || true
done
grep -E '/(\.mvm-test/)?target$' "$tmp/cands" | grep -v 'shared-guest-target' | sort -u > "$tmp/list" || true

total=0 n=0
while IFS= read -r t; do
    root=$(echo "$t" | sed -E "s#$wt_re#\1#")
    if grep -qxF "$root" "$tmp/live"; then echo "keep  live-process  $t"; continue; fi
    if [ -n "$(find "$t" -maxdepth 3 -mmin "-$((hours * 60))" -print -quit 2>/dev/null)" ]; then
        echo "keep  written<${hours}h  $t"; continue
    fi
    kb=$(du -sk "$t" 2>/dev/null | cut -f1)
    total=$((total + ${kb:-0})); n=$((n + 1))
    if [ "$apply" -eq 1 ]; then
        rm -rf "$t" && echo "gone  $((${kb:-0} / 1048576))G  $t"
    else
        echo "would $((${kb:-0} / 1048576))G  $t"
    fi
done < "$tmp/list"

verb="would free"; [ "$apply" -eq 1 ] && verb=freed
echo "$n dirs, $verb $((total / 1048576)) GiB"

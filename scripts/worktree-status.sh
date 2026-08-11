#!/usr/bin/env bash
#
# Classify this repo's git worktrees by whether they are still needed.
#
# Two problems this exists for, both of which cost real time on 2026-08-09:
#
#   1. Finished work is invisible. Ninety-five worktrees had accumulated, most
#      of them behind merged PRs, holding roughly a terabyte of build output and
#      dev state. Nothing said which were done.
#   2. In-flight work is invisible. `git worktree list` shows only paths, so a
#      branch someone else already has open reads the same as a free one — which
#      is how the same fix gets written twice.
#
# Verdicts:
#   SAFE    the PR merged and this worktree's tip is exactly the merged head,
#           with a clean tree — nothing here that is not already on main.
#   REVIEW  commits that never landed, or a closed-unmerged PR. A human call.
#   KEEP    an open PR, or uncommitted work.
#
# Never deletes anything. Pipe `--safe-only` into your own removal step once you
# have read the list.
#
# Usage:
#   scripts/worktree-status.sh              # full table
#   scripts/worktree-status.sh --safe-only  # bare paths, for scripting
set -euo pipefail

safe_only=0
[ "${1:-}" = "--safe-only" ] && safe_only=1

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
main_ref="origin/main"

git fetch --quiet origin main 2>/dev/null || true

prs=""
if command -v gh >/dev/null 2>&1; then
    # One call, then matched locally: a call per worktree is slow and rate-limited.
    prs=$(gh pr list --state all --limit 400 \
        --json number,headRefName,state,headRefOid \
        --jq '.[] | "\(.headRefName)\t\(.number)\t\(.state)\t\(.headRefOid)"' 2>/dev/null || true)
fi

# Snapshot the process list ONCE, up front. Grepping `ps` per worktree inside
# the loop looks equivalent and is not: the grep's own argv contains the path it
# is searching for, so every worktree matches itself and everything looks busy.
#
# The match is deliberately coarse: any process whose command line *mentions* a
# worktree path counts as using it, including a shell that merely names it in an
# argument. That over-protects — such a worktree reports KEEP and is never
# offered for removal — which is the right direction for a check whose wrong
# answer should be "left it alone". It does mean a path you just typed
# somewhere can read as busy until that process exits.
ps_snapshot=$(ps -eo command 2>/dev/null || true)

[ "$safe_only" -eq 1 ] || printf '%-40s %-34s %-14s %s\n' WORKTREE BRANCH PR VERDICT

git worktree list --porcelain | awk '
    /^worktree /{p=substr($0,10)}
    /^HEAD /{h=substr($0,6)}
    /^branch /{b=substr($0,8); sub(/^refs\/heads\//,"",b); print p"\t"h"\t"b; b=""}
    /^detached/{print p"\t"h"\t-"}
' | while IFS=$'\t' read -r path head branch; do
    [ "$path" = "$repo_root" ] && continue
    [ -d "$path" ] || continue

    dirty=$(git -C "$path" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
    ahead=$(git -C "$path" rev-list --count "${main_ref}..${head}" 2>/dev/null || echo 0)

    pr_num=""; pr_state=""; pr_head=""
    if [ -n "$prs" ] && [ "$branch" != "-" ]; then
        line=$(printf '%s\n' "$prs" | awk -F'\t' -v b="$branch" '$1==b{print; exit}')
        if [ -n "$line" ]; then
            pr_num=$(printf '%s' "$line" | cut -f2)
            pr_state=$(printf '%s' "$line" | cut -f3)
            pr_head=$(printf '%s' "$line" | cut -f4)
        fi
    fi

    in_use=0
    case "$ps_snapshot" in *"$path"*) in_use=1 ;; esac

    if [ "$in_use" -eq 1 ]; then
        # A fresh worktree has no commits of its own yet, which otherwise reads
        # as "nothing here that isn't on main" — exactly the shape of one
        # somebody just created and is about to work in.
        verdict="KEEP (a process is running in it)"
    elif [ "$dirty" -ne 0 ]; then
        verdict="KEEP (uncommitted: $dirty)"
    elif [ "$ahead" -eq 0 ]; then
        verdict="SAFE (nothing not already on main)"
    elif [ "$pr_state" = MERGED ] && [ "$pr_head" = "$head" ]; then
        verdict="SAFE (PR merged, tip matches merged head)"
    elif [ "$pr_state" = MERGED ]; then
        verdict="REVIEW (merged, but $ahead commit(s) not on main)"
    elif [ "$pr_state" = OPEN ]; then
        verdict="KEEP (open PR)"
    elif [ "$pr_state" = CLOSED ]; then
        verdict="REVIEW (closed unmerged; $ahead commit(s))"
    else
        verdict="REVIEW (no PR; $ahead commit(s) not on main)"
    fi

    if [ "$safe_only" -eq 1 ]; then
        case "$verdict" in SAFE*) printf '%s\n' "$path" ;; esac
    else
        pr_label="-"
        [ -n "$pr_num" ] && pr_label="#${pr_num} ${pr_state}"
        printf '%-40s %-34s %-14s %s\n' \
            "$(basename "$path")" "${branch:0:34}" "$pr_label" "$verdict"
    fi
done

if [ "$safe_only" -eq 0 ] && [ -z "$prs" ]; then
    echo
    echo "note: gh unavailable, so PR state is unknown and nothing can be called SAFE" >&2
fi

---
title: "How to land and clean up a PR from a worktree agent here: the queue refuses a merge-strategy flag, and agent worktrees stay locked"
author: Ari
date: 2026-11-17
branch: main
cost: { minutes: 153, tokens: 144274 }
id: l-7dd4a549
scope: repo
status: active
src: agent
touches:
  - ".github/workflows/release.yml"
---

## Decided

PRs here merge through the merge queue, so the merge strategy is not the caller's to choose. Enabling auto-merge works with the plain flag; the queue then consumes the request.

In the code: `gh pr merge <n> --auto --squash` is refused with 'merge strategy is set by the merge queue'; `gh pr merge <n> --auto` then says 'already queued to merge'. Once queued, `autoMergeRequest` reads null and `mergeStateStatus` is CLEAN, so check `gh pr view` for state MERGED rather than the auto-merge field. Merged branches are not always deleted on the remote: run `git push origin --delete <branch>`.

Cleaning an agent worktree after its PR merges: the worktree is locked by the agent's process even after the agent reports done, so `git worktree remove` fails. Run `git worktree unlock <path>` first, then remove; if a directory is left behind and is gitignored, remove that exact path. Delete the local branch only after the worktree is gone, since git refuses to delete a branch a worktree has checked out.

## Tried and ruled out

Closing a PR's issue with a Closes keyword when the work had a live-witness or open-question gap: it closed two issues early. Use Refs unless the PR meets the issue's whole acceptance.

## Watch out

A manual Release dispatch is validation-only (it cannot tag or publish), but its per-job logs are unreadable until the whole run finishes. An agent's merge watchers keep re-waking it and re-sending the same report; stop the agent once its PR is deliberately on hold.

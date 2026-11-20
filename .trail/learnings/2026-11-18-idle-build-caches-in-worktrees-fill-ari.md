---
title: Idle build caches in worktrees fill the disk; a prune script reclaims them and keeps anything in use
author: Ari
date: 2026-11-18
branch: chore/prune-worktree-targets
id: l-d6b3ed0e
scope: repo
status: active
src: agent
touches:
  - scripts/prune-targets.sh
---

## Decided
Reclaim disk by deleting idle per-worktree build caches, not worktrees. A full disk (3.6 TiB, 100% used) turned out to be 1.7 TiB of cargo target dirs, mostly the test lane's own target dir at 25-120 GiB per worktree, spread over four worktree roots. Cleaning them took the volume to 71% and freed about 975 GiB. The caches rebuild, so nothing but a slow first build is lost. The prune script is a bash script, deliberately not a Rust binary.

In the code: scripts/prune-targets.sh (dry run by default, --apply deletes, --hours sets the idle window), just maint::prune-targets, scripts/prune-targets.test.sh.

## Tried and ruled out
- Sizing the agent session stores with plain du on the home directory: it timed out every time. Size the target dirs only, in parallel with xargs -P, and write the result to a file.
- Judging "idle" from the target dir's own modification time: it only changes when a top-level entry is added, so an active build can look old. The script looks for any file written within the window, three levels down.
- Pointing every worktree at one shared target dir to avoid the sprawl: ruled out earlier because it poisons doctests and clippy across worktrees.

## Watch out
- Worktrees live under four roots, not one: the sibling .worktrees directory, the main checkout's .worktrees, and the .delta and .claude worktree directories. Agents from other tools create their own, so a new tool's directory is not scanned until it is added to the script.
- Peer sessions build in these worktrees while you clean. A process whose working directory is inside a worktree is the signal to skip it; match on that, never kill anything by pattern.
- On macOS lsof reports real paths, so a temp dir under /var does not match a process cwd under /private/var. The test resolves its temp dir with pwd -P for that reason.
- Deleting a worktree itself is a separate step that needs a git status check first: only the caches are safe to remove blind.

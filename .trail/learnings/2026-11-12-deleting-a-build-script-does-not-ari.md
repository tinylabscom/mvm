---
title: Deleting a build script does not stop a package from being rechecked when any of its files change
author: Ari
date: 2026-11-12
branch: chore/4839-delete-root-build-rs
cost: { minutes: 20 }
id: l-46f7740d
scope: repo
status: active
src: agent
touches:
  - crates/mvm-cli/build.rs
  - xtask/src/check_file_size.rs
---

## Decided
The root package's build script only set a macOS environment variable that nothing reads, so it was deleted as dead code. That is all the change claims.

## Tried and ruled out
Expected the deletion to stop the root crate rebuilding when an unrelated file in the package is touched. It does not: with no build script, Cargo fingerprints a package by the modification time of its own files, so touching a non-source file at the package root still rechecks it (about 4 seconds). Only the script run and the invalidation downstream of it went away. The box about over-broad build-script reruns therefore stays open.

## Watch out
The real churn candidate is the CLI crate's build script, which watches whole directories (crates, src) plus the git HEAD and index. Touching the README rebuilt that crate and the cause was not traced. Measure it before changing its rerun list, because it also drives the embedded-payload restore.
Agent worktree directories under .claude/worktrees can belong to a different clone (their .git file points into .delta/clones). Git refuses to remove them and their status reads the other repo, so check the .git pointer before treating one as stale.

In the code:
- build.rs (deleted), crates/mvm-cli/build.rs (rerun-if-changed list, lines ~100-125)
- xtask/src/check_file_size.rs only scans the root build.rs when it exists

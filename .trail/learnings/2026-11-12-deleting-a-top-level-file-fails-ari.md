---
title: "Deleting a top-level file fails the root layout gate unless its allow-list entry goes too, and one local gate will not tell you"
author: Ari
date: 2026-11-12
branch: chore/track-trail-learnings
cost: { minutes: 15 }
id: l-9baaa9f9
scope: repo
status: active
src: agent
touches:
  - xtask/src/check_root_layout.rs
---

## Decided
Before pushing a change that removes or adds a top-level repository entry, run the whole check-all suite locally (it passes or fails in about ten minutes), not just the one gate that looks related.

## Tried and ruled out
Checked a deleted root build script with only the file-size gate and a cargo check. Both passed, and CI then failed the root layout gate, which rejects an allow-list entry that is no longer tracked as well as an untracked one.

## Watch out
The gate is symmetric: adding a tracked root entry needs it on the allow-list, and deleting one needs it removed. Running check-all in a worktree needs the worktree's own MVM_HOME and CARGO_TARGET_DIR, and it takes several minutes of compile on a fresh target directory.

In the code:
- xtask/src/check_root_layout.rs (the ALLOWED list and the "no longer tracked" rule)
- cargo run -p xtask -- check-all

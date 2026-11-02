---
title: "specs cleanup stage 1: allow-list gate, sprint ledgers retired"
author: Ari
date: 2026-11-02
branch: chore/specs-allow-list-gate
cost: { minutes: 1, tokens: 17314 }
touches:
  - README.md
  - xtask/src/specs_transitional.txt
  - specs/prd.md
---

## Decided
- check-spec-hygiene now fails on any tracked path under specs/ that is not prd.md, README.md, adrs/, contracts/ or on the shrink-only list in xtask/src/specs_transitional.txt (ceiling enforced by a test). Each later stage deletes lines from that list; nothing is added.
- Owner chose: delete plus an archive tag (specs-archive-2026-11-02 at the pre-cleanup main commit), staged removal of legacy plans (unreferenced first), root allow-list gate plus small moves (docs/ and bin/dev), and no changes to ignored local dirs.
- specs/sprint/delivery (440 ledgers) and specs/01-project.md are gone; specs/prd.md replaces the project file.

## Tried and ruled out
- Branches that touch specs/sprint (chore/issue-based-spec-tracking, 4839-cleanup-first-batch, 3274, virtiofs) are all merged or closed, so they do not conflict.
- A constant used only by a test must be cfg(test), or clippy -D warnings fails the xtask bin on dead code.

## Watch out
- The main checkout may hold an untracked specs/prd.md; remove it before pulling this branch or git refuses the checkout.
- Frozen plans and notes still mention specs/sprint paths; they disappear in the plans stage, do not rewrite them.
- keys/ at the repo root is untracked signing material; never include it in a cleanup.
- Root has ~24 ignored local dirs (.claude, .delta, .worktrees, .agent-memory, tmp, out, ...); they are not in git and not part of the root gate.

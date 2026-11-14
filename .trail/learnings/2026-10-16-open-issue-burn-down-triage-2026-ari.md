---
title: Open-issue burn-down triage 2026-10-16
author: Ari
date: 2026-10-16
branch: main
cost: { minutes: 5, tokens: 128223 }
---

## Decided
Wave 1 agents in worktrees: #4464, #4480, #4477, #4466. #4483 (closes #4482) already queued. Only a merged PR may close an issue.
## Tried and ruled out
#4460 is a post-demo design decision, not implementable tonight. PS-21 chain (#4412-4416, #3730) and #3716 are multi-week epics. PR #4484 only partly fixes #4478.
## Watch out
164 worktrees exist and other sessions work the same issues, so check gh pr list and branches before starting. `gh pr merge --strategy` is rejected, the queue picks it. Do not commit the note file yourself in main; it is gitignored or lands in a PR branch.

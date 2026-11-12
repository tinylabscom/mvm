---
title: "PS-06 and #4839 checkbox triage (2026-11-02)"
author: Ari
date: 2026-11-03
branch: main
cost: { minutes: 2, tokens: 101787 }
---

## Decided
- PS-06 (#3731 line 54) stays unchecked: its row requires production image publication, signatures/provenance, mvm-packs#12, anchored revocation and a released in-guest witness. None is a code merge; publication/tagging needs explicit user authorization.
- #4839 had 86 unchecked body boxes plus 2 comments with checkboxes. Roughly: ~30 doable via subagent PRs (cleanup, scripts/, mvm-hostd shrink, deps, docs), the rest blocked on native hardware/release/publication or maintainer contract decisions (#4655, #4415).
- Plan proposed: one subagent per doable item in its own worktree, PR to merge queue, tick only after landing with evidence linked.

## Tried and ruled out
- Ticking PS-06 from merged source work: the issue itself forbids it.

## Watch out
- Many /tmp/wt-4839* worktrees and open PRs already exist; inventory them first to avoid duplicate work.
- mvm-gpu-* consolidation (#5018) just landed; that box may only need verifying.

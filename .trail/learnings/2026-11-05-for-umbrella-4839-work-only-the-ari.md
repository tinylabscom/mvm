---
title: "For umbrella 4839, work only the doable lanes and leave release and hardware boxes unchecked"
author: Ari
date: 2026-11-05
branch: main
cost: { minutes: 1, tokens: 1211 }
id: l-9f3a9540
scope: repo
status: active
src: agent
---

## Decided
Ari chose to execute only the roughly 30 doable boxes of #4839, one subagent per lane in its own worktree with its own PR to the merge queue (launched 2026-11-05: mvm-hostd shrink, narration/duplication cleanup in mvm-cli and mvm-runtime, extraneous-crate audit, panic-path and test review in foundation crates, docs and root-layout sync). Tick a box only after its PR lands, with evidence linked.

## Tried and ruled out
- Preparing #4764 release steps for Ari to authorize: not chosen; tagging and publishing need explicit authorization.
- Triage report only, no code: not chosen.

## Watch out
- About 70 boxes need a signed release, native HVF/KVM witnesses, mvm-packs publication, or maintainer decisions (#4655, #4415). They stay unchecked; never close #4839 with any box open.

In the code:
- 79 body and 20 comment boxes unchecked on 2026-11-05; dump with gh issue view 4839 --json body,comments to /tmp and grep for '- \[ \]'.

---
title: Umbrellas 3731 and 4839 close only when every checkbox is checked
author: Ari
date: 2026-10-30
branch: main
cost: { minutes: 1, tokens: 1287 }
---

## Decided
tinylabscom/mvm#3731 and #4839 coordinate the parallel sessions. Never close either until every checkbox in the body and in the comments is checked with verified evidence. A merged PR or a finished subtask is not grounds to close. Before taking a lane, ask the peer sessions who owns it.

## Tried and ruled out
The delta thread transcript could not be found by grepping ~/.claude/projects for its title. `gh issue list --search` finds the umbrella directly.

## Watch out
The #4839 body is about 65 KB. Save it to /tmp and grep it for unchecked boxes rather than printing it.

---
title: 4839 demo critical-path status check 2026-11-03
author: Ari
date: 2026-11-03
branch: main
cost: { minutes: 1, tokens: 95720 }
---

## Decided
The 12 demo issues listed in the #4839 reconciliation comment (6479006106) were all still open on 2026-11-03 with every box unchecked. Only #4511 and #4764 had activity after Oct 30. The first gate on the critical path is #4655 (builder custody), which was quiet since Oct 30.

## Tried and ruled out
Reading the comment alone. It dates from 2026-10-30 and is stale. Fetch each issue's live state with `gh api repos/<repo>/issues/<n>` first. The latest #4839 comments (Nov 3) are about dependency-reduction and mvm-hostd rows, not the demo list.

## Watch out
Open PRs for the 12 issues were not checked, so in-flight work may exist. The remaining items need real artifacts, signatures, and live runs, so more source merges will not close them.

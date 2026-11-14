---
title: "PRD rewrite: specs/prd.md replaces 01-project.md"
author: Ari
date: 2026-11-02
branch: main
cost: { minutes: 28, tokens: 198597 }
touches:
  - scripts/check-prod-agent-no-console.sh
  - scripts/plan-213-sp4-baseline.sh
  - specs/prd.md
  - specs/refactor/07-progress-and-decisions.md
  - specs/refactor/09-closeout.md
  - specs/research/hosted-microvm-platform-comparison.md
  - public/src/content/docs/reference/performance.md
  - public/src/content/docs/guides/policy-and-profiles.md
---

## Decided
- specs/prd.md is the tight PRD: security top line, pillars with snippets and stated limits, status tags (Shipped/Preview/Planned), a Not-promised list. Owner chose provable security as the headline and claims-plus-limits tone.
- Speed bars map onto the existing budgets in public/src/content/docs/reference/performance.md: cold under 300 ms to guest, warm claim p99 50 ms.
- Policy precedence source of truth is public/src/content/docs/guides/policy-and-profiles.md (merge rules table); pack trust is ADR-055.

## Tried and ruled out
- Old PRD promises with no witness: PII stripping (detect-only), taint tracking (not built), S3 volumes (spec type only), builder-VM shell (builder is headless), WASM as core goal (claim-free tier), Docker tier (retired).

## Watch out
- Never name the reference/competitor project in any file, branch or PR; refer to it as "the reference project".
- Comparison-table cold figures for other categories are unsourced.
- 01-project.md not yet deleted; check-spec-hygiene not run.
- Open owner decisions are listed at the end of the PRD.

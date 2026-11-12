---
title: "PRD completion: decisions resolved, only measured budgets open"
author: Ari
date: 2026-11-02
branch: main
cost: { minutes: 3, tokens: 152288 }
touches:
  - scripts/check-prod-agent-no-console.sh
  - scripts/plan-213-sp4-baseline.sh
  - specs/prd.md
  - specs/refactor/07-progress-and-decisions.md
  - specs/refactor/09-closeout.md
  - specs/research/hosted-microvm-platform-comparison.md
---

## Decided
- specs/prd.md now has a numbered five-step precedence order and a table pinning 13 merge rules to existing tests in crates/mvm-client/src/policy_profiles/ (names verified with rg).
- "Open decisions" became "Decisions": taint trigger = capability admitted; PII = structured identifiers + declared values (names only via declared values); Kotlin SDK and S3 volumes unpromised; mount allow-list stays /data and /work with a /data/cache convention; add an ADR-001 row for mount policy under claim 1.
- Only open item: Lightweight and dev-speed budgets, which need measurement on named hosts.

## Tried and ruled out
- Inventing budget numbers: no measurements exist, and placeholders are banned. Left as a measurement task.

## Watch out
- "Smallest ceiling wins across layers" has no layer-to-layer test, only flag-vs-ceiling (sizes_over_a_ceiling_are_refused); the PRD lists it as a gap.
- prd.md is still untracked in the main checkout; check-spec-hygiene and check-witness-citations were not run on the new text.
- The five resolved decisions are recommendations awaiting owner confirmation.

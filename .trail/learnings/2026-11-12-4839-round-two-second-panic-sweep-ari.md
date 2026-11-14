---
title: "4839 round two: second panic sweep found nothing to fix, and auto-merge needs explicit say-so"
author: Ari
date: 2026-11-12
branch: main
cost: { minutes: 38, tokens: 21519 }
id: l-503b678d
scope: repo
status: active
src: agent
touches:
  - ".agents/skills/secure-execution-review/SKILL.md"
  - ".github/copilot-instructions.md"
  - AGENTS.md
  - CLAUDE.md
  - xtask/src/check_root_layout.rs
  - crates/mvm-client/src/explain.rs
  - crates/mvm-client/src/instruction_trust/verify.rs
  - crates/mvm-client/src/launch/detached.rs
  - crates/mvm-hostd/src/mailbox_service.rs
  - README.md
---

## Decided
Round two of the #4839 doable lanes ran outcome-test replacement, a second panic sweep and duplication follow-ups. Auto-merge is armed only when the user says to merge; after the user's note that instructions do not authorize a merge, it was turned off on open PRs.

## Tried and ruled out
- A second panic and unsafe sweep over build, fs, net, bundler, http, agentd, runtime, backends, vmm and core found every non-test unwrap, expect and slice guarded locally. Do not repeat it; the unread remainder is hvf and libkrun driver internals, cold-channel custody, flowmux task ownership, the volume bridge and async cancellation safety.
- Propagating the ignored chmod result in the persistent builder job script: real but not testable to fail first, left unfixed.

## Watch out
- AGENTS.md now requires reading the secure-execution-review skill before security-sensitive design; branches cut before that update need origin/main merged in.
- The macOS loader-path wrapper test is gated off on macOS, so only Linux CI exercises it.

In the code:
- crates/mvm-cli/tests/embed_recipe.rs, crates/mvm-build/src/persistent_builder.rs

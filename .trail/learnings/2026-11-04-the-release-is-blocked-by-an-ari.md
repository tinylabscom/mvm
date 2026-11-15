---
title: "The release is blocked by an HVF supervisor that will not stop, not by the tag choice"
author: Ari
date: 2026-11-04
branch: main
cost: { minutes: 27, tokens: 1445797 }
id: l-75e26605
scope: repo
status: active
src: agent
touches:
  - crates/mvm-cli/src/commands/vm/checkpoint.rs
  - crates/mvm-cli/src/commands/vm/checkpoint/lineage.rs
  - crates/mvm-client/README.md
  - crates/mvm-client/src/checkpoint.rs
  - crates/mvm-hostlib/README.md
  - crates/mvm-hostlib/src/checkpoint.rs
  - crates/mvm-hostlib/src/lib.rs
  - crates/mvm-hostlib/src/registry.rs
  - crates/mvm-runtime/src/checkpoint/verify.rs
  - crates/mvm-sdk/sdks/python/README.md
---

## Decided
Before recommending a tag action, check the tag list and the release runs. A v0.26.1 tag already existed (cut Nov 3, run failed, no GitHub release), so a v0.27.0 suggestion was stale. The real blocker is the macOS HVF e2e shards failing with a supervisor that never confirms exit.

In the code: `git tag -l`, `gh release list`, `gh run list --workflow release.yml`, then `gh run view <id> --json jobs` for failed jobs. Failure text: "transient stop failed; state retained: HVF supervisor exit remains unconfirmed (supervisor status running)". Related HVF PRs: keep-waking-vCPUs fix (merged), serialize vCPU exits with destruction, notify the cancellation driver on completion.

## Tried and ruled out
- Cutting v0.27.0 or moving v0.26.0: ruled out, the owner had already tagged v0.26.1.
- Starting a release dry-run myself: left to the release owner, to avoid a second release lane. Nobody had run one on main after the vCPU fix merged.

## Watch out
- Peer sessions are named mvm-NN, not by role; ListAgents does not say who owns what, so ask for ownership rather than assuming.
- User rule: no "with Delta by Zed Industries" attribution on comments, PRs or commits.
- .trail/ is gitignored here; learnings ship only if force-added in a PR.

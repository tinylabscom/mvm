---
title: Installed-application launch tests stop at the signature check; do not widen the verifier to reach them
author: Ari
date: 2026-11-03
branch: main
cost: { minutes: 48, tokens: 236695 }
id: l-2f259825
scope: repo
status: active
src: agent
touches:
  - crates/mvm-hostd/src/plan_admission/registry_pack.rs
---

## Decided
Installed-application launch and host admission already re-verify pin, publisher policy, revocation and descriptor linkage in source. The remaining test gaps (CLI hand-off to the real resolver, hostd Application arm after a post-resolve trust change) need a genuinely Sigstore-signed application fixture, which only the maintainer signing path can produce. Box 7 of the application-reference issue stays partial until then.

## Tried and ruled out
Exposing the injected signature verifier to CLI or hostd tests through a test-support feature. It would add a second authentication path next to the one the signed-bundle and release-signing claims rely on. An end-to-end test using --dry-run is also impossible, since dry-run is refused for application references.

In the code: injected-verifier variants are pub(super) or cfg(test) in crates/mvm-core/src/registry_pack/application_bundle; the only chain test is a_catalogued_application_installs_atomically_and_resolves_for_launch in its tests.rs; host re-check lives in crates/mvm-hostd/src/plan_admission/registry_pack.rs.

## Watch out
Commits made in a worktree run the full workspace clippy pre-commit hook (several minutes), and --no-verify is blocked by a plugin hook, so amend in the background. Do not run two cargo jobs at once or the hook deadlocks on the build lock. Subagents add the AI co-author trailer and PR footer by default; strip both before merge.

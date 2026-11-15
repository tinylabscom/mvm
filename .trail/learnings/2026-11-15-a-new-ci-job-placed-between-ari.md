---
title: A new CI job placed between the runner picker and the first lint job fails a workflow-text test
author: Ari
date: 2026-11-15
branch: 4839-learnings-nov14
id: l-7bf6399f
scope: repo
status: active
src: agent
touches:
  - tests/github_actions_self_hosted_runner.rs
---

## Decided
New jobs in the PR workflow go after the lint jobs, never between the runner picker job and the first lint job. A workflow-text test treats everything in that span as the picker and forbids `set -e` inside it, so a new job whose script starts with `set -euo pipefail` fails it.

## Tried and ruled out
Running only the xtask workflow gates before pushing: they pass, and the failing test lives in a separate integration test file that reads the same workflow text.

## Watch out
After editing any workflow, run the whole workflow-text test files under tests/ (the self-hosted runner file, the extended e2e file, the workspace shard file, the release assets file), not just the xtask gates.

In the code:
- tests/github_actions_self_hosted_runner.rs, the picker is sliced out of ci.yml between its runners job and its lint-core job

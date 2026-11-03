---
title: Merging two near-identical gate scripts keeps the file count flat once the missing PR-time test is added
author: Ari
date: 2026-11-03
branch: main
cost: { minutes: 20, tokens: 48596 }
id: l-71505a3f
scope: repo
status: active
src: agent
---

## Decided
Merge gate scripts that differ only in a few strings into one script that takes a target argument, and give it a PR-time test with a fake cargo and nm on PATH. The nightly security workflow has no pull_request trigger, so these gates were never exercised on a PR.

In the code: scripts/check-no-authority.sh (guest-agent|builderd) and scripts/check-no-authority.test.sh, wired into ci.yml (run step and the shellcheck list) and called from security.yml.

## Tried and ruled out
- Counting this as a footprint reduction: scripts/ stays at 137 files and lines go 113 to 119 with the test. It removes duplication, it does not shrink the tree. Do not cite it for the scripts-consolidation box.
- Folding the installer-compat helper scripts into one lib: they are tested as separate processes, so merging means rewriting their tests. An earlier attempt stalled on a provider rate limit with its diff unvalidated.

## Watch out
- To prove a shell test can fail, force the check off in the script (for example replace the grep condition with false), run the test, then restore the file.
- BSD sed needs `sed -i ''`.

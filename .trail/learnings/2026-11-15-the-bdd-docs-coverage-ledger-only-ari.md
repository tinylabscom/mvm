---
title: "The BDD docs-coverage ledger only ran after merge, so documenting a command broke main and releases"
author: Ari
date: 2026-11-15
branch: 4839-learnings-nov14
id: l-fcdac1ff
scope: repo
status: active
src: agent
touches:
  - features/suites/s29_doc_examples/docs_coverage.toml
  - ".github/workflows/ci.yml"
---

## Decided
The scenario that ratchets documented commands against the coverage ledger now runs on pull requests that touch docs, examples, the ledger, the conformance crate or the CLI command tree, as its own small job (about 7 minutes). A new documented command needs a ledger line in the covered list when a scenario already exercises it, and in the uncovered list otherwise.

## Tried and ruled out
Listing a command as uncovered when a scenario already exercises it: the same scenario fails the other way and says the ledger still lists it as debt.

## Watch out
Before this job, the whole BDD suite ran only on merge to main, on release tags and on publish, so a docs-only pull request passed every check and broke main and the release run (the Yocto import and the no-detect run command both did). Merges also cancel the previous main run, so a red BDD can sit unnoticed.

In the code:
- features/suites/s29_doc_examples/docs_coverage.toml
- .github/workflows/ci.yml, the docs-ledger job

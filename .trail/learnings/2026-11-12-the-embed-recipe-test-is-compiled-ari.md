---
title: "The embed recipe test is compiled by bare rustc in CI, so it can only use the standard library"
author: Ari
date: 2026-11-12
branch: 4839-outcome-tests2-lane
id: l-afacd1af
scope: repo
status: active
src: agent
touches:
  - crates/mvm-cli/tests/embed_recipe.rs
  - ".github/workflows/ci.yml"
---

## Decided
That test file stays std-only: it finds the repo root by walking up to the Justfile and uses its own self-cleaning scratch directory.

## Tried and ruled out
Using tempfile and the manifest-dir compile-time variable, as every other test in the crate does. It passed under nextest and failed CI, because the Invariant job never goes through Cargo.

## Watch out
nextest passing says nothing about this file. Before pushing a change to it, run the exact rustc command from the Invariant job (--edition=2024 -D warnings --test, from the repo root).

In the code:
- crates/mvm-cli/tests/embed_recipe.rs
- .github/workflows/ci.yml (the embed-recipe step)

---
title: Why a release build compiles ~1017 crates and rebuilds
author: Ari
date: 2026-10-19
branch: main
cost: { minutes: 4, tokens: 135733 }
touches:
  - crates/mvm-cli/build.rs
---

## Decided
The ~1017 figure is two builds summed: mvmctl (~545 crates) plus the nested musl cargo-zigbuild that crates/mvm-cli/build.rs runs for mvm-host-vm-init, mvm-builderd and mvm-setpriv (374 crates, separate target dir, so shared crates compile twice). Best lever: move the guest-side bins out of mvm-build into a leaf crate (like mvm-setpriv); they currently link all of mvm-build (gix 81, libkrun-sys, rustls, tree-sitter, icu). Second lever: release.yml builds mvmctl with release-min but hostd/gpu/hostlib with --release, so shared deps compile twice; use one profile. gix removal is already issue #4538.

## Tried and ruled out
Did not re-run a general dep-cut review: Plan 309 already measured and declined tokio, toml, url, tree-sitter, tracing-subscriber. No cold release build was timed; the "~100 crates" leaf-crate size is an estimate.

## Watch out
The nested build is skipped when ~/.cache/mvm/embed holds a payload keyed to the tree, so warm local builds do not show the rebuild.

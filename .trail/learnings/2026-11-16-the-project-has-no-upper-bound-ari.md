---
title: The project has no upper bound on lines of code; a size cap is a future cleanup decision
author: Ari
date: 2026-11-16
branch: main
cost: { minutes: 1, tokens: 1004 }
id: l-51b32bbe
scope: repo
status: active
src: agent
touches:
  - xtask/src/check_rust_footprint.rs
---

## Decided

As of 2026-11-16 the maintainer says the project has no upper bound on lines of Rust. The earlier under-1M-line goal is dropped, not just paused. Any size cap or ratchet that blocks growth is a decision for a future cleanup task, so do not propose or enable one in the meantime.

In the code: xtask/src/check_rust_footprint.rs has ENFORCED=false; leave it false. The umbrella cleanup issue (#4839) now marks its under-1M box as dropped, and #5567 (restore the ratchet) is parked pending that future decision.

## Tried and ruled out

Treating the footprint ratchet as a harmless regression guard rather than a target: a ceiling set at current totals is still an upper bound, so it conflicts with this decision. I recommended enabling it and had to retract that.

## Watch out

Do not read the old 1,235,719-line measurement as a gap to close. Dependency-count work (#5300) is a separate question from line count and is unaffected.

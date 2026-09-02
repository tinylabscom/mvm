# Aux-helper staleness gate — inner loop 20.9s → 8.5s

Plan 334 delivered the musl half of taking `mvm-cli`'s build script off the
inner loop and named its residual: the per-VM aux helpers still rebuilt
unconditionally. That residual had grown to **17.8s of a 20.9s rebuild (85%)**
after a one-line `mvm-core` edit — the `mvm-cli(build)` progress line everyone
sits watching.

Closed by `specs/plans/2026-08-26-aux-helper-staleness-gate.md`:

- `crates/mvm-cli/build.rs` reuses a previous aux build on a content-key miss
  under the dev profile and marks it `<bin>.mvm-stale`.
- `crates/mvm-vmm/src/host/aux_bin.rs` refuses to spawn a marked helper,
  naming `just embed-refresh`.

That keeps #2058's guarantee — a supervisor that ignores your edit must never
run silently — while moving its cost from every build to only the builds that
actually spawn a VM. Measured 20.9s → 8.5s; `run-custom-build` leaves the
timing report's top eight.

10 new tests in `aux_bin.rs`, including two that drive `resolve_from` through
both resolution paths so the gate is proven wired, not merely defined.

Also raised the embed content store's ceiling on this host from its 4 GiB
default (it was pinned at exactly the cap, 371 entries, ~1 day of history
across ~32 worktrees, so returning to any older tree missed).

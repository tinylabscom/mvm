# Cut the per-VM aux-helper leg off the inner loop

Backing: shipped-source
Validation: resolve_missing_helper_names_the_command_that_builds_it

**Status:** SUPERSEDED by
`specs/plans/2026-08-28-build-script-drops-the-aux-helper-leg.md`
**Date:** 2026-08-26
**Owner:** mvm

> **Superseded (2026-08-28).** This plan made the aux leg *cheap* by reusing a
> previous build and refusing the reused binary at spawn. The leg has since been
> deleted outright: those seven binaries are ordinary `[[bin]]`s of `mvm-hostd`
> that a workspace `cargo build` already produces into `target/<profile>/`,
> where `aux_bin::resolve` already looked. Reuse, the `.mvm-stale` marker and
> the `MVM_ALLOW_STALE_AUX` escape hatch are all gone, because cargo owns
> freshness and staleness is no longer representable. The measurements and the
> reasoning below stand as the record of why the intermediate step was taken.

## Summary

Plan 334 took `mvm-cli`'s build script off the inner loop for the musl leg and
named its own residual: *"Native per-VM helpers still always rebuild (13s)."*
That residual has since grown to **17.8s of a 20.9s rebuild (85%)**, and it is
now the whole of what people mean by "`mvm-cli(build)` takes forever".

This closes it: the aux leg reuses a previous build on a content-key miss, and
`mvmctl` refuses to *spawn* a reused helper that does not carry the tree's
changes. Measured **20.9s → 8.5s**, with `run-custom-build` dropping out of the
timing report's top eight entirely.

## Measurements (2026-08-26, aarch64 macOS, 16 cores, `jobs=6`)

`cargo build -p mvm-cli --timings` after a one-line edit to `mvm-core/src/lib.rs`:

| Unit | Before | After |
|---|---|---|
| total wall | 20.9s | **8.5s** |
| `mvm-cli run-custom-build` | **17.8s** (0.8s → 18.6s) | not in top 8 |
| `mvm-cli` (the crate) | 2.3s, blocked until 18.6s | 2.2s, starts at 6.3s |

On a pristine tree the script was already ~0.4s — the content store from
PR #2644 works. The problem was that it **cannot hit on the inner loop by
construction**: the key hashes each helper's real dependency closure, every
helper links `mvm-hostd → mvm-core`, so any edit under those trees misses by
definition and paid a nested `cargo build` of a 100K-LOC crate in a second
target dir.

## Why this was not simply "reuse like the musl leg does"

The asymmetry was deliberate. A stale *embedded* musl binary only sits inside
`mvmctl`; a stale *supervisor* is spawned, and a guest that silently ignores
your edit is far worse than a slow build — that is why #2058 removed the reuse.
The known failure mode is a ~30s hang whose only tell is a missing console
field.

So reuse alone was not available, and neither was the status quo. The fix is to
move the check from build time to use time:

- `crates/mvm-cli/build.rs` — on a key miss under the dev profile, with a
  previous build present, reuse it and write a `<bin>.mvm-stale` marker beside
  it. A cold worktree still builds (nothing to reuse), and `--release` /
  `release-witness` still always build, matching the musl leg's existing rule.
  Cleared on any path that proves freshness (store restore, or a real build).
- `crates/mvm-vmm/src/host/aux_bin.rs` — `resolve` refuses a marked binary with
  an actionable error naming `just embed-refresh`, on both the directory-search
  and the explicit-path-override paths.

Net effect: the silent 30s hang becomes an instant, named error, *and* the
17.8s comes off every build that does not spawn a VM — which is nearly all of
them, including every `cargo check` and `clippy`.

Markers only ever exist in a source checkout's build-script directory. A
downloaded release ships helpers with no marker beside them, so the shipped
path is untouched.

## Escape hatches

- `just embed-refresh` — rebuild for real.
- `MVM_EMBED_NO_CACHE=1` — opt out of the store and both stale fallbacks.
- `MVM_ALLOW_STALE_AUX=1` — spawn the reused helper anyway, for edits that
  provably cannot reach it.

## Tests

`crates/mvm-vmm/src/host/aux_bin.rs`, 10 new cases: marker path shape, fresh
admitted, marked refused with all three recovery hints, override admits,
per-binary scoping, and — the ones that matter — `resolve_from` refusing
through both resolution paths, so the gate is proven *wired* rather than merely
defined. Mutating `refuse_if_stale` to always admit turns the refusal tests red.

## Deliberately not done

- **The stable-1.96 vs nightly double compile.** `just lint`/`just ci` run
  clippy on stable-1.96.0 into `target/stable-1.96.0` (3.3G) while everything
  else uses the pinned nightly in `target/`, so a lint run shares no artifact
  with a test run. Under investigation separately; `scripts/check-fast-cargo.sh`
  guards the split for release/MSRV lanes, so it is not a free change.
- **Refuted, do not re-propose without new evidence:** bare `cargo` vs
  `scripts/cargo-fast.sh` do *not* thrash (differing rustflags produce
  different metadata hashes and coexist in one target dir, costing disk rather
  than rebuilds), and `cargo check --workspace --all-targets` invalidates
  nothing in `cargo build -p mvm-cli`.

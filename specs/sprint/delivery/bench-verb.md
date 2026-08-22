# `mvmctl bench` — the harness gets a front door

**Plan:** `specs/plans/329-run-first-cli-and-upstream-adoption.md` Phase 7.

## What existed and what did not

The measurement substrate has been in `crates/mvm-cli/src/bench/` for a while:
five launch lanes, percentile statistics, a versioned JSON report, baseline
regression gating, and the budgets the docs publish (200/250/300 ms
prepared-cold p50/p95/p99 diagnostics; 30/50 ms warm-claim p50/p99).

The prepared-cold release requirement is stricter: every dispatch must be
under 200 ms. The default output now presents that hard maximum separately
from percentiles, uses explicit PASS/FAIL words, and explains each phase in a
Remarks column. `--json` remains supported and schema v6 carries the hard
comparison, limit, observed maximum, verdict, and remark.

What it did not have was a caller outside the project. Only the CI gate, the
conformance suite and two `#[ignore]`d tests drove it — so "is my host meeting
this contract?" was a question only the project could ask about its own
runners, and the published numbers were unfalsifiable by the people they most
concerned.

`mvmctl bench` drives the same harness against the same budgets and writes the
same report shape, deliberately: a user's report and a CI report should be
comparable artifacts, not two formats carrying similar numbers.

## Why a verb and not `doctor --benchmark`

Plan 329 offered either. `doctor` reports posture without side effects; this
boots VMs, repeatedly, and takes minutes. Folding it into `doctor` would mean
the diagnostic command sometimes launches twenty microVMs.

## Three refusals that keep a number honest

- **A debug build refuses to measure.** A debug binary is several times slower
  on the same work, so its percentiles describe the build profile, not the
  host. Publishing or comparing them is worse than having no number.
  `--allow-debug-build` exists for looking at the report's shape.
- **Below 20 samples is labelled indicative**, matching the harness's own
  publication floor, rather than being silently emitted as if comparable.
- **The default launch is host-independent**: the bundled image (no registry
  pull), `--no-detect` so the working directory cannot change which image
  boots, and `/bin/true` so the number is the launch rather than the workload.
  A baseline that varies with where it was run is not a baseline. `-- <launch>`
  overrides it.

The verb also warns, before measuring, that the prepared lanes assume a warm
cache — on a cold `~/.mvm` the first launch pays a one-time builder bootstrap.
The runner's lane validation already refuses such a sample, so the failure was
loud but confusing; saying it first turns that into one instruction
(`mvmctl prepare`).

## Audit posture

`bench` emits nothing itself. It spawns `mvmctl run` once per sample, and each
of those carries its own `cmd.run` envelope and its own signed-plan admission,
so auditing the harness on top would double-count the launches it exists to
measure. Declared `InteractiveOrControl`; the total-coverage test caught the
omission before it could ship undeclared.

## Not done

**Density.** This measures latency only. Plan 265 WS3 and Phase 4 own density
and stay open; the plan is updated to say so rather than implying Phase 7 is
finished.

Verified against the built binary: help renders, every lane is selectable, the
debug-build refusal fires, and the verb drives a real launch end to end. A full
20-sample publication-grade measurement was **not** obtained on this host — the
run reached a cold-cache builder bootstrap, which is the case the new warning
now describes.

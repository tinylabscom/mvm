---
title: Launch performance
description: The dispatch-window budgets mvm gates every launch against, the lanes they are measured in, and how to reproduce a measurement.
---

mvm's launch contract is a set of budgets on the **dispatch window** — the span
from an admitted execution plan to the guest command being dispatched. That is
the window the contract is set against, so it is the one published here.

This page states the contract. It does not state results: the budgets below are
ceilings that CI enforces, not percentiles anyone observed. A ceiling printed in
the same column as an observation gets read as an observation, so measured
matrix numbers are published separately, per host, once a lane report has been
seeded.

## Lanes

Launch costs are reported per lane and never averaged across them. Folding a
first-time image acquisition into a prepared launch would make the prepared
number meaningless and hide the acquisition cost at the same time.

The acquisition lanes (`mount_miss`, `artifact_miss`) publish no budget. Their
cost is dominated by a registry and a disk, and gating mvm on someone else's
network would make the gate measure the wrong thing.

<!-- generated:launch-budgets:begin -->

A lane result is publishable only when it carries at least 20 measured samples taken after exactly 2 discarded warm-ups, under report schema version 5. A report that misses any of those is refused rather than published with a caveat.

| Lane | What it measures | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| `prepared_cold` | Cached artifacts, no mount image, new VMM and new guest identity. | 200 ms | 250 ms | 300 ms |
| `prepared_cold_mount_hit` | The same launch with an unchanged cached read-only mount image. | 200 ms | 250 ms | 300 ms |
| `mount_miss` | Directory fingerprint plus first mount-image materialization. | — | — | — |
| `artifact_miss` | Image acquisition, unpack, verification, and preparation. | — | — | — |
| `warm_claim` | A claimed warm standby — a comparison point, never folded into a cold number. | 30 ms | — | 50 ms |

<!-- generated:launch-budgets:end -->

The table between those markers is generated from the same accessor the gate
reads. Editing it by hand fails the doc-sync test rather than changing a budget.

## What disqualifies a measurement

A lane refuses a sample that did work the lane forbids, rather than reporting it
as a faster or slower version of the same thing. A launch labelled
`prepared_cold` that quietly pulled an image, ran a build, materialized a mount
image, or claimed a warm standby is not a prepared cold launch, and publishing it
as one would make the number unfalsifiable.

The gate reads recorded work flags, not timings. An uninstrumented phase records
no span, so refusing on a missing span would pass exactly the contamination the
check exists to catch.

Beyond per-sample validity, a report is refused for publication when it:

- carries fewer measured samples than the contract requires;
- was produced with the wrong number of discarded warm-ups;
- carries a summary that does not match its own raw samples;
- was built from an unoptimised binary;
- omits the root-filesystem strategy the launch selected;
- omits process-memory evidence on a warm sample;
- exceeds any published budget above.

Raw per-sample vectors are kept in every report. Summary-only evidence cannot be
re-analysed, cannot show a bimodal distribution, and cannot be checked against
the percentiles that were published from it.

## Comparability

Two reports are comparable only when their host fingerprint matches — OS,
architecture, hypervisor, VMM version, and selected root-filesystem strategy.
A baseline from a different host or kernel is refused as incomparable rather
than compared, because silently comparing a faster kernel's numbers against an
older baseline masks a real regression or invents a fake one.

Storage matters as much as the host tier. On a rotational disk a large,
fixed fraction of a measured launch is `fsync` cost that disappears on NVMe.
A number measured on spinning media is not a runtime number, and is not
comparable to one that was not.

## Reproducing a measurement

The launch benchmark is a library surface driven by a live, `#[ignore]`d test,
not a shipped CLI verb — the suite can never produce a launch number by
accident. Run it against a release binary on a host with a prepared artifact
cache:

```sh
export MVM_COLD_LAUNCH_MVMCTL=target/release/mvmctl
export MVM_COLD_LAUNCH_ARGS="machine run --image alpine -- /bin/true"
export MVM_COLD_LAUNCH_LANE=prepared_cold
export MVM_COLD_LAUNCH_RUNS=20
export MVM_COLD_LAUNCH_WARMUP=2

cargo test --release --test cold_launch_bench -- --ignored --nocapture
```

Every knob except the counts is required. A benchmark that guesses what to
launch measures the wrong thing, so an unset variable fails and names itself
rather than defaulting.

The run writes a JSON report under `$MVM_HOME/bench/`, alongside a
`-latest.json` copy. The report carries the host fingerprint, the per-lane
percentiles, and the full raw sample vector.

---
title: Launch performance
description: The dispatch-window budgets mvm gates every launch against, the lanes they are measured in, and how to reproduce a measurement.
---

mvm's launch contract is a set of budgets on the **dispatch window** — the span
from an admitted execution plan to the guest command being dispatched. That is
the window the contract is set against, so it is the one published here.

The budget table states the contract. It does not state results: those budgets
are ceilings that CI enforces, not percentiles anyone observed. A ceiling
printed in the same column as an observation gets read as an observation, so
seeded matrix results are published in a separate table below, per host.

## Lanes

Launch costs are reported per lane and never averaged across them. Folding a
first-time image acquisition into a prepared launch would make the prepared
number meaningless and hide the acquisition cost at the same time.

The acquisition lanes (`mount_miss`, `artifact_miss`) publish no budget. Their
cost is dominated by a registry and a disk, and gating mvm on someone else's
network would make the gate measure the wrong thing.

<!-- generated:launch-budgets:begin -->

A lane result is publishable only when it carries at least 20 measured samples taken after exactly 2 discarded warm-ups, under report schema version 7. A report that misses any of those is refused rather than published with a caveat. Prepared-cold lanes additionally require every measured dispatch to be strictly under 200 ms, even below the publication sample floor.

| Lane | What it measures | p50 | p95 | p99 | Every boot |
| --- | --- | --- | --- | --- | --- |
| `prepared_cold` | Cached artifacts, no mount image, new VMM and new guest identity. | 200 ms | 250 ms | 300 ms | < 200 ms |
| `prepared_cold_mount_hit` | The same launch with an unchanged cached read-only mount image. | 200 ms | 250 ms | 300 ms | < 200 ms |
| `mount_miss` | Directory fingerprint plus first mount-image materialization. | — | — | — | — |
| `artifact_miss` | Image acquisition, unpack, verification, and preparation. | — | — | — | — |
| `warm_claim` | A claimed warm standby — a comparison point, never folded into a cold number. | 30 ms | — | 50 ms | — |

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

## Seeded measurements

These are observations, not new budgets. The report gate revalidated every raw
sample before the row was added.

| Date | Lane | Host fingerprint | Backend | Storage | Samples | p50 | p95 | p99 |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| 2026-08-19 | `prepared_cold` | Linux 6.8.0-137 x86_64, Intel i7-7700 | Firecracker v1.14.1 | rotational md-RAID (`ROTA=1`) | 20 (+2 warm-ups) | 171.5 ms | 176.0 ms | 178.0 ms |

The source revision was `b107dfb22c`. The full schema-v5 raw report is kept at
`specs/evidence/performance/2574-prepared-cold-firecracker-2026-08-19.json`;
its SHA-256 digest is
`523ffd3f2904696141edd806861093abb1011de00d6c345b7acc3be27f4ee6c4`.
All 20 measured samples were release builds, used `block_ext4`, carried no
degradation, and recorded every prepared-cold work flag as false.

## Reproducing a measurement

`mvmctl bench` is the shipped, visible verb for this. The lane is a **flag**, not
a subcommand. Run it from a release build on a host with a prepared artifact
cache:

```sh
mvmctl prepare
mvmctl bench --lane prepared-cold --runs 20 --warmup 2
```

`--lane` defaults to `prepared-cold` and accepts `prepared-cold`,
`prepared-cold-mount-hit`, `mount-miss`, `artifact-miss`, and `warm-claim`.
`--runs` defaults to 20 and `--warmup` to 2 — below 20 measured samples the
report is not publication-grade. `--json` prints the report instead of a human
summary, `--out <PATH>` redirects where it is written, and a debug build refuses
to measure at all unless you pass `--allow-debug-build`, whose numbers mean
nothing.

Name the launch after `--` to measure something other than the built-in
reproducible baseline:

```sh
mvmctl bench --lane prepared-cold -- machine run --image alpine -- /bin/true
```

The same measurement substrate is also driven by a live, `#[ignore]`d test for
CI use, so a routine `cargo test` never produces a launch number by accident.

The run writes a JSON report under `$MVM_HOME/state/bench/`, alongside a
`-latest.json` copy. The report carries the host fingerprint, the per-lane
percentiles, and the full raw sample vector.

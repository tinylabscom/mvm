# Telemetry emit-path baselines and regression budgets

Backing: preview
Validation: none — hardware-dependent measurements, deliberately not a CI gate.

Pre-feature baselines for the pieces guest capture will sit on, so enabling
collection later has numbers to be judged against. Produced by
`cargo run --release -p xtask -- telemetry-baseline`; raw per-run reports are
committed beside this file. A report carries a host descriptor and a schema
version; numbers are comparable only against the same hardware and schema.

## Hardware and commands

- Host: Apple M3 Max, 16 logical cores, macOS (aarch64). Toolchain:
  pinned Rust 1.97.1, release profile.
- Commands (run five times, one report per run):

```sh
cargo build --release -p xtask
./target/release/xtask telemetry-baseline > baseline-run-<n>.json
```

- Raw runs: `baselines/2026-09-19-macos-m3max/baseline-run-{1..5}.json`.
- Defaults: 100,000 samples per latency metric; 50 flood rounds of
  4 producers × 256 attempts against one 256-slot outbox.

## Measurements (5 runs, nanoseconds)

Coefficient of variation (CV) is across the five runs' values of each
statistic. `max` is scheduler-noise-bound on macOS (CV up to ~170%) and is
recorded but not budgeted.

| metric | p50 (CV) | p95 (CV) | p99 (CV) | max range |
|---|---|---|---|---|
| timer overhead (Instant pair) | 0 (0%) | 42 (0%) | 42 (0%) | 84–42,708 |
| prepare, small coverage record | 400 (5.6%) | 484 (4.6%) | 542 (0%) | 35,667–48,666 |
| prepare, typical log record (256 B message + 4 attrs) | 942 (2.4%) | 1,142 (4.1%) | 1,275 (1.8%) | 43,625–69,958 |
| offer, queued, small | 41 (0%) | 42 (0%) | 50 (37%) | 8,083–62,750 |
| offer, queued, typical | 41 (1.1%) | 42 (0%) | 42 (0%) | 5,792–19,666 |
| offer, full-queue shed | 41 (0%) | 42 (0%) | 42 (0%) | 208–48,166 |

Interpretation notes:

- Every offer statistic sits at the timer floor: one `Instant::now()` pair
  costs ~42 ns p95, so "41–42 ns" means "at or below timer resolution", not a
  precise cost. The honest claim is: admission (queued and shed alike) is
  indistinguishable from free at this timer's resolution.
- Preparation dominates the producer path, as the outbox delivery notes
  already record: record building and wire encoding allocate and cost
  ~0.4–1.3 µs depending on record size; admission itself does not.
- Allocations are not re-measured here: the admission path's zero
  allocation/free property is witnessed by `mvm-core`'s outbox allocation
  regressions, natively and under Miri.
- Memory is deterministic, not sampled: 32,768-byte slots, 256-slot ceiling,
  8,388,608-byte maximum storage per outbox, paid at construction.

## Flood fairness: a recorded deficiency, not a budget

With four producers racing 256 attempts each at one 256-slot outbox from a
barrier start, per-round admitted min/max ratio was ~0 in essentially every
round (p50 = 0.000 across all five runs; best single round 0.200): admission
is so fast that the first-scheduled producer monopolizes the queue before the
others wake, and ~49% of all attempts land as `Contended` on the single
`try_lock`. Aggregates per run: 12,800 queued (exactly capacity × rounds),
~24,300–25,700 contended, remainder shed as full.

This is the pre-feature record of the plan's flood-fairness concern: burst
fairness across producers does not exist today and nothing claims it does.
Whatever fairness the capture design later provides (or explicitly declines
to provide) must be stated against this baseline rather than assumed.

## Regression budgets

Rule: budget = worst observed value of that statistic across the five runs,
×1.5, rounded up — wide enough to absorb run-to-run variance on this host,
tight enough that a real regression (a lock on the emit path, an allocation,
a format call) blows through it. `max` carries no budget. Budgets bind when
capture work starts landing on these paths (W3 onward) and are asserted on
this hardware, not in shared CI.

| metric | p50 budget | p95 budget | p99 budget |
|---|---|---|---|
| prepare, small | 624 ns | 750 ns | 813 ns |
| prepare, typical | 1,437 ns | 1,812 ns | 1,938 ns |
| offer, queued (either size) | 63 ns | 63 ns | 126 ns |
| offer, shed | 63 ns | 63 ns | 63 ns |

An offer budget of 63 ns is one timer-pair above the floor: any measurable
cost added to admission fails it.

## Open: hardware-qualified control/exit latency

VM control and workload-exit latency need a booted guest, which this offline
harness deliberately does not do. The live lanes own those numbers and their
budgets; record them with:

```sh
cargo run -p xtask -- perf boot --runs 30 --rootfs <rootfs.ext4>   # Linux + KVM
```

plus the `mvm-cli` bench harness's interaction lane for launch-latency
distributions. Until those runs are recorded per backend on qualified
hardware, control/exit telemetry impact has a command, not a baseline, and
nothing here claims otherwise.

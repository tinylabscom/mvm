# Offline overflow-policy evaluation

Backing: preview
Validation: `cargo test -p xtask telemetry_baseline`

This is the **evaluation-only** portion of
[#3942](https://github.com/tinylabscom/mvm/issues/3942). It does not change
production `Outbox`, agent capture, loss summaries or defaults.
**Retain drop-newest.** Policy simulation is useful for retention semantics,
but cannot satisfy the issue's actual admission-cost or reference-hardware
fairness criteria.

## Reproduce

From this checkout in Bash:

```bash
source scripts/dev-env.sh
cargo test -p xtask telemetry_baseline
cargo build --release -p xtask
rustc --version --verbose
for run in 1 2 3 4 5; do
  "$CARGO_TARGET_DIR/release/xtask" telemetry-baseline \
    --samples 100000 --rounds 50 > "/tmp/overflow-evaluation-${run}.json"
done
```

Keep the complete reports, command, revision, release profile and toolchain
output when comparing runs. Host CPU, OS, architecture and logical-core count
are in the existing `host` section; `experimental_overflow_models.toolchain`
records `rustc --version` from the execution environment (which must match the
build environment). The existing production baseline fields remain schema 1;
the additive model section has its own `model_schema_version: 1`.
Consumers should ignore unfamiliar report fields.

## Scope and workload

All three policies use a shared mutex and exactly one `try_lock` per offer.
The queue stores only `(source, sequence, bytes)` descriptors, with a global
limit of 16 records and 4096 declared payload bytes:

| Policy | Behavior |
|---|---|
| `drop_newest` | Reject the arriving record when either global bound is full; preserve queued history. |
| `drop_oldest` | Evict FIFO descriptors until both bounds permit admission; an oversize arrival rejects without evicting anything. |
| `reserved_drop_newest` | Hard-partition admission: eight records and 2048 bytes per source; no borrowing, eviction or transfer of unused reservation. |

Two sources represent noisy and quiet traffic. In each scripted trace the
noisy source attempts 128 records; the quiet source attempts 16 (one per eight
noisy records), with monotonically increasing source-local sequence numbers.
Sizes cycle through 64, 512, 128 and 1024 bytes with a source-dependent offset.
The stalled worker does not drain until producers finish. The periodic worker
drains one record after every four noisy attempts, then drains the remainder.
These are deterministic schedules, not claims about real producer rates.

Each policy additionally runs `--rounds` barrier-started concurrent rounds:
two producers each offer 128 variable-size records while one worker performs
128 pop attempts, joins the producers, then drains the remainder. The finite
worker schedule intentionally avoids sleep polling. Counts vary with host
scheduling. This differs from the existing four-producer no-worker production
fairness baseline: do not compare its ratios as like-for-like results.
Reservation cannot guarantee fairness when the single lock is contended.

Reports include per-source attempted, admitted, rejected, contended, evicted
and drained **records and bytes**, plus exact drained sequence lists.
After the final drain, assertions require:

```text
attempted = rejected + contended + admitted
admitted = evicted + drained
```

The equations apply independently to record counts and bytes, per source.
Eviction is a loss of a previously admitted record, not rejection of the
new arrival. Sampled `observed_peak_records` and `observed_peak_bytes` check
global bounds; in concurrent runs they are observations, not guaranteed
high-water marks. Unit tests separately cover exact count and byte boundaries,
multi-victim eviction, oversize rejection, quiet-source reservations under
both count and byte saturation, held-worker-lock nonwaiting admission, and
the worker's ownership of already-popped records.

## What the models tell us

- Drop-newest retains early history and loses newer ranges. Drop-oldest
  retains recent queued history, but moves gaps into earlier ranges.
  Once the worker owns a popped record, eviction cannot retract it; the
  resulting stream can contain old in-flight records followed by much newer
  records. Neither policy rewrites sequence numbers.
- Byte limits matter independently of slots. A large arrival can evict
  several small records; work is bounded by queue capacity, not constant
  per arrival. Production has up to 256 slots, rather than this model's 16.
- Reserving slots alone would not protect a quiet source when noisy records
  exhaust the byte budget. Reserving both resources protects capacity but
  strands unused quota and does not solve single-lock contention.
- A second per-source queue would isolate locks and eviction domains, unlike
  a reservation in one shared queue. Keeping the same total memory budget
  still partitions capacity; it does not manufacture space. It also needs
  an explicit worker scheduling policy and gives up shared FIFO order.
  Separate queues are an architectural alternative, **not measured here**.

  ### Local observations

  Five release runs with the reproduction command on Apple M4 Max, macOS
  aarch64, 16 logical cores, Rust `1.100.0-nightly (e7769602a 2026-08-24)`
  produced the following deterministic retention results in every run.
  Each source cell is `drained / rejected / evicted` records; stalled and
  periodic schedules both finish with a full drain.

  | Policy | Stalled noisy (128) | Stalled quiet (16) | Periodic noisy (128) | Periodic quiet (16) |
  |---|---|---|---|---|
  | Drop-newest | 10 / 118 / 0 | 1 / 15 / 0 | 44 / 84 / 0 | 3 / 13 / 0 |
  | Drop-oldest | 8 / 0 / 120 | 1 / 0 / 15 | 38 / 0 / 90 | 2 / 0 / 14 |
  | Reserved drop-newest | 8 / 120 / 0 | 7 / 9 / 0 | 30 / 98 / 0 | 13 / 3 / 0 |

  The reservation buys quiet-source retention at the expense of noisy-source
  retention. Merely switching eviction direction does not protect the quiet
  source: drop-oldest's global recency rule lets later noisy arrivals evict
  earlier quiet records, leaving only one quiet record in the stalled queue.
  These are workload-specific results, not universal fairness ratios.
  All byte-accounting assertions also passed, including the 50 concurrent
  worker rounds per policy per run.

  The timer p95 was 42 ns in all five runs. **Metadata-model-only** mixed-offer
  p95 ranges were 125–166 ns (drop-newest), 167–250 ns (drop-oldest), and
  125–208 ns (reserved). These numbers include model-specific scanning and
  allocation; they establish neither a production regression nor compliance.
  Raw reports are generated at the `/tmp/overflow-evaluation-{1..5}.json`
  paths above and are not committed as new reference baselines.

Sequence lists expose gaps only within this finite trace, where every attempt
is known. In production, absent tail records are not independently discoverable
from subsequent data until more data arrives; explicit cumulative loss evidence
remains necessary. Eviction accounting must charge the victim's source and
bytes, not the arriving record. Neither admission nor this simulated drain
is an acknowledgement of transport delivery.

## Timing limits and enablement evidence

`mixed_model_offer_ns` includes the baseline timer pair, metadata scanning,
and allocation of the model's eviction list. It mixes admission and rejection
outcomes across the two scripted workloads. It excludes payload copy/zeroing,
real loss-counter atomics, encoding, worker transport, poison/close behavior
and actual capture. The descriptor deque and eviction vectors are not a
production storage design or a zero-allocation witness. **Do not compare this
metric to 63 ns or describe it as production overhead.** It exists to make
model runs inspectable; the existing production offer measurements remain
the only production measurements in the report.

The committed offer budgets bind the Apple M3 Max/macOS, pinned Rust 1.97.1,
release-profile baseline. Its roughly 42 ns p95 timer floor means apparent
41–42 ns values do not resolve actual operation cost. Host/toolchain/schema
differences prevent treating a local run as proof those budgets were met.
The separate Firecracker Intel i7-7700 reference-host fairness remeasurement
required before enablement is still outstanding, as is live capture/control
evidence. No VM operation is needed or performed by this harness.

Before changing production policy, measure a representative fixed-storage
implementation with actual payload copies and loss accounting on the budget
host, including worst-case multiple evictions and concurrent draining.
Compare outcomes separately rather than hiding costly eviction under a mixed
distribution, run the required Firecracker-reference fairness lane, and decide
whether retaining recent UI data outweighs historical loss and quota waste.
This evaluation leaves those acceptance criteria open and does not close
#3942.

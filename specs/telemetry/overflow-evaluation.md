# Overflow policy: evaluation and decision

Backing: preview
Validation: `cargo test -p xtask telemetry_baseline`

[#3942](https://github.com/tinylabscom/mvm/issues/3942) asked which record a
full capture queue should shed when a noisy producer floods it, and whether
per-source quotas should protect quiet producers.

**Decision: keep drop-newest, and add no per-source quotas.** A full queue
refuses the arriving record; queued history is never evicted. The decision
rests on the fixed-storage measurement in
[the decision measurement](#decision-measurement-fixed-storage-noisy-producer)
below, not on the metadata models that follow it.

## Decision measurement: fixed storage, noisy producer

`cargo xtask telemetry-baseline --noisy` runs both rules on the production
storage shape: 128 slots of 32 KiB (the guest agent's capture queue), the
payload copy under the one `try_lock`, zeroing a slot when its record leaves,
per-source loss counters as single atomic adds, and a worker that copies
records out under the lock on the capture session's 25 ms cadence. The
drop-newest arm is the production admission rule; the drop-oldest arm differs
only in evicting the head until the arrival fits. A noisy producer offers a
701-byte log record back to back, a quiet producer offers one every
millisecond, and each round runs 1 s live, 500 ms with the worker stalled
(an unreachable host) and 500 ms of recovery. After the final drain the
harness asserts, per source, `attempted = queued + shed + contended` and
`queued = evicted + delivered`.

Host: AMD Ryzen 5 3600 (12 logical cores), Linux 6.1, the Firecracker KVM
reference host, shared with other work (load average 18–28 during the runs);
Rust 1.98.1, release profile; source
`b45a7f794650e274592eb4067902bcf6fe2dd64c`. Five runs of
`telemetry-baseline --noisy --rounds 5 --samples 100000`; raw reports with
SHA-256 sums are in
[`baselines/2026-10-12-kvm-ryzen5-3600-noisy/`](baselines/2026-10-12-kvm-ryzen5-3600-noisy/).
Ranges are across the five runs. Every latency includes one `Instant::now()` pair.

| Measure | Drop-newest | Drop-oldest |
|---|---|---|
| Uncontended full-queue offer, 701 B, p50 / p99.9 | 30–70 / 50–90 ns | 50–100 / 80–150 ns |
| Uncontended full-queue offer, 32 KiB, p50 / p99.9 | 30–70 / 50–110 ns | **990–1,190 / 1,340–2,220 ns** |
| Noisy producer offer under flood, p50 / p99 | 40 / 50–300 ns | 50–70 / 100–310 ns |
| Quiet producer offer under flood, p50 / p99 | 110–150 / 650–820 ns | 280–530 / 1,150–1,550 ns |
| Quiet attempts lost to lock contention | 11.7–18.5% | 32.0–36.2% |
| Quiet records delivered | 0.1–7.0% per round | 0.1–7.8% per round |
| Quiet records lost after admission (evicted by the noisy source) | 0 | 5,421–6,387 per run |
| Age of a record when the worker takes it, live, p99 | 0.1–27 ms (25–27 ms in four runs) | 0.05–0.1 ms |
| Oldest record in the first drain after a 500 ms outage | 501–526 ms | 0 ms |
| Most records evicted by one admission | — | 1 |

What the numbers say:

- **Cost.** Drop-oldest must copy the arrival (and zero the victim) on every
  full-queue offer, which is exactly when a flood is running. For a
  maximum-size record that is about 1 µs at p50 and 2 µs at p99.9 — over
  twenty times the drop-newest cost and far outside the committed 63 ns offer
  budget. Drop-newest's full-queue path is a length check.
- **Fairness gets worse, not better.** Holding the lock for a copy on every
  flood offer more than doubles the quiet producer's contention losses, and
  each noisy admission evicts whatever is oldest — usually someone else's
  record. Neither rule protects the quiet source (both deliver well under
  10% of its records under this flood); drop-oldest additionally charges
  the noisy source's overflow to the quiet source.
- **Attribution.** Under drop-newest the producer whose record is refused is
  the one told, at offer time, so per-producer loss counters and sequence
  gaps stay exact with no per-slot owner metadata. Drop-oldest would have to
  record the owner of every slot and charge losses to a producer that did
  not overflow.
- **Recency is the one thing drop-oldest buys,** and it is bounded. While the
  worker is draining, a drop-newest record waits at most one drain interval
  (about 25 ms at p99) — invisible at UI scale. After an outage, drop-newest first
  delivers the 128 records queued when the outage began; the session sends
  them in two capped turns and is back to live records within one drain
  interval of reconnecting. The staleness is one queue's worth, once, and it
  is marked by the sequence gap and loss summary that follow it.

Per-source quotas were evaluated with the metadata models below: a
reservation in the shared queue strands unused capacity and does nothing for
lock contention, which is the larger quiet-source loss in the measurement
above; a queue per source changes the worker's scheduling contract and was
not measured. Neither is adopted. Quiet-source starvation under a flood
remains the documented deficiency recorded in [the baselines](baselines.md),
made visible to consumers by per-producer loss summaries rather than hidden.

The rule a consumer can rely on is recorded in the
[studio data contract](studio-contract.md#semantics-the-ui-must-respect).

## Metadata models (earlier evaluation)

The rest of this document is the earlier, metadata-only evaluation. It
changed no production behavior and established neither a production cost nor
compliance with the offer budget; the measurement above supersedes it for
the decision.

### Reproduce

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
These rounds stress accounting under scheduling variation; the start barrier
does not guarantee that draining overlaps offers. A worker can finish its
empty pop attempts before either producer runs. They are not an overlap or
concurrent-fairness witness.

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
  The five complete original reports, SHA-256 checksums and recovery instructions
  are preserved in the [issue evidence](https://github.com/tinylabscom/mvm/issues/3942#issuecomment-6067625153).
  Their measured source is commit `1999f048c4f7bb7d6f07e23cac895a8daac0ee75`.
  They are local observations, not new reference baselines. Independent inspection
  of all 780 recorded traces verified per-source record/byte conservation and
  strictly ordered, unique drained sequences.

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

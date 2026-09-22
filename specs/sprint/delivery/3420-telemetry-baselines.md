# Telemetry emit-path baselines: harness, measurements and budgets

Issue #3420, the W1 baseline item of `2026-09-17-host-mediated-telemetry`
(split W1d offline / W1e live in the plan); epic #3419 remains open.

`cargo run --release -p xtask -- telemetry-baseline` measures, offline and
without booting anything: record preparation latency (small coverage record
and a typical 256-byte log record), outbox admission latency on the queued
and full-shed paths, multi-producer flood fairness (4 producers × 256
attempts racing one 256-slot outbox per round), timer overhead, and the
deterministic storage bound. One JSON report per run with a host descriptor
and schema version; not a `check-all` gate because the numbers are
hardware-dependent.

Committed evidence (`specs/telemetry/baselines.md` + five raw run reports
under `specs/telemetry/baselines/2026-09-19-macos-m3max/`), from five release
runs on Apple M3 Max, pinned Rust 1.97.1:

- Preparation: ~400 ns p50 small, ~940 ns p50 typical (CV ≤ 5.6% on
  budgeted statistics). Admission: at the timer floor (~41–42 ns, one
  `Instant` pair costs ~42 ns p95), queued and shed alike.
- Flood fairness: per-round admitted min/max ratio ~0 in essentially every
  round — the first-scheduled producer monopolizes the queue and ~49% of
  attempts land `Contended` on the single `try_lock`. Recorded as a
  pre-feature deficiency the capture design must speak to, not a budget.
- Budgets derived as worst-of-five × 1.5 per statistic (`max` excluded as
  scheduler-noise-bound); an offer budget of 63 ns means any measurable cost
  added to admission fails it. Budgets bind on this hardware from W3 onward.
- Allocations are not re-measured: the zero-allocation admission property is
  already witnessed by `mvm-core`'s outbox allocation regressions, natively
  and under Miri. Memory is computed (256 × 32 KiB = 8 MiB ceiling), not
  sampled.

Explicitly open (W1e): VM control/exit latency needs a booted guest; the
live lanes and exact commands are recorded in the baselines doc, and no
control/exit baseline is claimed. This session launches no VMs, per the
plan's environment rules.

## Validation

- Seven focused harness tests pass: nearest-rank percentiles, exact
  queued/shed separation, flood accounting (every attempt lands exactly
  once, admissions equal capacity), fairness aggregation, record-size
  ordering, report serialization with a populated host descriptor, and
  flag refusal paths.
- `cargo fmt --all -- --check`, workspace clippy (pinned 1.97.1, warnings
  denied), full workspace tests via `just test` (14,722 tests, zero failures, 27 skipped),
  pinned-toolchain doctests, all 74 `check-all` repository gates and
  `just check-gated` pass.

This slice changes no runtime, transport or capture behavior: it adds a
measurement command, committed measurements and budgets. Numbers from this
host bind only on this host. W1e and W2–W7 remain open. Do not close #3420
or #3419 on this delivery alone.

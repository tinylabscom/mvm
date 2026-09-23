# Live control-latency baseline and the graceful-stop blocker

Issue #3420, the W1e item of `2026-09-17-host-mediated-telemetry`; epic
#3419 remains open.

Measured on a dedicated KVM host (Hetzner, Intel i7-7700, 62 GiB, Ubuntu
24.04, Firecracker v1.17.0, pinned Rust 1.97.1), using the CI boot-latency
lane's recipe verbatim: the pinned published image fetched and
cosign/checksum-verified, then the `runtime_boot_bench` harness at 30 serial
boots plus a 3-wide concurrent fan-out, repeated five times.

- Boot-to-guest-agent-ready serial p50 across repetitions: 502–549 ms
  (~4.5% CV); one unsmoothed 2.3 s cold outlier in repetition 2. Budgets by
  the offline set's rule (worst-of-five × 1.5): p50 ≤ 824 ms, p95 ≤ 1,986 ms
  on this hardware. Full tables and commands in `specs/telemetry/baselines.md`.
- The harness change (`tests/runtime_boot_bench.rs`) times the stop the
  bench already performs and prints an informational distribution beside the
  boot summary; failed stops are counted, never folded into percentiles, and
  the budget gate stays about boot. Nineteen harness tests pass.

The exit half is a finding, not a number: **all 165 stops failed the
graceful path** — the stop-time flush verb (`sleep-prep`) is refused with
`VerbNotAuthorized` because every backend boots guests under
`mvm.require_grant=1` and a raw bench `backend.start` provisions no signed
verb grant. No VMM processes leaked (the error path still kills), and the
refusal reproduces 100%. Consequences recorded: CI's boot-latency lane has
only ever exercised the failed-stop path, and a graceful-stop baseline
requires a grant-provisioned bench boot — follow-up work, named in the
baselines doc.

Environment note: measurements ran over SSH on the dedicated box; no VM was
launched from a macOS session. Bench state dirs were removed from the box
after the series.

## Validation

- 19 `runtime_boot_bench` unit tests pass locally; the live series passed
  all five repetitions within the (deliberately loose) 15 s smoke budget.
- Full battery on the branch — fmt, workspace clippy, workspace tests,
  doctests, repository gates, `just check-gated` — recorded on the PR.

Not claimed: exit/graceful-stop latency (blocked as above), other backends'
live numbers, and any telemetry behavior — this slice measures and records.
W1 is complete except the graceful-stop follow-up folded into the finding
above; do not close #3420 or #3419 without maintainer review of that
disposition.

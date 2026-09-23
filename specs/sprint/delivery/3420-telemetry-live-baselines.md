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
- This is the CI boot-latency lane's own baseline (debug-profile harness,
  published dm-verity image + runtime overlay, agent-ready endpoint), **not**
  the 200/250/300 ms prepared-cold dispatch-window gate — that gate is
  measured by the release-profile launch harness, and its latest live
  acceptance on the same CPU was 171.5 ms p50, inside budget
  (`specs/sprint/delivery/2574-firecracker-readiness-retry-floor.md`). The
  baselines doc's "Relation to the launch contract" section itemizes every
  input that differs. Nothing here records a launch-contract regression.
- These numbers are pre-feature by construction: W3/W4 are unlanded, so no
  telemetry hook, handshake, or connection wait exists on any measured path,
  and the plan's nonblocking section now states that boot readiness never
  gates on telemetry connecting.
- The harness change (`tests/runtime_boot_bench.rs`) times the stop the
  bench already performs and prints an informational distribution beside the
  boot summary; failed stops are counted, never folded into percentiles, and
  the budget gate stays about boot. Nineteen harness tests pass.

The exit half is a finding, not a number: **all 165 stops failed the
graceful path** — the stop-time flush verb (`sleep-prep`) is refused with
`VerbNotAuthorized` because every backend boots guests under
`mvm.require_grant=1` and a raw bench `backend.start` provisions no signed
verb grant. No VMM processes leaked (the error path still kills), and the
refusal reproduces 100% — a pre-existing steady state the harness made
visible by timing the stop it always performed, not a new failure.
Consequences recorded: CI's boot-latency lane has only ever exercised the
failed-stop path, and a graceful-stop baseline requires a
grant-provisioned bench boot — filed as
[#3637](https://github.com/tinylabscom/mvm/issues/3637).

Environment note: measurements ran over SSH on the dedicated box; no VM was
launched from a macOS session. That is a controlled-variable choice, not a
scope statement about macOS: baseline numbers are comparable only within
one hardware descriptor, and a developer laptop under interactive load is
not a bench host. The per-backend launch-contract gate (200/250/300 ms
prepared-cold) is unaffected — it is enforced by its own release-profile
lanes per backend, not by this bench. Live boot-bench baselines for the
macOS backends (HVF, libkrun) need an equivalent dedicated macOS bench
host and are named as future hardware-lane work in the plan. Bench state
dirs were removed from the box after the series.

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

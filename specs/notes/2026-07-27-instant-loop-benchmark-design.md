# Instant-loop benchmark — design

Date: 2026-07-27
Status: Design (approved for spec write)
Slice: 1 of the "mvm feels instant" umbrella

## Why

"Working with a microVM should add no perceptible latency." That is a single
product property with three cost budgets that compound in one real session:

- A — start: `run` to workload executing.
- B — interaction: the round-trip of working with a *running* VM (`exec`,
  `invoke`, `fs`, console) over the vsock data plane.
- C — density: memory per guest, i.e. how cheaply N coexist.

The anchor workflow is the interactive dev loop (edit → run → observe), because
it exercises A and B on every iteration, so making it feel instant necessarily
advances both. Agent fan-out is that same start path at concurrency N, bounded
by C. A long-lived session is the loop minus repeated start. Anchoring on the
dev loop subsumes the others without dropping any.

The governing rule is measure before optimize. Two of the three budgets already
have measurement; one does not:

- A has cold-boot measurement (the existing launch benchmark harness) plus
  per-run seam timing behind `MVM_PHASE_TIMING=1`
  (`crates/mvm-cli/src/commands/vm/phase_timing.rs`).
- C has the existing density benchmark.
- B has never been measured. There is a metric for the vsock *handshake* RTT
  (`mvm_core::observability::metrics::vsock_handshake_rtt_ms`) but no per-RPC,
  post-handshake latency anywhere. You cannot tune what you have not measured,
  and "feels instant" with no number is how this class of goal quietly fails.

A second fact reshapes the slice. The warm-start path is not in `main`:
`microvm/snapshot.rs::warm_restore_instance_from_path` is hard-disabled
(`bail!`), `machine revert/rewind/advance` are cold re-admits, and the warm
standby pool is fail-closed `Unsupported` on every CLI-selectable backend (the
selectable libkrun runner masks the raw shim's `standby_pool: true` at
`crates/mvm-runtime/src/driver/libkrun.rs`). The warm-start work lives in
unmerged draft branches. So this slice does not "unblock the warm number"
directly; it establishes the baselines the warm work will be measured against
and the regression gate that will later prove warm beats cold.

## Where benchmarking belongs: a dev/CI gate, not a user verb

Benchmarking microVM latency is not an end-user action. The end-user value of
"feels instant" is that it *is* instant, not that a user can measure it.
Measuring and gating it is our job, the same role the security-claim witnesses
already play. This also matches the direction the CLI already trends —
`security` was folded into `doctor`, `mvmctl dev` was dropped; the surface
shrinks rather than accreting diagnostic verbs.

So this work removes benchmarking from the shipped CLI and relocates it to the
dev/test side, modelled on the claim → witness → CI-gate pattern the repo runs
on: "feels instant" becomes a measured property with budgets, gated in CI,
sitting alongside the security-claim suites.

One constraint forces the exact placement. The cucumber conformance crate
(`crates/mvm-conformance`) is black-box: it runs Gherkin scenarios against the
real `mvmctl` binary and is "not a dependency of any shipped crate"
(`cargo tree -p mvm-conformance -e no-dev` must stay empty). The interaction
measurement must *link* real code — boot a backend and speak vsock RPC — which a
binary-only scenario cannot do once the CLI verb is gone. Therefore the
measurement harness lives as a **feature-gated Rust integration test that links
the backends directly** (dev-only, CI-run), reusing the relocated harness
library. A cucumber `.feature` witness on top remains possible but needs a
dev-only non-shipped entry point to drive; it is out of scope for this slice
(YAGNI) and recorded as a follow-up.

## Goal

1. Remove the user-facing `ops bench` surface and relocate its harness out of
   the CLI command tree into a test-support library.
2. Add the interaction (B) baseline — the number nobody has today: cold RPC and
   warm RPC round-trips — to that harness.
3. Drive the whole thing from a feature-gated integration test that asserts
   within-budget and regression-gates against a committed baseline.

## Non-goals

- No fabricated warm-start number. There is no warm path in `main`; the start
  half is cold-boot only. A `warm_start_ms` field stays absent until a warm path
  lands, at which point warm-start drops in as a second probe.
- No console byte-pipe timing. The console data channel is an unframed raw pipe
  (`crates/mvm-agentd/src/console.rs`) with no request/response boundary, so it
  yields echo latency, not a decodable RTT. The RPC control plane (`Ping`) is
  the representative "working with it" round-trip shared by `exec`/`invoke`/`fs`.
- No new percentile/stats library, no new report/regression machinery — the
  relocated harness carries the only such helpers in the workspace.
- No user-facing verb of any kind. This is a dev/CI gate.

## Scope of the CLI removal

Remove the benchmarking verb only, not the whole `ops` group. The `ops` group
also dispatches `metrics`, `config`, and `mcp`, and the `ops/` module namespaces
unrelated top-level commands (`network`, `cache`, `secret`, `reconcile`, …);
none of those are benchmarking and none are touched. (If the whole `ops` group
should be reconsidered, that is a separate, larger audit — flagged, not done
here.)

Concretely:

- Delete the `OpsCmd::Bench` variant, its dispatch arm, and the `bench` args in
  `crates/mvm-cli/src/commands/ops/group.rs`.
- Relocate the reusable harness — `commands/ops/bench/{harness,probes,stats,
  report,regression,mod}.rs` and `commands/ops/bench_probe.rs` — into a
  test-support library location outside the command tree (exact crate/module
  decided in the plan), preserving the `libkrun-live` / hvf / firecracker
  feature gating.
- Sweep the fallout of removing a verb: CLI help-text snapshot tests
  (`crates/mvm-cli/tests/cli.rs`, the `s0_cli` suite), the CLI command reference
  doc, and any `ops bench` mention. No shipped behavior other than the removed
  verb changes.

## Design

### Measurement model

Start (cold, reuse). The existing `LaunchProbe` implementations and
`boot_measure_once` already admit through the real signed-plan path and record
`IterationTiming { start_to_pid_ms, pid_to_connect_ms, handshake_ms,
total_ready_ms }`. Reused verbatim for the start half — no second boot path.

Interaction (new). Against one already-booted VM:

- Cold RPC: dial `runtime/v.sock` port 5252, run the three-frame authenticated
  handshake, issue one `Ping` → `Pong` — the first-interaction cost (dial +
  ECDH/Ed25519 handshake + one encrypted round-trip). Repeated over a small set
  of fresh sessions (default 10) and reported as the median, since one dial is
  noise.
- Warm RPC: hold one `ControlSession` (`crates/mvm-agentd/src/vsock/rpc.rs`)
  open and issue N sequential `Ping` → `Pong` via `call_unary`, timing each
  `write` → `read` pair. This is the steady-interaction cost — the number the
  budget is set against.

`GuestRequest::Ping` (`crates/mvm-agentd/src/vsock/request.rs`) is the correct
instrument: its handler is a bare `GuestResponse::Pong` constructor
(`bin/mvm-guest-agent/handlers.rs::handle_ping`) with no lock, I/O, or state
mutation, and it is a baseline verb answered even by a trust-restricted agent,
so measurement does not depend on grant state.

### Architecture

A new `InteractionProbe` trait mirrors the existing `LaunchProbe`:

```
trait InteractionProbe {
    fn measure_rtts(&self, cfg: &InteractionRunCfg) -> Result<InteractionTimings>;
}
```

It measures over an already-booted VM handle and is backend-agnostic — it speaks
only vsock RPC, so FC, HVF, and libkrun are measured through the identical code
path. That is a deliberate property: interaction latency becomes a clean
cross-backend comparison, unlike start, which is per-VMM.

The measurement run composes existing units plus the one new probe:

1. Boot-and-hold one VM via the existing `HeldProbeVm` (RAII teardown).
2. Capture the start marks the boot already emits.
3. Run `InteractionProbe::measure_rtts` against the held session.
4. Aggregate with the existing `percentile` / `summarize` helpers.
5. Emit via the existing report + regression machinery.

The warm-RPC timer wraps `ControlSession::call_unary` from the outside — the
harness owns the session and times around the call. No edit to the shared
`rpc.rs` hot path; measurement stays external to the code under test.

### Data types

```
struct InteractionTimings {         // raw samples, ms
    cold_rtt_ms: Vec<f64>,          // M fresh dial+handshake+ping (median reported)
    warm_rtt_ms: Vec<f64>,          // N pings over the held session
}

struct InstantLoopReport {          // serde, schema-versioned
    schema_version: u32,
    host_descriptor: HostDescriptor,        // reused
    hypervisor: String,
    start: LaunchStats,                     // reused shape (cold boot)
    interaction_cold_rtt_ms: f64,           // median of cold_rtt_ms
    interaction_warm_rtt: TailLatencyStats, // reused {p50,p95,p99}
    interaction_verdict: SloVerdict,        // warm p50 vs budget
}
```

`TailLatencyStats` and `HostDescriptor` are reused from the relocated report
module; `LaunchStats` reuses the existing launch report shape. `SloVerdict`
records the warm p50, the active budget, and pass/fail.

### Invocation (test/CI, no user surface)

The measurement is driven by a feature-gated integration test, not a CLI verb.
Recommended home (plan to confirm): keep the relocated harness inside `mvm-cli`
as a non-command library module and put the gate at
`crates/mvm-cli/tests/instant_loop.rs`, since the existing probes already link
`LibkrunBackend` and the vsock API from within `mvm-cli` behind `libkrun-live` —
the least-churn move that keeps the harness where its backend wiring already is.
Run configuration that was CLI flags becomes test/CI configuration:

- backend under test — selected per feature (`libkrun-live` / hvf / firecracker)
  as the existing probes already are.
- sample counts — constants with env overrides in the harness (`warm` default
  200, `warmup` default 20, `cold-samples` default 10).
- report artifact — written to a CI artifact path (or `~/.mvm/bench/` locally),
  same JSON schema as today.
- regression gate — a committed baseline fixture; the test fails if warm p50
  regresses beyond tolerance, reusing the existing regression comparison.

### Budgets and verdict

Start (cold): informational baseline this slice, no pass/fail. `DISPATCH_BAR_MS =
200` already exists for the dispatch window and is reported for reference.

Interaction (warm p50): the budget is a local-vsock encrypted round-trip —
UDS round-trip + AES-256-GCM encrypt/sign/decrypt/verify + serde. The working
hypothesis is warm-RPC p50 ≤ 2 ms, p99 ≤ 5 ms; the first clean baseline confirms
or resets it. Threshold-setting rule, so the number is derived not guessed: take
the first clean baseline's p99, round up to the next whole millisecond, adopt as
the committed baseline, then ratchet down as optimizations land. The verdict is
recorded from run one; it is soft (recorded, not failing the test) until the
first baseline is captured, then wired into the regression gate.

### Where it runs

The interaction half needs only a cold-booted VM, so it runs today, locally, on
HVF and libkrun on Apple Silicon and on Firecracker on the KVM box — no warm
path, no box-only dependency for the B baseline. The start half reuses the
existing live probes.

## Testing

- Unit: `InteractionProbe` aggregation over synthetic samples (deterministic);
  `InstantLoopReport` serde roundtrip; `SloVerdict` boundary at/below/above
  budget; regression compare against a fixture baseline. These are pure and run
  without a backend.
- Live (feature-gated integration test — the gate itself): boot one VM, run N
  `Ping` RTTs, assert non-empty stats and warm-RPC p50 < cold-RPC (handshake
  amortized), assert within budget / regression tolerance; reuse the existing
  `assert_*_bench_cleanup` teardown assertions.

## Phasing

1. Relocate the existing bench harness out of the command tree and delete the
   `ops bench` verb; sweep help-text tests and docs. Behavior preserved as a
   test-invocable library; no measurement change.
2. Add `InteractionProbe` + the instant-loop measurement and the feature-gated
   integration-test gate with a committed baseline.

## How this extends

- When the warm-start path lands, add a second start probe (warm) to the same
  harness; the regression gate then enforces warm < cold as a CI number rather
  than a claim.
- Density folds in later as a third section of one "instant" report, so a single
  gate covers A + B + C.
- Interaction under concurrency (the fan-out workflow) reuses the existing
  concurrent-wave pattern with the interaction probe.

## Deferred follow-ups

- Warm-start probe wiring — gated on the warm path merging to `main`.
- Promote per-RPC interaction latency to a runtime observability metric, as the
  handshake RTT already is, so "feels instant" is watched continuously and not
  only at gate time.
- Optional cucumber `.feature` witness for claim-style visibility, driven by a
  dev-only non-shipped entry point.
- Unified A+B+C "instant" gate; concurrent-interaction measurement.

# Benchmark plan — sub-second startup and eager copy-on-write restore

**Status:** Proposed
**Date:** 2026-06-27
**Owner:** mvm
**Relates to:** [Plan 214](../plans/214-clean-replacement-architecture.md),
[Plan 212](../plans/212-subsecond-machine-run.md),
[ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md),
[Research note](../research/clean-replacement-architecture-review.md)

Sub-second startup is a hard requirement, not an aspiration. This plan makes it
measurable and gateable so "sub-second" cannot stay vague. It defines the latency
classes, the targets, what is measured, how it is measured, and the acceptance
gates that block a regression.

## Latency classes

```
cold path:   deterministic, may be slower (first build / first boot)
warm path:   sub-second, hard requirement
hot/warm-pool path: feels instant (claim or restore from a resident pool)
```

The cold path is allowed to be slow because it is deterministic (build inside the
isolated builder microVM, content-addressed). The warm and hot paths are the
gated ones.

## Targets

```
ephemeral warm run to process start:        < 1 second
interactive warm shell attach:              < 1 second
warm restore p95 (backend permitting):      < 250 ms
warm restore p99:                           bounded; recorded after spike, then gated
egress broker connection setup:             minimal, measured (target < 20 ms p95)
```

"Backend permitting" means: Linux KVM and the raw-hypervisor macOS backend are
expected to meet the 250 ms restore p95; the high-level macOS framework's coarse
save/restore is exempt from the sub-100 ms / 250 ms restore targets
([ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md)) and is measured for
reference only. If the spike shows a target is not yet realistic on a given
backend, the target for that backend is set from the spike's measured floor plus a
stated margin, and that floor is recorded here.

## What is measured

For each run, capture the timeline by lifecycle marker
(`BOOTED → MOUNTS_READY → METADATA_READY → SECRETS_READY → PRE_EXEC →
WORKLOAD_STARTED → READY → WORKLOAD_EXITED`) so latency is attributable to a stage,
not a single opaque number. Readiness is observed from markers and probes, never
from a sleep.

Per scenario:

- ephemeral warm run: time from `machine run` invocation to `WORKLOAD_STARTED`
- interactive warm shell attach: time from `machine shell` to first PTY byte
- warm restore: time from claim/restore request to vCPU run, broken into validate /
  map / restore-state / run
- hot reuse (skip-restore-on-release): time from claim to first byte on a hot-held
  guest that was *not* restored — the throughput lever for hot-cache workloads;
  recorded as a speedup ratio against the restore-each-time path
- warmup-baked vs. cold-cache restore: same-workload latency for a snapshot captured
  at `snapshot_at = AFTER_WARMUP` vs. a snapshot with a cold page cache
- egress broker connection setup: time from guest connect to first byte through the
  broker

Memory, per warm sibling and per pool:

- resident RSS
- private dirty
- shared clean
- cow_shared_estimate
- restore_inflight count
- configured vs. charged vs. measured (the resident-memory accountant's view)

Restore distribution: p50 / p95 / p99 over a fixed sample size per backend.

Snapshot-cache storage:

- on-disk bytes for N sibling snapshots derived from one base, reflink (`clonefile`/
  `FICLONE`) vs. plain-copy fallback — confirms derive-from-sibling stays cheap as
  warm-pool density grows.

## How it is measured

- A repeatable benchmark harness under the workspace (a bench binary / xtask
  subcommand) that drives the `Machine` library directly, not the CLI, so CLI
  formatting is excluded from the timing.
- Marker timestamps come from `mvm-init`'s lifecycle markers over the vsock control
  channel; the host stamps receipt time.
- Memory figures come from the resident-memory accountant's measurement path
  (RSS / footprint), the same source the warm-pool admission uses, so the benchmark
  and the scheduler agree.
- Each scenario runs a warm-up set (discarded) then the measured set; sample size
  is fixed per backend and recorded with the results.
- Randomness/host noise is controlled by pinning the backend, the image digest, and
  the resource shape; results are tagged with host id and backend id.

## Backends measured

Per the [research note](../research/clean-replacement-architecture-review.md)
decision matrix:

- Linux KVM (direct): primary eager-CoW restore target — full restore gates
- raw-hypervisor macOS backend (when the ADR-098 spike lands): full restore gates
- high-level macOS framework: reference only for restore; gated for warm run /
  shell attach
- third-party in-process VMM: warm run / shell attach gates; restore gated only if
  the spike shows it can map guest memory
- Firecracker: warm run / shell attach gates; restore measured against its existing
  path
- QEMU (dev/test): excluded from warm-restore gates

## Acceptance gates

A change that touches the boot, restore, networking, or warm-pool path must keep
these green (measured by the harness, recorded in the results file):

1. ephemeral warm run to `WORKLOAD_STARTED` < 1 s on every gated backend
2. interactive warm shell attach to first PTY byte < 1 s on every gated backend
3. warm restore p95 < 250 ms on Linux KVM and the raw-hypervisor macOS backend (or
   the recorded spike floor + margin, whichever is the agreed target)
4. warm restore p99 within the recorded bound for the backend
5. egress broker connection setup p95 < 20 ms (or the recorded floor + margin)
6. resident-memory accountant: measured warm-sibling RSS within the learned charge
   + safety margin (no admission that exceeds the host budget; forward-progress
   timeout fires rather than deadlocking)
7. no sleep-based readiness anywhere on the measured path

A regression past a gate blocks the change. If a target is intentionally relaxed
for a backend, the new floor and the reason are recorded in the results file in the
same change.

## Spike-driven calibration

Before gates 3–5 are enforced, the [Plan 214](../plans/214-clean-replacement-architecture.md)
Phase 9 (eager-CoW) and Phase 11 (raw-hypervisor) spikes run this harness to
establish the measured floor on each backend. The spike output sets the initial
gate values; subsequent changes are gated against them. The spike also records, per
backend, whether eager CoW is feasible (can map a file-backed region as guest RAM)
and the fixed-address remap result — feeding the eager-CoW-vs-userfaultfd decision.

## Results recording

Benchmark runs append to a results file under `specs/perf/` tagged with date,
host id, backend id, image digest, resource shape, sample size, and the full
metric set above. The file is the source of truth for the current gate values; a
target change is a change to that file plus the gate rationale.

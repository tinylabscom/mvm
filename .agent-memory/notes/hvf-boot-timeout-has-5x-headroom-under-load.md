---
title: The 5s HVF PID-file timeout has ~5x headroom even at load 45 — do not raise it
date: 2026-09-02
tags: [hvf, boot-latency, timeout, falsification, measurement]
---

`PID_FILE_TIMEOUT` for HVF is a hardcoded `Duration::from_secs(5)`
(`crates/mvm-backends/src/driver/hvf_process.rs`), with no env override, against
QEMU's 10s. A workload boot failed once with `hvf supervisor did not confirm
boot within 5s` on a machine at load 40, which made the ceiling look marginal
and the asymmetry with QEMU look like a bug.

**It is not.** 12 consecutive `machine run --image rust` boots on an
Apple Silicon host at load 40–47 (Cursor, a local model server, a rustc, and
Spotlight indexing — an ordinary working desktop), measuring the
`backend_start` phase that contains the supervisor spawn and the PID-file wait:

| | backend_start |
|---|---|
| min | 167 ms |
| median | ~250 ms |
| mean | 327 ms |
| max | 1017 ms |

12/12 succeeded. Worst observed sample used **20% of the budget** — 4.9x
headroom — at a load *higher* than the one where the failure happened. Raising
the ceiling or making it tunable would buy nothing measurable.

Reproduce with `MVM_PHASE_TIMING=1` and read `backend_start=` off the
`phase-timing:` line. `MVM_LAUNCH_SAMPLE_JSON` writes the same data as JSON.

## What the single failure probably was

Not steady-state load: that is what the table above was measured under. The one
plausible correlate is a *burst* — five VM state dirs (`w-dev-console`,
`w-policy`, `w-raw`, `w-sealed`, `w-wire`) appeared in `~/.mvm/vms` at the same
minute, so another session was creating five guests at once. A concurrent
multi-guest burst is a different load shape from a high load average, and it is
the one shape this measurement does not cover.

If this recurs, measure during a burst before touching the constant. Do not
infer a systematic problem from a boot failure on a loaded machine — steady
load is not the cause, and this table is the evidence.

## Two other refuted explanations

Both were plausible and both are wrong, so do not spend time on them again:

- **"A debug-profile supervisor is too slow to boot in 5s."** A debug supervisor
  boots fine; the samples above are all against a debug build.
- **"First launch of a freshly built supervisor spends the budget on
  `codesign --force` and the re-exec."** Forced a fresh unsigned rebuild and the
  first boot took 2.8s wall, well inside the window. The self-signing path is
  not expensive enough to matter.

## Incidental

Every sample reported `launch_mode=cold`. A warm claim skips the fresh
supervisor spawn entirely, so warm and cold boots are different populations and
must not be pooled when measuring anything about this timeout.

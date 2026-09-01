---
title: The prepared_cold 200ms budget covers backend_start + vsock_wait only — admit, teardown and command are all out of scope
date: 2026-08-26
tags: [perf, launch-budget, benchmarks, scope]
---

`RunPhaseTimings::dispatch_window_ms()`
(`crates/mvm-cli/src/commands/vm/phase_timing.rs`) is
**`backend_start_ms + vsock_wait_ms`, nothing else**. That is the entire
quantity `LaunchLane::PreparedCold` budgets: p50 200ms / p95 250ms / p99 300ms,
plus `PREPARED_COLD_HARD_MAX_MS`, which requires every single boot to come in
strictly under 200ms.

**Out of scope entirely:** `admit_ms`, `warm_window_ms`, `command_ms`,
`teardown_ms`, `resolve_ms`, `drives_ms`. The doc comment reads
"admitted-plan to command-dispatch", and the window *starts after* admission —
so a 346ms `admit_ms` does not fail the lane, and neither does a 12.7s
`teardown_ms`.

Read a sample with that in mind: `warm_window_ms` is approximately
`backend_start_ms + vsock_wait_ms`, so warm_window is effectively the dispatch
window under another name.

Separately from the budget, a lane refuses a sample outright when
`work.performed()` includes any of `image_pull`, `image_build`,
`mount_materialize`, `warm_claim`, `artifact_hash`, `process_table_scan`. That
is a **validity** gate, not a budget: a launch can be comfortably under 200ms
and still produce no number at all, which reads like a missing measurement
rather than a rejected one.

The practical consequence is that "prepared_cold is green" is a much narrower
statement than "launch is fast", and quoting it as the latter overstates it.

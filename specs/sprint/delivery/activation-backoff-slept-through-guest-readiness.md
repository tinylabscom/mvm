# The activation backoff slept through the guest being ready

**Status: COMPLETE**

## What was wrong

`activate_workload` retries the connect+handshake to the guest agent until it
answers. The gap between attempts was:

```rust
fn activation_retry_delay(attempt: u32) -> Duration {
    let scaled = 50u64.saturating_mul(1u64 << attempt.min(16));
    Duration::from_millis(scaled.min(500))   // 100ms, 200ms, 400ms, 500ms...
}
```

The first gap was 100 ms. The event it polls for — the guest agent binding its
control port — happens ~50 ms after the VM starts. So every launch took the
same shape:

```
attempt 1  tried_at=0ms     failed_after=48-52ms   sleeping=100ms
attempt 2  tried_at=151ms   took=6-11ms            total=159-162ms
```

~8 ms of activation work inside a ~160 ms span, and ~100 ms of it was a sleep
through a readiness that had already happened. A backoff coarser than the event
it waits for does not measure that event, it replaces it.

## What changed

The schedule now doubles from 2 ms to a 25 ms cap (`ACTIVATION_POLL_MIN` /
`ACTIVATION_POLL_MAX`). Nothing else about the loop moved: the same 30 s
deadline, the same retryable-error set, and a genuine rejection
(`ActivateEnvironmentError` or an unexpected response) still returns
immediately and is never retried.

The success path gained one `tracing::debug!` splitting the span into waited
vs. activated. The coarse phase timer reports a single `activate_workload`
number and cannot tell "the guest was slow" from "the schedule slept through
the guest being ready" — which is how a 100 ms first backoff hid inside a
160 ms span for as long as it did.

Two doc comments were corrected. Both said the agent "takes a few seconds" to
come up; measured, it takes ~50 ms. That estimate is what made a 100 ms first
gap look reasonable.

## Measured

Same host, `machine run --image alpine -- sh -c "echo hi"`, HVF:

| | before | after |
|---|---|---|
| `activate_workload` | 159–162 ms | **60–68 ms** |
| `backend start` | 173–175 ms | **77–85 ms** |
| **dispatch window** | 174–175 ms | **78–85 ms** |
| total | 289–290 ms | **209–228 ms** |

`PREPARED_COLD_HARD_MAX_MS` is 200 ms on the dispatch window, as a per-sample
invariant. That went from 175 ms — passing with 25 ms of margin — to ~80 ms.

The remaining `activate_workload` is close to its floor: attempt 2 now fires at
t≈53–59 ms because attempt 1 fails at ~50 ms and the new gap is 2 ms. That
~50 ms is the guest agent genuinely coming up, and ~8 ms is the activation
round-trip. There is no longer meaningful slack in this phase.

## Still open

- **Total is ~220 ms, not under 200 ms.** The dispatch window is what the
  repo's 200 ms budget measures and that is comfortably met; total wall clock
  is not, and needs the two below.
- `admit` is 65–68 ms and **rising** — it was 56 ms earlier the same day. The
  attested-prefix fast path still reads all segment bytes and builds the tree
  over every leaf twice, so it grows with history. Caching sealed segments'
  leaf hashes, validated by recomputing the signed root from them, would make
  publication `O(entries since the last root)` and take this to ~5 ms.
- `teardown` is 49–59 ms, most of it the supervisor genuinely shutting down
  (kqueue-observed, not a polling artifact). Only removable by not waiting for
  it, which trades against the exit-capture flush.
- **The first launch after a release build is reliably an outlier** —
  `backend start` 570–902 ms and, once, a 74 s admission. Four occurrences now,
  always the first run against a freshly linked binary, all phases affected.
  Not root-caused. Discard the first sample when benchmarking.

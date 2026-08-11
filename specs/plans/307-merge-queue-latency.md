# Plan 307 — Merge-queue latency

**Status: COMPLETE** — all five workstreams landed. WS2 was applied by a
maintainer on 2026-08-10 and verified against the live ruleset; the rest are
in `main`.

## Why

On 2026-08-08 the merge queue stopped merging for roughly four hours with ten
entries waiting. The investigation is worth writing down, because the visible
symptom pointed at the wrong cause and the wrong cause has an expensive fix.

What it looked like: runner starvation. Thirteen workflow runs queued against
three executing, queue-head entries sitting in `AWAITING_CHECKS` for hours. The
tempting conclusion is "buy more runners".

What it was: **one PR at queue position 1 failing a policy gate**. `#2232`
carried a `check-no-vz` violation — a doc comment naming the retired backend,
which the gate added in #2235 forbids. The merge queue validates entries in
batches built on top of each other, so every batch inherited the failure,
`Lint policy` went red, the batch was discarded, `merge-queue-requeue.yml` put
the entry back, and the cycle repeated. Starvation was real but secondary: the
queue was converting runner time into nothing at a steady rate.

The generalisable lesson: **in a serial queue, a bad head entry is
indistinguishable from a slow queue.** Both present as "nothing merges". The
distinguishing evidence is per-entry check state on the `gh-readonly-queue/**`
branches, not the queue's own position/state display, which shows
`AWAITING_CHECKS` in both cases.

## Workstreams

- [x] **WS0 — unjam.** Fixed the `check-no-vz` violation on #2232 directly and
      dequeued/re-pushed it. One line. Nothing else in the queue was wrong.

- [x] **WS1 — a required check that cannot report is a 90-minute tax.**
      Landed as **#2252**, independently authored — not duplicated here.
      `kernel-build.yml` now carries the `merge_group` trigger, so the required
      contexts report instead of being absent. Previously it had no such
      trigger and was
      `paths:`-filtered, so on any PR not touching kernel paths the required
      `Build kernels (aarch64|x86_64)` contexts were simply *absent*. An absent
      required check leaves the entry waiting out
      `check_response_timeout_minutes: 90` before ejection. #2252 moves the
      filter off the trigger into a `scope` job that always reports. This plan
      records the interaction and defers to that PR.

- [x] **WS2 — the queue merges one PR per validation cycle.**
      The ruleset had `min_entries_to_merge: 1` with
      `min_entries_to_merge_wait_minutes: 0`, so a batch shipped the instant one
      entry was green and never accumulated — despite `max_entries_to_merge: 5`.
      Every PR therefore paid a full validation cycle (~30 min of CI plus two
      kernel builds at 15–30 min each) alone.

      **Applied 2026-08-10 by a maintainer.** This is repo configuration rather
      than code, so it could not be scripted from here — the write was refused
      by the local permission policy. The edit, against ruleset `17624371`
      (`main merge queue`, whose only rule is `merge_queue` — required status
      checks live in classic branch protection and were untouched):

      ```
      min_entries_to_merge:              1 -> 3
      min_entries_to_merge_wait_minutes: 0 -> 5
      ```

      Verified live afterwards: `min_entries_to_merge=3`,
      `min_entries_to_merge_wait_minutes=5`, with `merge_method`,
      `grouping_strategy`, `max_entries_to_build`, `max_entries_to_merge` and
      `check_response_timeout_minutes` unchanged — the PUT replaces the whole
      rules array, so confirming the untouched fields is part of the check. The
      queue was observed batching five entries shortly after.

      **Expect a pause, not a stall.** With a minimum of 3, a queue holding
      fewer than that now waits up to five minutes for another entry. That
      wait is the feature; it is also the shape a jammed queue has, so check
      `min_entries_to_merge` before diagnosing a stall.

      A quiet period then costs at most five extra minutes; a busy one
      amortises one validation cycle across up to five PRs
      (`max_entries_to_merge` is already 5). Revert by setting them back to
      `1` and `0`.

      This trades against `grouping_strategy: ALLGREEN`, under which one bad
      entry discards the whole batch — bigger batches mean a flake costs more,
      which is why WS3 is sequenced first.

- [x] **WS3 — flaky tests are unusually expensive under ALLGREEN.**
      A flake does not merely retry a job; it discards a batch and burns
      another full validation cycle for every entry in it. `#2246`
      (`a_holder_that_stops_refreshing_loses_the_lease`, a 20 ms lease TTL
      against a 40 ms sleep) already cost one red queue run. Fix the timing
      dependence rather than widening the margin: the property under test is
      that an expiry exists and is enforced, which does not need real time.

- [x] **WS4 — auto-requeue re-queues entries that cannot merge.**
      `merge-queue-requeue.yml` decides whether an ejection was transient by
      reading `mergeable` / `mergeable_state`, which are computed against
      **`main`** — not against the batch the entry was being validated in. An
      entry that conflicts with another *queue member* reads as clean and gets
      requeued, where it conflicts again. Observed live: #2249 conflicts with
      #2251 in `crates/mvm-client/src/audit/normalize.rs`, is clean against
      `main`, and was requeued after a manual dequeue.

      Each such cycle costs a full validation run. Proposal: when an entry is
      ejected and its own head is unchanged since the last ejection, require a
      distinct signal before requeuing rather than treating "clean against
      main" as proof the ejection was transient.

## Not doing

**Buying runners.** Capacity is not the binding constraint while a poisoned
head entry can consume the pool indefinitely, and WS1–WS4 reduce demand rather
than raise supply. Revisit only with WS1–WS4 landed and evidence of queue
latency that is not explained by them.

**`max_entries_to_build: 4` → lower.** It multiplies concurrent runner demand,
but lowering it also lowers throughput once the queue is healthy. No change
until WS2 is measured.

**Superseded 2026-08-11 by Plan 316.** The measurement arrived as a production
timeout loop: four speculative groups plus ordinary pull-request and manual
work delayed successful required checks past the 90-minute response timeout.
Auto-requeue then repeated the unchanged work while invalidated runs continued
consuming runners. The live ruleset now builds two speculative entries, permits
immediate one-entry progress, and waits up to 240 minutes for checks. Timeout
ejections are no longer automatically requeued at the unchanged commit.

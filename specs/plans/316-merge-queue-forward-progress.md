# Plan 316 — Merge-queue forward progress

**Status:** Complete.

## Goal

Make runner congestion degrade queue latency without turning into an
unbounded timeout/requeue loop that prevents every pull request from merging.
Exact merge-commit validation and all required checks remain intact.

## Incident evidence

On 2026-08-11 the queue held twelve pull requests and stopped landing changes
after 17:36 UTC. The live ruleset built four speculative entries, required a
minimum batch of three, and discarded an entry when checks had not reported in
90 minutes. Each speculative merge-group commit emitted roughly ten CI jobs in
addition to kernel and architecture jobs.

The bottleneck was runner admission rather than failing validation. PR #2344
was removed with `checks_timed_out` at 18:47 UTC; its CI completed successfully
at 19:03. The auto-requeue workflow immediately put the unchanged commit back.
PR #2339 then followed the same pattern: timeout removal at 20:20 and successful
CI completion at 20:29. Downstream speculative runs continued consuming runners
after their synthetic commits had been invalidated, so every automatic retry
increased the work competing with the valid queue head.

## Work

- [x] Read the live merge queue, ruleset, dequeue reasons, check runs, job
      admission times, and recent merge history to distinguish failure from
      runner starvation.
- [x] Apply and read back capacity-safe live settings: speculative build
      concurrency `4 -> 2`, minimum merge batch `3 -> 1`, minimum wait
      `5 -> 0` minutes, and check-response timeout `90 -> 240` minutes.
- [x] Make `merge-queue-requeue.yml` read the authoritative dequeue reason and
      refuse to automatically requeue `checks_timed_out` at the unchanged
      commit. Preserve the existing bounded retry for other transient
      ejections and the fail-closed conflict handling.
- [x] Add structural regression coverage and validate the workflow with
      `actionlint`, focused workflow tests, formatting, workspace check,
      all-target host Clippy, and the complete serial workspace test suite.
- [x] Read back the live ruleset after the write and verify that the queue
      resumed forward progress under the reduced speculative load.

## Safety boundary

The recovery workflow remains a trusted-base `pull_request_target` workflow
that never checks out pull-request code. It keeps its existing permissions and
does not gain `actions: write`; automatic cancellation of in-progress workflow
runs is deliberately excluded because a stale queue snapshot could terminate a
valid run. Forward progress comes from bounded speculation, a timeout above the
measured successful tail, and refusing the automatic same-condition retry.

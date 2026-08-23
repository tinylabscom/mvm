# Security watcher delivery backstop

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2792](https://github.com/tinylabscom/mvm/issues/2792)

## Status

**COMPLETE**

## Problem

The event-driven Security lane watcher can inspect a failed or cancelled run
only when GitHub delivers its `workflow_run` event. A completed scheduled run
on 2026-08-21 produced no watcher run, so the repository needs a separately
scheduled observer of the same evidence.

## Delivery

- [x] Query the latest `schedule` run for each scheduled claim-bearing
      workflow, excluding unrelated pull-request and dispatch runs.
- [x] Require that run to be both fresh for its declared cron and completed
      with conclusion `success`.
- [x] Keep the tracking issue and PR verdict fail-closed for stale, running,
      failed, cancelled, timed-out, or malformed evidence.
- [x] Add focused tests for successful, failed, cancelled, timed-out,
      still-running, absent, stale, and malformed observations.
- [x] Update the scheduled workflow, sprint delivery record, and refactor
      rollup to describe the independent conclusion backstop.

## Validation

- `cargo test -p xtask check_claim_witness_freshness`
- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`


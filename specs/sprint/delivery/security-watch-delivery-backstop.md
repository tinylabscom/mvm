# Security watcher delivery backstop

Issue #2792 established that the Security lane's `workflow_run` event is not a
durable notification: a scheduled run completed as cancelled on 2026-08-21,
but GitHub created no watcher run. The event-driven watcher remains the fast
path, including its delivered-cancellation handling, while the independently
scheduled claim-witness gate is now the reconciliation backstop.

The gate queries only scheduled runs for every scheduled claim-bearing
workflow. It requires the newest observation to be recent enough for the
workflow's cron, in status `completed`, and concluded `success`. A failed,
cancelled, timed-out, or still-running latest nightly therefore opens or
updates the same tracking issue even when no `workflow_run` notification was
delivered. Pull-request and manual-dispatch runs cannot overwrite that
scheduled evidence.

## Validation

- focused unit tests cover success, failure, cancellation, timeout,
  in-progress, absent, stale, and malformed observations
- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`


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

Pull requests validate witness resolution and schedule parsing without reading
mutable Actions history. Only the independent scheduled run enables reporting,
so a nightly that is still running cannot turn an otherwise valid PR red.

## Validation

- focused unit tests cover success, failure, cancellation, timeout,
  in-progress, absent, stale, malformed, and PR-static observations
- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

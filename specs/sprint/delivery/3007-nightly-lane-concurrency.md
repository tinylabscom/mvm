# Nightly lanes stop cancelling themselves

- [x] Repaired the concurrency group on `ci-full.yml`, `security.yml` and
      `miri.yml`. None has a `pull_request` trigger, so `cancel-in-progress`
      could only reach a run already under way; and keying the group on
      `github.ref` grouped the nightly cron together with operator dispatches
      rather than separating them, so each killed the other.
- [x] Reused ci.yml's proven group expression rather than inventing one:
      dispatches key on their own run id, the nightly keeps the ref.
- [x] Added `a_workflow_without_pull_requests_never_cancels_a_run_in_flight`,
      derived from each workflow's trigger list, and verified it fails on the
      exact defect it guards.
- [x] Passed the workflow-structure suite (31 tests) and `check-workflow-paths`.
- [ ] Record the first uninterrupted Extended CI run.
- [ ] Merge the linked pull request through the queue.

Owning plan: `specs/plans/2026-09-04-nightly-lanes-stop-cancelling-themselves.md`.

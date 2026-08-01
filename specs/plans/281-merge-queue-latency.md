# Merge queue latency audit

**Status:** Complete.

**Goal:** Keep exact-merge-commit validation intact while removing avoidable
merge-queue cancellation and measuring the capacity settings that control
queue latency.

## Evidence snapshot

The snapshot was taken on 2026-08-01 UTC from the repository ruleset, classic
branch protection, pull-request timelines, merge-queue entries, Actions runs,
jobs, and one failed run's logs.

- The queue ruleset built five speculative entries. Each entry emitted five
  required GitHub Actions checks, so one full generation created 25 required
  jobs. The repository had no repository-scoped self-hosted runners.
- Across 50 recently merged queue entries, queue-entry-to-merge latency was
  38m26s p50 and 2h14m03s p95. Initial merge-group creation was normally fast
  (18s p50, 3m56s p95), but regenerated groups added as much as 2h04m21s.
- Across 101 jobs from 44 recent completed merge-group workflow runs, runner
  wait was 7m59s p50 and 34m16s p95; job execution was 26m42s p50 and 40m00s
  p95. The sample reached 19 simultaneously running merge-group jobs before
  counting ordinary pull-request work.
- Required CI workflow duration, including runner admission, was 52m07s p50
  and 1h19m05s p95 across 19 completed merge-group CI runs. At the time of the
  measurement, the ruleset's status-check timeout was 60 minutes.
- The required contexts were `Lint (fmt + clippy + policy)`, `Test`,
  `MCP server stdio roundtrip`, `Nix flake check (Linux eval)`, and `Invariant`.
  A successful merge-group commit emitted all five under the GitHub Actions app.
  No third-party check or deployment was required.

## Work

- [x] Make the two required workflows listen explicitly for
  `merge_group: checks_requested`.
- [x] Keep pull-request supersession cancellation while preventing
  merge-group cancellation and manual-run serialization.
- [x] Make the CI workflow's read-only token posture explicit.
- [x] Validate all workflows with `actionlint` and add structural tests for
  required-check names, merge-group triggers, concurrency, and permissions.
- [x] Run repository formatting, check, test, and clippy gates. The host
  workspace suite passed serially; an initial parallel run exposed an existing
  process-environment/socket isolation race in `mvm-runtime`, and the focused
  serial rerun passed all 1,219 active library tests.
- [x] Apply the measured GitHub settings and read them back from the ruleset.
- [x] Record the completed work in `specs/SPRINT.md` and
  `specs/REFACTOR-STATUS.md`.

## Applied GitHub settings

The repository ruleset now keeps squash merging, `ALLGREEN`, minimum group
size 1, maximum group size 5, all five required checks, no bypass actors, and
no required deployments. On 2026-08-01 it changed speculative build
concurrency from 5 to 3, minimum-group wait from 5 minutes to 0, and the check
response timeout from 60 to 90 minutes. Three speculative entries create at
most 15 required jobs with the measured five-check shape, leaving capacity for
ordinary pull-request feedback. The 90-minute timeout is the smallest round
value above the measured 79-minute successful p95 while runner and critical-
path changes roll out.

## Non-goals

- Do not drop, rename, or replace a required check with a skipped compatibility
  job.
- Do not reuse pull-request artifacts as proof for a different merge-group SHA.
- Do not add privileged secrets, `pull_request_target`, or broader workflow
  permissions to the required workflows.

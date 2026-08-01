# Merge queue auto-requeue

**Status:** Complete.

**Goal:** Return transiently ejected pull requests to the merge queue without
executing untrusted code with a privileged token or retrying indefinitely.

## Work

- [x] Handle only the `dequeued` activity type and serialize decisions per PR.
- [x] Refuse closed, merged, draft, and conflicting pull requests.
- [x] Bound automatic retries to two persistent attempts per PR.
- [x] Use a base-ref `pull_request_target` workflow only for GitHub API calls;
  never check out or execute the pull request's code.
- [x] Add structural tests for event scope, permissions, checkout absence,
  conflict handling, persistent retry counting, and auto-merge invocation.
- [x] Validate workflows, formatting, focused tests, workspace check, and
  clippy, then record completion in the sprint and refactor rollup.

## Security posture

The workflow has `contents: read` and `pull-requests: write`, receives only the
repository identifier and numeric PR number from the event, and never checks
out a ref. Its shell code is loaded from the trusted base branch. A per-PR
concurrency key prevents two dequeue events from racing the attempt counter.

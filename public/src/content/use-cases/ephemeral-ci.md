---
title: Give CI jobs a disposable runtime
description: Run build and test workloads in explicit guest environments instead of carrying accidental runtime state between jobs.
team: Platform engineering
outcome: Keep job state intentional
order: 3
guide: /examples/ci-cd-ephemeral-builder/
guideLabel: Set up an ephemeral CI workload
---

## The situation

Your team runs tests for changing dependencies and pull requests. Reusing a runner’s runtime directories can carry files, credentials, or stale state from one job into the next.

## A workflow with mvm

1. Declare the worker environment and build it from reviewed, pinned inputs.
2. Give the CI invocation its own mvm state directory.
3. Run the test task with a timeout and retain the intended build outputs and run receipt as CI artifacts.
4. Clean up runtime guests. Cache verified downloads and trusted build inputs deliberately, not the whole guest state.

For example, a platform team could use the same declared test environment for dependency-update branches while collecting a receipt alongside each job’s test report.

## What your team gains

The runtime and retained artifacts become explicit. A failing job is easier to investigate when the environment definition is versioned and state reuse is a choice rather than a side effect.

## What to plan for

Your CI system still owns job scheduling and artifact retention. Confirm the runner supports the selected backend. Do not expose trusted caches, broad writable host mounts, or deployment credentials to untrusted jobs. Review cleanup commands carefully on shared runners.

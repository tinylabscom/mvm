# Worker restart identity barrier

- [x] Located the race between process-group signaling and worker exit.
- [x] Added an explicit replacement-worker identity barrier before recovery
      assertions.
- [x] Passed the focused regression and all four host-agent restart tests.
- [x] Recorded a green focused restart suite, all ordinary workspace tests,
      isolated `mvm-cli` doctests, workspace Clippy, formatting, and repository
      policy gates.
- [ ] Merge the linked pull request through the queue.

Owning plan: `specs/plans/2026-08-28-worker-restart-identity-barrier.md`.

# Worker restart identity barrier

- [x] Located the race between process-group signaling and worker exit.
- [x] Added an explicit replacement-worker identity barrier before recovery
      assertions.
- [x] Passed the focused regression and all four host-agent restart tests.
- [ ] Record workspace validation after it passes.
- [ ] Merge the linked pull request through the queue.

Owning plan: `specs/plans/2026-08-28-worker-restart-identity-barrier.md`.

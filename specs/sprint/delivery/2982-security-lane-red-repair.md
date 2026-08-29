# Security lane red repair

- [x] Reproduced the scheduled supply-chain and mutation-witness failures.
- [x] Replaced yanked `chacha20 0.10.1` with `0.10.2` and pinned that result
      with a lockfile regression.
- [x] Added a direct libkrun vCPU-capability witness and removed eight stale
      mutation exemptions reported as caught by the Linux Security lane.
- [x] Passed the focused regressions, `cargo deny`, and the static
      mutation-surface gate.
- [x] Pass workspace tests, isolated doctests, workspace Clippy, formatting,
      and repository policy gates.
- [ ] Pass a fresh Security run, including the Linux mutation-witness lane.
- [ ] Merge the linked pull request through the queue.

Owning plan: `specs/plans/2026-08-28-security-lane-red-repair.md`.

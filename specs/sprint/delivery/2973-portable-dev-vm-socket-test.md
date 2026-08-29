# Portable dev-VM socket resolver test

- [x] Reproduced the deterministic macOS Unix-socket path assertion.
- [x] Replaced the state-directory-only expectation with the canonical
      state-or-short socket-directory resolver.
- [x] Passed the focused regression and all 598 `mvm-vmm` tests.
- [x] Passed workspace tests and Clippy; an initial contended doctest compile
      was green on its immediate isolated rerun.
- [ ] Merge the linked pull request through the queue.

Owning plan: `specs/plans/2026-08-28-portable-dev-vm-socket-test.md`.

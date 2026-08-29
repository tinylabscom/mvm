# Extended CI red repair

- [x] Linux no longer enables the macOS-only `libkrun-sys` helper build.
- [x] Both documented-surface jobs install `uv` before the SDK drift witness.
- [x] The live suite explicitly builds the source-matched SDK sidecar once.
- [x] Installed bundle SHA-256 values resolve through the existing
      slot-or-bundle dispatcher and retain fail-closed identity checking.
- [x] The live macOS witness uses the Intel hosted runner instead of the arm64
      environment that returned `HV_UNSUPPORTED`.
- [x] Focused regressions, shared resolver tests, formatting, and package Clippy
      are green.
- [x] Latest-main workspace tests, isolated doctests, workspace Clippy,
      formatting, and repository policy gates are green.
- [ ] A fresh Extended CI witness and merge-queue delivery remain.

Owning plan:
`specs/plans/2026-08-28-extended-ci-red-repair.md`.

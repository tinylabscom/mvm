# Issue #2830 — Extended CI lane repair

- [x] Both macOS lanes trust the third-party Homebrew tap before installing
      `slp/krun/libkrun`; the general Apple lane now installs the library it
      needs before compiling all workspace targets.
- [x] The Linux builder-image lane supplies `mvm-builderd` alongside the other
      manifest-declared host binaries, so Nix evaluation no longer fails on a
      missing impure input.
- [x] Structural tests pin both contracts in `ci-full.yml`.

Owning plan: `specs/plans/2026-08-24-extended-ci-lane-repair.md`.

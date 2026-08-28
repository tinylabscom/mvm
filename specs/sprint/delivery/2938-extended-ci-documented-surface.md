# Extended CI documented-surface repair

- [x] Both scheduled documented-surface jobs build with the `user` surface,
      keeping signed release-manifest verification enabled.
- [x] The macOS HVF witness installs the root binary's target-gated libkrun
      dependency through the shared trusted installer.
- [x] Structural tests refuse verifier bypasses and preserve both prerequisites.

Owning plan:
`specs/plans/2026-08-27-extended-ci-documented-surface.md`.

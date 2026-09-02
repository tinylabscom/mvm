# Extended CI documented-surface repair

- [x] Both scheduled documented-surface jobs build with the `user` surface,
      keeping signed release-manifest verification enabled.
- [x] The macOS HVF witness installs the root binary's target-gated libkrun
      dependency through the shared trusted installer.
- [x] Structural tests refuse verifier bypasses and preserve both prerequisites.
- [x] Post-merge live execution exposed an aws-lc fast-codegen link failure and
      a missing embedded Linux cross target on macOS.
- [x] Signature-verifying builds use Cargo's standard link path, and the macOS
      witness installs the shared cross toolchain before it builds.
- [x] Structural tests preserve both post-merge corrections.
- [x] The explicit published-image choice now reaches builder bootstrap, both
      witnesses compile that download arm, and macOS downloads its workload
      kernel rather than cycling through the unavailable source builder.
- [x] Clean runners build the SDK codegen driver before checking generated SDK
      drift.
- [x] Warm the source-matched SDK sidecar after PR #2954 supplies its Stage 0
      build command.

Owning plan:
`specs/plans/2026-08-27-extended-ci-documented-surface.md`.

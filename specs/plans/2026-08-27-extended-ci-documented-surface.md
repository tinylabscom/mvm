# Extended CI documented-surface repair

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2938](https://github.com/tinylabscom/mvm/issues/2938)

## Outcome

Both scheduled documented-surface jobs build an `mvmctl` that verifies signed
release manifests. The macOS job also installs the target-gated libkrun
dependency required to compile the root binary before exercising HVF.

## Delivery checklist

- [x] Diagnose both failures from Extended CI run 33090455721.
- [x] Add regression coverage for the Linux verifier feature and macOS libkrun
      prerequisite.
- [x] Enable the `user` surface in both documented-surface jobs without any
      signature-verification bypass.
- [x] Reuse the shared, trusted libkrun installer in the macOS job.
- [x] Build the exact `mvmctl --features user` configuration on macOS.
- [x] Pass workflow lint, workspace tests/check, and zero-warning Clippy.
- [x] Record the implementation in the sprint and refactor rollup.
- [ ] Merge the tested pull request and close #2938 through its linkage.

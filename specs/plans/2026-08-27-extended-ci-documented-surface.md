# Extended CI documented-surface repair

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2938](https://github.com/tinylabscom/mvm/issues/2938)

## Outcome

Both scheduled documented-surface jobs build an `mvmctl` that verifies signed
release manifests and can explicitly download their published boot artifacts
through the standard link path. The macOS job also installs the target-gated
libkrun dependency and embedded Linux cross toolchain required to compile the
root binary before exercising HVF.

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
- [x] Reproduce the post-merge Linux aws-lc link failure with the exact runner
      command from Extended CI run 33137960741.
- [x] Keep signature verification enabled while routing that build around the
      incompatible fast-codegen wrapper.
- [x] Install the shared embedded cross toolchain in the macOS witness.
- [x] Add structural regressions for both post-merge failures.
- [x] Reproduce the remaining macOS bootstrap and SDK-codegen failures from
      Extended CI run 33139650457.
- [x] Make builder bootstrap honor the existing `MVM_BOOT_IMAGE=fetch`
      acquisition choice instead of unconditionally selecting the source flake.
- [x] Compile the release-artifact download path in both witnesses and use the
      published workload kernel on macOS.
- [x] Build the SDK codegen driver before the clean-run drift scenario invokes
      it directly.
- [x] Warm the source-matched SDK sidecar after PR #2954 lands.
- [ ] Pass the corrected live Extended CI witnesses.
- [ ] Merge the corrective pull request and close #2938 through its linkage.

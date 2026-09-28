# Security mutation witnesses

**Status: IN PROGRESS**

Issue: #3679. Related freshness alert: #3750.
Worktree: `mvm-3679-security-witnesses`.

The latest scheduled failure, run 36378277756, reports surviving mutations in
mvm-cli, mvm-build, mvm-fs, mvm-hostd, mvm-contract and mvm-vmm. The release-tag
run 36446915750 also completed with failure.
The witness-freshness alert is reporting this failed scheduled conclusion;
the scheduler itself has fired.

- [x] Pass mvm-contract and mvm-fs unit tests: 1,103 and 421 tests respectively,
      including package-field, kernel-inventory, DNS-class, embedded-address
      and route-accessor regressions.
- [ ] Validate the path-kind, cache-capacity, credential-injection and
      egress-diagnostic regression tests in the remaining packages.
- [ ] Validate the four documented equivalent mutations against the mutation gate.
- [ ] Validate independent base-image scan and absolute-source-root tests in this
      worktree; preserve the unrelated uncommitted tests in the main checkout.
- [x] Pass host workspace Clippy with warnings denied.
- [ ] Pass full workspace tests and Linux builder all-targets Clippy.
- [ ] Run Security on the final branch, merge the isolated PR, and confirm closure.

The main checkout's base-image and runtime-overlay work is preserved. This branch
adds independent coverage without copying or modifying those uncommitted edits.
No mutation baseline was broadly re-recorded: only four algebraically or
control-flow equivalent mutations have explicit per-mutation explanations.
The focused contract/filesystem run passed 1,524 tests; remaining package,
workspace and mutation validation is pending. No security failure is marked fixed.

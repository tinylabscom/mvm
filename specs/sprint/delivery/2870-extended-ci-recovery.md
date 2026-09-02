# Extended CI executes the intended witnesses reliably

## Problem

The scheduled AArch64 no-KVM smoke supplied `/bin/true` as an ad-hoc command,
which replaced the sealed fixture's baked `exit 7` entrypoint and correctly
returned zero. On one current macOS runner, Homebrew resolved the firmware
formula to a bottle basename absent from the tap's release, so retrying the same
404 could never repair the install. Once installation succeeded, the Apple
workspace build also lacked the pinned embedded-host Rust target and Zig
wrapper required by mvm-cli's build script.

## Delivered behavior

Both AArch64 launches select `machine run --entrypoint`, so the first boot and
the exported-and-reinstalled bundle exercise the workload the witness claims to
test. Scheduled and release macOS jobs share one trusted-tap libkrun installer;
it builds the checksum-pinned firmware formula from source before installing
libkrun, and retries the complete transaction three times with bounded backoff
for genuinely transient downloads. The Apple lane installs the repository's
shared embedded-host toolchain action before its workspace build.

## Validation

- `cargo test --test github_actions_aarch64_no_kvm`;
- `cargo test -p xtask check_workflow_paths`;
- actionlint over `ci-full.yml` and `release.yml`;
- the required PR and merge-group checks remain the merge gate.

# Transient `LocalBackend::launch` attaches the universal initramfs

## Problem

A transient `LocalBackend::launch` (`mvm_hostd::run::admit_and_boot_local`)
attached the runtime overlay but no universal initramfs, so a runtime-lean
OCI rootfs booted with no `/init` at all: the guest panicked before
userspace and the host only saw an agent that never answered. SDK callers
hit this on every in-process transient launch (the plan's execution log
recorded it as a known defect; SDK machines were kept persistent until it
was fixed).

## What landed

- `mvm_runtime::universal_initramfs` is the one home for the attach
  decision: the kernel-booting-backend allow-list, the source-fingerprint
  eviction, the cache/build ladder, and the fail-closed refusal when a
  kernel-and-rootfs boot cannot resolve an initramfs. Moved out of
  `mvm-client::launch::runtime_source`, which re-exports it so existing
  callers keep resolving.
- `mvm_runtime::host_shell` carries the `ShellEnvironment` both the
  initramfs build fallback and the host shell-out paths use.
- `mvm_build::image_source::guest_runtime_source_checkout` is the shared
  "which checkout builds the guest runtime" answer; the client's
  `runtime_overlay_source_checkout_root` delegates to it.
- `mvm_hostd::run` attaches the guest runtime (overlay + initramfs
  together, `attach_guest_runtime`) on the transient in-process boot and
  the warm-activation path; `session_resume` goes through the same helper.
  Session-resume and run tests seed artifacts through
  `mvm_runtime::universal_initramfs::seed_warm_universal_initramfs` and
  `crate::test_fixtures::install_runtime_overlay` instead of hand-rolled
  cache entries.

## Tests

- `a_local_boot_attaches_the_initramfs_that_mounts_its_overlay` (hostd):
  a kernel-and-rootfs boot on firecracker/hvf gets both the overlay and
  the initramfs from the host cache.
- 13 `mvm_runtime::universal_initramfs` unit tests: the backend
  allow-list, fingerprint eviction, fail-closed refusal, proxy/sidecar
  reads, and the warm-seed fixture.
- Session-resume tests (31) re-seeded through the shared fixtures.

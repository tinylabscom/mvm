# Transient LocalBackend launches boot with the universal initramfs

Backing: shipped-source
Validation: cargo test -p mvm-hostd (lib suite green, including
`attach_universal_initramfs_from_cache_*`);
`cargo clippy -p mvm-hostd --all-targets -- -D warnings`;
live repro below.

Issue #3785.

## The bug

A transient `LocalBackend::launch` (the in-process hostlib path, PS-01) of a
runtime-lean OCI image booted to a kernel panic: `mvm_hostd::run`'s local
admission attaches the runtime overlay but never the universal initramfs, and
the initramfs is what mounts the overlay at `/mvm/runtime` and supplies
`/init`. The CLI's start paths attach it through `mvm-client`, which
`mvm-hostd` cannot reach because `mvm-client` depends on it. The host only
saw the guest die as `host session handshake failed … failed to fill whole
buffer` on the first SDK call.

First observed as both documented-surface e2e lanes failing the two
in-process SDK scenarios on the v0.18.1 release (deterministic across two
runs), reproduced locally on this Mac, root-caused to this issue's
known-defect entry.

## The fix

`mvm-hostd::run::attach_universal_initramfs_from_cache` resolves the
universal initramfs through the same `mvm-build` ladder the CLI runs
(cached entry, deterministic cargo build, then the pinned image set's
member — the crate already depends on `mvm-build`, so both layers call one
implementation) and attaches it on every in-process boot that attaches the
overlay: `admit_and_boot_local`, `admit_signed_and_boot_local`, and the
fresh boot `session_resume` builds. A kernel-and-rootfs boot fails closed
when no initramfs can be vouched for; kernel-less shapes and non-kernel
backends are left alone.

## Evidence

- Unit: a warm version-keyed cache attaches `initrd_path` for a
  kernel-and-rootfs boot; mock backend and kernel-less configs are skipped;
  a wrong-version entry refuses with the artifact named (a genuinely cold
  cache in this workspace cold-builds from sources instead — the ladder's
  own behavior — so the refusal is tested through the unvouched-entry arm).
- Live: on this Mac, `mvmctl run --mode live --profile dev
  crates/mvm-conformance/fixtures/e2e/sandbox_script.py` at the v0.18.1 tag
  died with the handshake short read; with this fix the same command boots
  the machine and the script completes (exit 0).

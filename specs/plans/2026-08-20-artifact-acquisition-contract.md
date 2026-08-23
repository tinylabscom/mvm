# Artifact acquisition contract

Backing: shipped-source
Validation: workspace gates

**Status:** COMPLETE
**Opened:** 2026-08-20

## Goal

Make artifact acquisition an explicit product contract: official release
binaries download verified artifacts and never implicitly invoke local build
tools, while contributor binaries build source-matched artifacts deliberately
and report the cold-build phase clearly.

## Work

- [x] Add an explicit compiled source/release channel and release-boundary tests.
- [x] Route boot image, workload kernel, runtime overlay, initramfs, and guest
      runtime defaults through the shared channel.
- [x] Extend bootstrap to prepare every launch-critical runtime artifact.
- [x] Make contributor guest compilation a named, concise phase with verbose
      raw Cargo output available on request.
- [x] Measure the guest target-cache layout and safely reuse dependency output
      without allowing stale source artifacts.
- [x] Run focused, workspace, gated, and clippy validation; update sprint and
      refactor rollup.

## Validation

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `just check-gated`
- release-channel policy and source-detection tests
- production OCI policy preflight regression proving rejection precedes guest
  runtime preparation
- merge-queue aarch64 no-KVM smoke preserves and executes a source-channel root
  `mvmctl` binary with the `user` signature-verification surface, while a
  separate release-channel helper downloads only the already-published builder
  VM; pre-merge code cannot consume its new runtime-overlay archive contract
  until a release publishes those bytes. The smoke installs `virtiofsd` and
  `ipxe-qemu` (the Ubuntu package carrying `efi-virtio.rom`), then runs
  source-matched bootstrap before its first builder-backed launch. The hosted
  runner grants its unprivileged QEMU process access to `/dev/vhost-vsock`, and
  the local Docker witness passes through that one device. The runtime overlay
  is prepared before that builder produces the workload kernel.
  Hook-mutated rootfs images pass an offline journal repair/check after their
  writable mount is dropped and are flushed before export completion; the
  workload can therefore retain a hypervisor-enforced read-only rootfs without
  relying on ext4's unsafe `noload` escape hatch.
  The tagged release workflow independently signs the newly packaged overlay
  and drives it through the exact production downloader before publish
- refreshed standalone `mvm-hostd` fuzz lock passes stable and pinned-nightly
  `--locked --all-targets` checks after the current-main dependency expansion
- release-asset structure and guest-binary-list synchronization gates
- project builder-VM realization of
  `nix/images/runtime-overlay#runtime-overlay` for `aarch64-linux`, including
  executable checks for all six published OCI guest shims

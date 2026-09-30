# Vsock-only guest devices

Backing: shipped-source
Validation: check-declared-backing

## Problem

QEMU creates a user-network NIC when no networking option is supplied. The
workload and builder launchers omitted that option. An older opt-in Firecracker
pool builder explicitly attached TAP. Both violate the guest-device invariant:
no microVM has a guest NIC, TAP, or TUN path to the host; outbound traffic crosses
the vsock endpoint.

## Work

- [x] Disable QEMU's implicit NIC in workload and all builder launches, with
      regression tests for launch arguments and the source gate.
- [x] Retire the TAP-backed pool-builder mode with a clear early error; remove
      its launcher and add a regression that prevents new builder TAP setup.
- [x] Correct capability metadata and stale source descriptions.
- [x] Close the cached builder-kernel capability gap: a kernel booted on
      macOS has `CONFIG_TUN=y` and `CONFIG_VIRTIO_NET=y` despite the current
      `mvm-images` recipe disabling both. Define and verify a fail-closed cache
      contract with the image publisher before claiming zero TUN capability.
- [x] Publish a signed image set with builder cache contract 5 and the resolved
      kernel-config artifact for both architectures, then advance the `mvm`
      image lock to that train. Do not merge the contract-5 consumer while the
      checked-in lock still pins contract 4.
- [x] Run focused tests, the single-network-path gate, host workspace tests,
      check, and Clippy; record any Linux-only validation that needs the builder VM.
- [ ] Update the sprint and refactor rollup; land through a reviewed PR.

## Validation status

The network-path gate and its 18 tests pass. `mvm-build`, `mvm-backends`, and
`mvm-runtime` pass their individual host test suites. Workspace check, Clippy,
formatting, shellcheck, actionlint, and the image-lock, sprint/plan/source guards
pass. The serialized, unskipped `cargo test --workspace -- --test-threads=1`
rerun passes all host crates, including 894 `xtask` tests and doctests. The
first full run exposed a stale telemetry inventory launch edge for the removed
pool builder; it now records the remaining binary as unwired. Linux builder-VM
Clippy, gated compilation, and live boot verification remain pending.

The exact cached aarch64 builder kernel from the reported macOS run embeds
`CONFIG_TUN=y` and `CONFIG_VIRTIO_NET=y`. Its manifest declares cache contract
version 4 and `vsock_egress_ready=true`, and its provenance identifies a
source-checkout Stage 0 build. The present `mvm-images/kernel/base.nix` disables
these options, so this is a cached-artifact/contract gap, not evidence that the
current recipe intentionally includes a NIC. `bootstrap_tool_builder_vm_image_in_process`
accepts structurally valid cached kernel/rootfs files without checking these
kernel capabilities; `builder_vm_image::validate_cache` accepts the manifest
readiness flags without checking them either. No live network bypass has been
demonstrated, but the requested zero-TUN-capability invariant is not yet proven.

The image producer landed through `mvm-images` PR #39 after all 27
non-publishing checks passed, including both builder architectures and all
six canonical reproducibility jobs. Its protected release workflow rebuilt
and verified the complete set, then published signed `image-set/v0.2.3`.
The released manifest declares cache contract 5 and boot ABI 1. Its keyless
signature verifies against the exact tagged release-workflow identity. Both
released builder `kernel.config` assets match their digests in that signed
manifest and pass the resolved no-network-device check. This branch now pins
that manifest digest, release tag, compatibility and both Stage 0 kernel
digests through `xtask repin-image-lock`; old contract-4 caches are refused.

After the pin advance, the serialized host run passes `mvm-build --lib` (1,243
tests, 3 ignored) and `mvm-cli --lib` (2,231 tests, 2 ignored). Linux builder-VM
and live boot verification remain pending.

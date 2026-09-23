# Firecracker GICv2 virtio-mmio launch

Issue #3577.

## Change

The Firecracker launch script no longer passes `--enable-pci`. Block, vsock,
and entropy devices therefore use Firecracker's portable virtio-mmio transport
on both GICv2 and GICv3 aarch64 hosts, as well as x86_64. The process launch,
API socket, pid marker, scope, and privilege behavior are unchanged.

The regression test inspects the exact production launch script and proves it
still passes `--api-sock` while refusing the PCI flag. The test failed on the
old launch line and passes after the one-argument removal.

## Validation

- The full `mvm-backends` suite passes: 255 tests.
- `cargo test --workspace -- --test-threads=1` passed every unit and
  integration target. Its sole terminal failure was rustdoc losing the
  existing `mvm_sdk` artifact while starting the `mvm-build` doctest; the
  immediate isolated `cargo test -p mvm-build --doc -- --test-threads=1`
  rerun passed with exit status zero.
- Workspace all-target Clippy with warnings denied and formatting pass.
- `just check-gated` passes both the Linux workspace/all-target check and the
  BDD-feature conformance check.
- `cargo run -q -p xtask -- check-all` reports all 74 repository-policy gates
  clean.

## Hardware evidence

The originating Raspberry Pi 4 witness already replayed mvm's exact
Firecracker API configuration on a GICv2 KVM host. The configuration booted
with virtio-mmio and failed every virtio probe with `-524` only when PCI was
forced. This change makes the production launch match the successful replay.

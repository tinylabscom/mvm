# AArch64 sealed workloads run end to end and tear down cleanly

## Problem

The Raspberry Pi QEMU witness exposed several architecture and lifecycle gaps:
the wrong serial console, a repeated uid drop, compressed kernel modules,
incomplete source-checkout overlay plumbing, and teardown through an
auto-selected backend instead of the backend that owned the session.

## Delivered behavior

The AArch64 guest reaches its workload entrypoint with the correct console and
privilege transition, stages available compressed modules, and receives the
required builder/runtime-overlay artifacts. Session teardown reads the recorded
backend marker and reaps QEMU together with its vsock bridge. An opt-in
diagnostic setting can retain transient state without changing the secure
default cleanup behavior.

## Validation

- focused unit and integration tests cover entrypoint, mount, activation,
  backend mapping, builder, and teardown behavior;
- the Raspberry Pi QEMU witness ran the sealed exit-code workload and returned
  its expected status without leaving QEMU or vsock-bridge processes;
- workspace CI remains the merge gate for formatting, Clippy, and full tests.

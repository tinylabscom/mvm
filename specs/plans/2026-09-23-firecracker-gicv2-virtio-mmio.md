# Firecracker GICv2 virtio transport

Backing: shipped-source
Validation: check-sprint-append

Issue: #3577

**Status: IN PROGRESS.**

## Problem

The Firecracker launcher forced `--enable-pci` for every guest even though the
configured block, vsock, and entropy devices all work over virtio-mmio. On an
aarch64 GICv2 host, Firecracker's PCI device tree contains an unresolved
interrupt-controller phandle, every virtio device fails probe with `-524`, and
the guest can never mount its rootfs or answer the host agent.

The same API configuration boots on the affected hardware when Firecracker
uses its default MMIO transport.

## Work

- [x] Add a launch-script regression that refuses `--enable-pci` while
      preserving the API-socket argument.
- [x] Remove the forced PCI flag from the production launch line.
- [x] Update CI and hardware-witness documentation that described the old
      launch requirement.
- [x] Pass the full `mvm-backends` test suite (255 tests).
- [x] Pass workspace tests, all-target Clippy, gated-target checks, formatting,
      and repository policy checks.
- [ ] Deliver through the protected merge queue and close #3577.

## Security and compatibility

This does not add a host device or passthrough surface. It selects the smaller,
portable Firecracker virtio-mmio device model already used when PCI is not
explicitly enabled. The API socket, process identity, privilege boundary, and
guest device set are unchanged.

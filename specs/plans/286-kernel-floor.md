# Plan 286 — Drive the guest kernel toward its hardware floor

**Status:** IN PROGRESS
**Opened:** 2026-08-02

## Goal

Compile only the Linux subsystems exercised by mvm's supported virtual hardware
and guest contract. Preserve Firecracker/libkrun MMIO, VZ PCI, virtio block,
network, console, balloon, rng and vsock, dm-verity, virtio-fs, TUN-over-vsock,
seccomp, the x86 KVM clock and ACPI/MADT, and the ARM FDT/GIC/timer path.

## Baseline

The latest successful kernel-build artifacts on current main contain 1,189
x86_64 built-ins in a 7,656,448-byte `bzImage`, and 1,314 aarch64 built-ins in a
14,460,936-byte `Image`.

## Work

- [x] Audit the resolved workload configs rather than trusting requested
      disables. Confirm that sound, USB, wireless, Bluetooth, DRM and media are
      already absent, while selector-pinned input/VT, RF-kill/NFC, physical PHY,
      SoC, filesystem, power/debug and foreign-hypervisor families remain.
- [x] Add a required-disable set and fail config generation if `olddefconfig`
      silently restores any audited removal.
- [x] Remove the unused common subsystem and selector chains while retaining the
      explicit supported-backend hardware contract.
- [x] Remove x86 physical-PC, laptop, non-KVM guest, VGA, DVFS and appliance ACPI
      leaves while retaining ACPI core, PCI, KVM paravirtualization and ttyS0.
- [x] Resolve and ratchet both architecture configs: 902 x86_64 and 938
      aarch64 built-ins.
- [x] Build the x86_64 workload kernel and verify its 4,072,448-byte image boots
      under Firecracker 1.14.1 on KVM through the production ELF extraction
      shape.
- [x] Measure `CC_OPTIMIZE_FOR_SIZE` against the same config. It saved about
      0.7 MiB while Firecracker reached PID 1 within normal sub-second variance,
      so make it the workload default.
- [x] Build the 955-symbol, 4,977,664-byte builder kernel; verify its Nix
      sandbox/network/filesystem features remain present and boot it to PID 1
      under Firecracker.
- [ ] Build the native aarch64 workload artifact and boot the ARM image through
      the supported HVF/VZ path.
- [x] Run format, workspace tests/check, Linux all-target clippy and Nix checks;
      record the final byte and symbol deltas in the sprint and refactor rollup.

## Acceptance

- Both resolved configs are at or below their ratcheted symbol ceilings.
- An audited required-disable restored by Kconfig fails the derivation.
- x86_64 Firecracker and aarch64 HVF/VZ reach userspace with the slim kernel.
- Builder-kernel virtio-fs, cgroup and netfilter requirements still resolve and
  its image boots.
- The repository's complete required gates pass before merge.

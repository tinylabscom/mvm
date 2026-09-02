Feature: Verified boot rejects a tampered rootfs

  A tampered rootfs image fails to boot: the dm-verity roothash check
  panics the kernel before userspace runs, so a compromised image can
  never reach a running workload. Each VMM must also receive the console and
  kernel format it can actually boot, without changing the shared verity
  device contract.

  Under the universal initramfs the roothashes travel over vsock, so the sealed
  cmdline must not carry the legacy `mvm.roothash`, `mvm.data`, `mvm.hash`, or
  runtime-overlay equivalents. A legacy per-rootfs initramfs is no longer
  supported, so those cmdline tokens are never emitted.

  Scenario: A sealed libkrun workload on the universal initramfs uses its virtio console
    When I assemble a sealed workload cmdline for "libkrun" booting the "universal" initramfs
    Then the sealed workload cmdline contains "console=hvc0"
    And the sealed workload attaches the verified runtime overlay
    And the sealed workload cmdline omits "mvm.runtime_source_policy="
    And the sealed workload cmdline omits "mvm.roothash="
    And the sealed workload cmdline omits "mvm.data=/dev/vda"
    And the sealed workload cmdline omits "mvm.hash=/dev/vdb"
    And the sealed workload cmdline omits "mvm.runtime_roothash="
    And the sealed workload cmdline omits "mvm.runtime_data=/dev/vdc"
    And the sealed workload cmdline omits "mvm.runtime_hash=/dev/vdd"
    But the sealed workload cmdline omits "console=ttyAMA0"
    And the sealed workload cmdline omits "earlycon=pl011"

  Scenario: A sealed HVF workload on the universal initramfs keeps its pl011 console
    When I assemble a sealed workload cmdline for "hvf" booting the "universal" initramfs
    Then the sealed workload cmdline contains "console=ttyAMA0"
    And the sealed workload cmdline contains "earlycon=pl011"
    And the sealed workload attaches the verified runtime overlay
    And the sealed workload cmdline omits "mvm.runtime_source_policy="
    And the sealed workload cmdline omits "mvm.roothash="
    But the sealed workload cmdline omits "console=hvc0"

  Scenario: Libkrun maps the workload kernel to its host-loadable format
    When I map an existing ELF workload kernel through the libkrun driver
    Then the libkrun kernel format matches the current host architecture

  Scenario: A single flipped data block on a sealed rootfs refuses to boot
    Given a sealed ext4 rootfs with /sbin/init
    And the rootfs verity root hash is recorded
    When a single byte in the rootfs data area is flipped
    Then the tampered rootfs does not match the recorded verity root hash

Feature: Verified boot rejects a tampered rootfs

  A tampered rootfs image fails to boot: the dm-verity roothash check
  panics the kernel before userspace runs, so a compromised image can
  never reach a running workload. Each VMM must also receive the console and
  kernel format it can actually boot, without changing the shared verity
  device contract.

  Scenario: A sealed libkrun workload uses its virtio console
    When I assemble a sealed workload cmdline for "libkrun"
    Then the sealed workload cmdline contains "console=hvc0"
    And the sealed workload cmdline contains "mvm.roothash="
    And the sealed workload cmdline contains "mvm.data=/dev/vda"
    And the sealed workload cmdline contains "mvm.hash=/dev/vdb"
    And the sealed workload cmdline contains "mvm.runtime_roothash="
    And the sealed workload cmdline contains "mvm.runtime_data=/dev/vdc"
    And the sealed workload cmdline contains "mvm.runtime_hash=/dev/vdd"
    But the sealed workload cmdline omits "console=ttyAMA0"
    And the sealed workload cmdline omits "earlycon=pl011"

  Scenario: A sealed HVF workload keeps its pl011 console
    When I assemble a sealed workload cmdline for "hvf"
    Then the sealed workload cmdline contains "console=ttyAMA0"
    And the sealed workload cmdline contains "earlycon=pl011"
    And the sealed workload cmdline contains "mvm.roothash="
    But the sealed workload cmdline omits "console=hvc0"

  Scenario: Libkrun maps the workload kernel to its host-loadable format
    When I map an existing ELF workload kernel through the libkrun driver
    Then the libkrun kernel format matches the current host architecture

  @wip
  Scenario: A single flipped data block on a sealed rootfs refuses to boot
    Given a scenario awaiting its step implementation

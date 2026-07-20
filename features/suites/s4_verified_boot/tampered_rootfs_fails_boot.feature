Feature: Verified boot rejects a tampered rootfs

  A tampered rootfs image fails to boot: the dm-verity roothash check
  panics the kernel before userspace runs, so a compromised image can
  never reach a running workload.

  @wip
  Scenario: A single flipped data block on a sealed rootfs refuses to boot
    Given a scenario awaiting its step implementation

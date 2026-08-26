Feature: Universal initramfs cache attachment

  The universal initramfs is shared across workloads. Its absence must never
  silently fall back to a legacy per-rootfs initrd; sealed/verity boots own their
  initramfs through the universal initramfs attach step.

  What this scenario pins is *ordering*, not tolerance: when a nearer
  precondition has already failed, the CLI must report that one rather than the
  initramfs. It used to read as "a cold initramfs cache does not block machine
  run", which was a claim about tolerance — and the launch path really was
  tolerant, swallowing an unresolvable initramfs at debug level and booting a
  guest that had no runtime overlay to mount, no agent, and no egress client.
  That guest panicked its kernel and the host reported only an agent-readiness
  timeout. A cold initramfs cache now refuses the launch and says so; this
  scenario stays green because the kernel check fails first, which is the whole
  point of it.

  @cli
  Scenario: a nearer precondition failure is reported instead of the initramfs
    Given an isolated mvm home with a cached non-verity workload kernel
    When I run mvmctl in the isolated mvm home with "machine run --image alpine -- /bin/true"
    Then the command exits with code 1
    And the output contains "workload kernel capability check failed"
    And the error output does not contain "initramfs"

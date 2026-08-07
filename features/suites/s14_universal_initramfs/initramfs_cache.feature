Feature: Universal initramfs cache attachment

  The universal initramfs is shared across workloads and may be absent from the
  local cache.  Its absence must never be the reason a workload fails to start;
  the boot path falls back to the legacy per-rootfs /init when the initramfs is
  not yet cached, and the CLI must fail fast for the *next* real precondition
  (e.g., an unusable workload kernel) rather than emitting an initramfs error.

  @cli
  Scenario: A cold initramfs cache does not block machine run
    Given an isolated mvm home with a cached non-verity workload kernel
    When I run mvmctl in the isolated mvm home with "machine run --image alpine -- /bin/true"
    Then the command exits with code 1
    And the error output contains "workload kernel"
    And the error output does not contain "initramfs"

Feature: Universal initramfs cache attachment

  The universal initramfs is shared across workloads and may be absent from the
  local cache. Its absence must never silently fall back to a legacy per-rootfs
  initrd; sealed/verity boots own their initramfs through the universal
  initramfs attach step. The CLI must fail fast for the *next* real precondition
  (e.g., failed verified kernel reacquisition) rather than emitting an initramfs
  error or resurrecting the unsupported legacy path.

  @cli
  Scenario: A cold initramfs cache does not block machine run
    Given an isolated mvm home with a cached non-verity workload kernel
    When I run mvmctl in the isolated mvm home with "machine run --image alpine -- /bin/true"
    Then the command exits with code 1
    And the output contains "workload kernel capability check failed"
    And the error output does not contain "initramfs"

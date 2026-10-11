Feature: machine run --image workload-kernel precondition

  Booting an OCI image needs a dm-verity-capable workload kernel. When a
  verified cache entry carries an explicit non-verity config, `machine run
  --image` must refuse it without repairing or mutating the cache. Explicit
  bootstrap owns reacquisition.

  @no_local_images_checkout
  Scenario: machine run --image refuses an incompatible prepared workload kernel
    Given an isolated mvm home with a cached non-verity workload kernel
    When I run mvmctl in the isolated mvm home with "machine run --image alpine -- /bin/true"
    Then the command exits with code 1
    And the error output contains "config without CONFIG_BLK_DEV_DM=y and CONFIG_DM_VERITY=y"
    And the incompatible workload kernel cache remains unchanged

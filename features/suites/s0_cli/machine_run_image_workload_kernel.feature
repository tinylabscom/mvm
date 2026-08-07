Feature: machine run --image workload-kernel precondition

  Booting an OCI image needs a dm-verity-capable workload kernel. When the
  cached workload kernel cannot boot a verity-sealed rootfs, `machine run
  --image` must fail fast with an actionable message *before* pulling the image
  — never a silent hang after the pull.

  Scenario: machine run --image fails fast when the workload kernel cannot boot verity-sealed rootfs
    Given an isolated mvm home with a cached non-verity workload kernel
    When I run mvmctl in the isolated mvm home with "machine run --image alpine -- /bin/true"
    Then the command exits with code 1
    And the error output contains "workload kernel"
    And the error output contains "kernel build --which workload"

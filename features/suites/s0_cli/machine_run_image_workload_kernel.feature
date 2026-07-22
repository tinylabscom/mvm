Feature: machine run --image workload-kernel precondition

  Booting an OCI image needs a dm-verity-capable workload kernel. On a source
  checkout that kernel is built locally and never downloaded, so when it is
  missing `machine run --image` must fail fast with an actionable message
  *before* pulling the image — never a silent hang after the pull. This guards
  the regression where the run resolved the kernel only after the OCI pull, so a
  cold-cache checkout looked wedged instead of telling the user what to do next.

  Scenario: machine run --image fails fast when the workload kernel is missing
    When I run mvmctl with "machine run --image alpine -- /bin/true" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "workload kernel"
    And the error output contains "kernel build --which workload"

Feature: machine run --image workload-kernel precondition

  Booting an OCI image needs a dm-verity-capable workload kernel. When a
  verified cache entry carries an explicit non-verity config, `machine run
  --image` must discard the whole entry and start verified reacquisition before
  pulling the image. This hermetic scenario points reacquisition at a closed
  local endpoint so it proves the transition without network or Stage 0.

  Scenario: machine run --image evicts an incompatible workload kernel and reacquires it
    Given an isolated mvm home with a cached non-verity workload kernel
    When I run mvmctl in the isolated mvm home with "machine run --image alpine -- /bin/true"
    Then the command exits with code 1
    And the error output contains "discarding it and preparing a correct kernel"
    And the incompatible workload kernel cache is evicted

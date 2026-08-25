Feature: Workload lifecycle correctness

  A transient microVM tears down cleanly on entrypoint exit, and its
  reported exit code is sourced from the vsock-audited workload result
  rather than guessed at the host boundary.

  @live
  Scenario: A transient run tears down on entrypoint exit with the sourced exit code
    # A nonzero code is the interesting case: zero is what a host boundary
    # reports by default, so it cannot distinguish "the workload said 0" from
    # "nobody asked". 7 can only have come from the workload itself.
    Given an isolated mvm home
    When I run mvmctl in an isolated live home with "machine run --image alpine --timeout 120 -- /bin/sh -c 'exit 7'"
    Then the command exits with code 7
    And the isolated mvm home has no transient request state directories

  @live
  Scenario: A transient run that succeeds still tears its state directory down
    Given an isolated mvm home
    When I run mvmctl in an isolated live home with "machine run --image alpine --timeout 120 -- /bin/echo mvm-bdd-teardown-ok"
    Then the command exits with code 0
    And the output contains "mvm-bdd-teardown-ok"
    And the isolated mvm home has no transient request state directories

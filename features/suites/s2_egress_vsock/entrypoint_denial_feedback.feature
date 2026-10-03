Feature: Entrypoint egress denial feedback

  A baked entrypoint can attempt outbound work while its machine boots and
  dispatches. The host reports denials from its signed audit chain before
  returning the entrypoint status.

  @live @firecracker @ci_live
  Scenario: a baked entrypoint reports blocked egress before its nonzero exit
    When I run mvmctl in an isolated live home with "machine run --flake examples/entrypoint-denial --entrypoint --allow-host example.com --timeout 180"
    Then the command exits with code 22
    And the error output contains "egress blocked: blocked.example:443"
    And the error output contains "egress denied: 1 destinations"

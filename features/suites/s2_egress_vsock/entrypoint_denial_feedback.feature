Feature: Entrypoint egress denial feedback

  A baked entrypoint can attempt outbound work while its machine boots and
  dispatches. The host reports denials from its signed audit chain before
  returning the entrypoint status. With no terminal to review them on, it
  names the command that reviews them later instead of prompting.

  The guest agent hands an egress boot's workloads the proxy environment, so
  the entrypoint's curl asks the host-side endpoint for the connection rather
  than resolving the name itself. The endpoint refuses the destination, curl
  reports the refusal as HTTP 403 and exits 22, and the host names the blocked
  destination, not a DNS lookup.

  @live @firecracker @ci_live
  Scenario: a baked entrypoint reports its blocked destination before its nonzero exit
    Given an isolated mvm home
    When I run mvmctl without a controlling terminal in an isolated live home with "machine run --flake examples/entrypoint-denial --entrypoint --allow-host example.com --timeout 180"
    Then the command exits with code 22
    And the error output contains "egress blocked: blocked.example:443 (not in the allow-list)"
    And the error output contains "egress denied: 1 destination"
    And the error output contains "this run was admitted without a project mvm.toml to add grants to; to grant any of them later, run from the project directory:"
    And an error output line starts with "[mvm]   mvmctl explain " and ends with " --review"
    And the error output does not contain "Grant / [S] Skip"
    # The entrypoint call ends its own audit session: 22 can only be the code
    # the workload reported, so the seal carries the observed exit.
    When I run mvmctl in the isolated mvm home with "trust audit sessions"
    Then the output contains "sealed (exit 22)"

  @live @firecracker @ci_live
  Scenario: a JSON entrypoint call carries a review command without prompting
    Given an isolated mvm home
    When I run mvmctl without a controlling terminal in an isolated live home with "machine run --flake examples/entrypoint-denial --entrypoint --json --allow-host example.com --timeout 180"
    Then the command exits with code 22
    And the error output contains "egress_denial_summary"
    And the error output contains "egress_review"
    And the error output contains "mvmctl explain "
    And the error output contains "--review"
    And the error output does not contain "Grant / [S] Skip"

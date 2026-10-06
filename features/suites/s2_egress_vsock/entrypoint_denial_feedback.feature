Feature: Entrypoint egress denial feedback

  A baked entrypoint can attempt outbound work while its machine boots and
  dispatches. The host reports denials from its signed audit chain before
  returning the entrypoint status. With no terminal to review them on, it
  names the command that reviews them later instead of prompting.

  @live @firecracker @ci_live
  Scenario: a baked entrypoint reports blocked DNS before its nonzero exit
    When I run mvmctl without a controlling terminal in an isolated live home with "machine run --flake examples/entrypoint-denial --entrypoint --allow-host example.com --timeout 180"
    Then the command exits with code 28
    And the error output contains "egress blocked: DNS lookup of blocked.example"
    And the error output contains "egress denied: 1 destination"
    And the error output contains "this run was admitted without a project mvm.toml to add grants to; to grant any of them later, run from the project directory:"
    And an error output line starts with "[mvm]   mvmctl explain " and ends with " --review"
    And the error output does not contain "Grant / [S] Skip"

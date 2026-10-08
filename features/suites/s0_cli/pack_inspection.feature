Feature: installed pack inspection

  Pack inspection verifies installed bytes before it reports an artifact as
  usable. A name from an index alone cannot pass verification.

  @pack_cli
  Scenario: pack search is available under the pack command
    When I run mvmctl with "pack search --help"
    Then the command exits with code 0
    And the output contains "mvmctl pack search"

  @pack_cli
  Scenario: pack pull is available under the pack command
    When I run mvmctl with "pack pull --help"
    Then the command exits with code 0
    And the output contains "mvmctl pack pull"

  Scenario: an uninstalled pack cannot be reported as verified
    Given an isolated mvm home
    When I run mvmctl with "pack verify runtime/go@1.0.0"
    Then the command exits with code 1
    And the error output contains "not pinned"
    And the output does not contain "Official status"

  Scenario: pack information does not claim an uninstalled artifact
    Given an isolated mvm home
    When I run mvmctl with "pack info runtime/go@1.0.0"
    Then the command exits with code 1
    And the output does not contain "Publisher issuer"

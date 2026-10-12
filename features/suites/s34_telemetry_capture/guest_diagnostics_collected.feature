@telemetry_collection
Feature: Guest agent diagnostics reach the host collector

  Diagnostics the guest agent emits must reach authenticated host collection,
  not a local console nobody captures. Every session also announces the
  agent's coverage, so an operator can tell a quiet agent from a missing one.

  Scenario: Guest agent diagnostics arrive at the authenticated collector
    Given an isolated mvm home
    And a machine "diag" whose guest agent emitted boot diagnostics
    When I run mvmctl in the isolated mvm home with "machine telemetry diag"
    Then the command exits with code 0
    And the output contains "coverage started guest-agent"
    And the output contains "bdd agent boot diagnostic"

  Scenario: One machine's telemetry is not shown for another
    Given an isolated mvm home
    And a machine "first" whose guest agent emitted boot diagnostics
    And a machine "second" whose guest agent emitted an event outside any span
    When I run mvmctl in the isolated mvm home with "machine telemetry first"
    Then the command exits with code 0
    And the output contains "bdd agent boot diagnostic"
    And the output does not contain "bdd standalone event"

  Scenario: A record carrying a secret bound to the machine is withheld and counted
    Given an isolated mvm home
    And a machine "leaky" whose guest agent logged a secret bound to it
    When I run mvmctl in the isolated mvm home with "machine telemetry leaky"
    Then the command exits with code 0
    And the output contains "bdd clean diagnostic"
    And the output contains "secret withheld 1"
    And the output does not contain "bdd-telemetry-secret-5f2a9c71e0"

  Scenario: A guest that outruns its host loses records visibly, never waits
    Given an isolated mvm home
    And a machine "flooded" whose guest flooded diagnostics while no host was reading
    When I run mvmctl in the isolated mvm home with "machine telemetry flooded"
    Then the command exits with code 0
    And the output contains "guest lost"
    And the output contains "bdd flood"

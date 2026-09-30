Feature: explain policy without starting a workload

  A policy question is useful before an agent starts only when answering it is
  local, deterministic, and does not weaken an absolute runtime deny.

  Scenario: metadata remains denied without booting a workload
    When I run mvmctl with "why --host 169.254.169.254 --json" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "subject"
    And the output contains "host"
    And the output contains "allowed"
    And the output contains "false"
    And the output contains "absolute runtime deny"

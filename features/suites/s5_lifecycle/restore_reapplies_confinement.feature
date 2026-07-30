Feature: Restore reapplies confinement

  Confinement parameters are part of the launch contract and must remain
  effective across warm restore.

  Scenario: a dry-run workload advertises its standard confinement profile
    When I run mvmctl with "machine run --image alpine --dry-run -- echo hi"
    Then the command exits with code 0
    And the output contains "profile: standard"
    And the output contains "network: deny-all"
    And the output contains "enforced: flow-drop"

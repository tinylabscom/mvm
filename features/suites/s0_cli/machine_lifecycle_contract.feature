Feature: machine lifecycle request contract

  The `machine` verbs that manage records rather than guests — create, ls, rm —
  are decidable without booting anything, so they belong in the hermetic lane.
  Every scenario here uses one isolated mvm home so the record written by an
  earlier step is the record a later step reads.

  Scenario: creating a machine records it without booting a guest
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create --name bdd-lifecycle --image alpine"
    Then the command exits with code 0
    And the output contains "created machine bdd-lifecycle"
    When I run mvmctl in the isolated mvm home with "machine ls"
    Then the command exits with code 0
    And the output contains "bdd-lifecycle"
    And the output contains "stopped"
    # Creating a record must not leave runtime state behind: `vms/` is where a
    # booted guest lives, and nothing was booted.
    And the isolated mvm home does not contain directory "vms/bdd-lifecycle"

  Scenario: removing a machine drops it from the listing
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create --name bdd-removable --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine rm --yes bdd-removable"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine ls"
    Then the command exits with code 0
    And the output does not contain "bdd-removable"

  # A name reaches the filesystem as a directory and the audit log as an
  # identity, so it is validated rather than sanitised — silently rewriting a
  # name would make the record disagree with what was asked for.
  Scenario: a machine name outside the allowed alphabet is refused
    When I run mvmctl with "machine create --name Bad_Name --image alpine" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "lowercase alphanumeric + hyphens"

  Scenario: removing a machine that does not exist says so and points at the listing
    When I run mvmctl with "machine rm --yes ghost" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "does not exist"
    And the error output contains "machine ls"

  # The error names the command that would fix it, which is the difference
  # between a dead end and a next step.
  Scenario: exec against a machine that does not exist suggests creating it
    When I run mvmctl with "machine exec ghost -- /bin/true" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "does not exist"
    And the error output contains "machine create --name ghost"

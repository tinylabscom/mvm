Feature: machine lifecycle request contract

  The `machine` verbs that manage records rather than guests — create, ls, rm —
  are decidable without booting anything, so they belong in the hermetic lane.
  Every scenario here uses one isolated mvm home so the record written by an
  earlier step is the record a later step reads.

  Scenario: creating a machine records it without booting a guest
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-lifecycle --image alpine"
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
    When I run mvmctl in the isolated mvm home with "machine create bdd-removable --image alpine"
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
    When I run mvmctl with "machine create Bad_Name --image alpine" and an isolated mvm home
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
    And the error output contains "machine create ghost"

  # `machine start` can create the spec on demand, so the request-contract
  # behavior is testable without booting a guest.
  Scenario: start with a source creates the spec without booting when dry-run
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine start bdd-start-create --image alpine --dry-run"
    Then the command exits with code 0
    And the output contains "no VM will be booted"
    And the output contains "image: OCI reference"

  Scenario: start without a source on a missing machine suggests creating it
    When I run mvmctl with "machine start bdd-missing" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "does not exist"
    And the error output contains "--image"

  Scenario: start with the same config reuses an existing machine
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-reuse --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine start bdd-reuse --image alpine --dry-run"
    Then the command exits with code 0
    And the output contains "no VM will be booted"

  Scenario: start with a changed config refuses to recreate without force
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-change --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine start bdd-change --image ubuntu --dry-run"
    Then the command exits with code 1
    And the error output contains "different config"
    And the error output contains "--force"

  Scenario: start with a changed config and force recreates the machine
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-force --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine start bdd-force --image ubuntu --force --dry-run"
    Then the command exits with code 0
    And the output contains "no VM will be booted"

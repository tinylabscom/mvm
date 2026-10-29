@runner_selection
Feature: Conformance distinguishes execution from empty or skipped selections

  Scenario: conformance help remains available without executing scenarios
    When I run the conformance runner with "--help"
    Then the command exits with code 0
    And the output contains "Usage:"
    And the output contains "--name"

  Scenario: an unmatched scenario name is not successful validation
    When I run the conformance runner with "--name '^no-such-conformance-scenario$'"
    Then the command exits with code 1
    And the error output contains "zero scenarios selected"

  Scenario: an unmatched input glob is not successful validation
    When I run the conformance runner with "--input 'no-such-conformance-features/*.feature'"
    Then the command exits with code 1
    And the error output contains "zero scenarios selected"

  Scenario: an unmatched tag is not successful validation
    When I run the conformance runner with "--tags '@no_such_conformance_tag'"
    Then the command exits with code 1
    And the error output contains "zero scenarios selected"

  Scenario: intentional platform skips are not passing execution evidence
    When I run the conformance runner with "--tags '@runner_selection_gated'"
    Then the command exits with code 0
    And the output contains "0 scenarios"
    And the error output contains "no scenarios executed"
    And the error output contains "intentionally skipped"
    And the error output contains "not passing execution evidence"

  Scenario: a name filter cannot bypass a disabled capability
    When I run the conformance runner with "--name '^a controlled live-gated fixture requires opt-in$'"
    Then the command exits with code 0
    And the output contains "0 scenarios"
    And the error output contains "no scenarios executed"
    And the error output contains "not passing execution evidence"

  Scenario: a name filter cannot bypass the shard gate
    When I run the conformance runner with "--name '^a selected conformance smoke scenario executes$'" excluding probe "a selected conformance smoke scenario executes" by shard
    Then the command exits with code 1
    And the output contains "0 scenarios"
    And the error output contains "zero scenarios selected"

  Scenario: a tag filter cannot bypass the shard gate
    When I run the conformance runner with "--tags '@runner_selection_gated'" excluding probe "a controlled live-gated fixture requires opt-in" by shard
    Then the command exits with code 1
    And the output contains "0 scenarios"
    And the error output contains "zero scenarios selected"

  Scenario: a nonempty selection can succeed
    When I run the conformance runner with "--name '^a selected conformance smoke scenario executes$'"
    Then the command exits with code 0
    And the output contains "1 scenario (1 passed)"

  Scenario: a selected conformance smoke scenario executes
    When I run mvmctl with "--help"
    Then the command exits with code 0
    And the help output lists the "run" verb

  # A filtering regression can fail this fixture but cannot start a VM.
  @live @runner_selection_gated
  Scenario: a controlled live-gated fixture requires opt-in
    Then the conformance live opt-in is present

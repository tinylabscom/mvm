Feature: mvmctl top-level CLI surface

  The top-level verb list `mvmctl --help` prints is the CLI's discoverability
  contract: every beginner-facing verb documented here must actually appear,
  and the command must exit cleanly.

  Scenario: mvmctl --help lists the documented top-level verbs
    When I run mvmctl with "--help"
    Then the command exits with code 0
    And the help output lists the "machine" verb
    And the help output lists the "build" verb
    And the help output lists the "doctor" verb
    And the help output lists the "ls" verb
    And the help output lists the "bootstrap" verb

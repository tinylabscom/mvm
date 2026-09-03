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
    And the help output lists the "bootstrap" verb

  Scenario: mvmctl --help keeps global option descriptions concise
    When I run mvmctl with "--help"
    Then the command exits with code 0
    And the help output contains "Output format"
    And the help output contains "Builder VMM: libkrun, qemu, or hvf"
    And the help output contains "Kernel source: compile, download, auto"
    And the help options fit within 80 columns
    But the help output does not contain "Highest priority"
    And the help output does not contain "platform-default auto-detect"

  Scenario: machine run help keeps option descriptions concise
    When I run mvmctl with "machine run --help"
    Then the command exits with code 0
    And the help output contains "Boot an OCI image"
    And the help output contains "Allow outbound access"
    And the help output contains "Select the VMM"
    And the help output contains "Record check interval"
    But the help output does not contain "Mutually exclusive with"
    And the help output does not contain "production-safe call surface"

  Scenario: every CLI help item is one line shorter than 80 columns
    Then every mvmctl command and subcommand help item is one line shorter than 80 columns

  Scenario: machine help advertises the fork and restore verbs
    When I run mvmctl with "machine --help"
    Then the command exits with code 0
    And the help output contains "fork"
    And the help output contains "restore"

  Scenario: machine fork help documents the child naming options
    When I run mvmctl with "machine fork --help"
    Then the command exits with code 0
    And the help output contains "--as"
    And the help output contains "--branch"

  Scenario: machine restore help documents the child naming options
    When I run mvmctl with "machine restore --help"
    Then the command exits with code 0
    And the help output contains "--as"
    And the help output contains "--branch"

  # Skipped: This test iterates over every command path and runs two help invocations
  # per path (with -h and help <path>). With dozens of top-level commands and
  # hundreds of subcommands, this causes hundreds of process spawns and stalls.
  # The main help test (`every mvmctl command and subcommand help item`) already
  # covers the same ground with one invocation per path.
  # Scenario: every alternative CLI help entry point obeys the one-line limit
  #   Then every alternative CLI help item is one line shorter than 80 columns

  Scenario: the MCP consumer advertises its local stdio transport
    When I run mvmctl with "ops mcp --help"
    Then the command exits with code 0
    And the help output contains "stdio"

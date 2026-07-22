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

  Scenario: mvmctl --help keeps global option descriptions concise
    When I run mvmctl with "--help"
    Then the command exits with code 0
    And the help output contains "Output format"
    And the help output contains "Builder VMM: libkrun, qemu, or hvf"
    And the help output contains "Kernel source: compile, download, or auto"
    And the help options fit within 80 columns
    But the help output does not contain "Highest priority"
    And the help output does not contain "platform-default auto-detect"

  Scenario: machine run help keeps option descriptions concise
    When I run mvmctl with "machine run --help"
    Then the command exits with code 0
    And the help output contains "Boot an OCI image"
    And the help output contains "Allow outbound access to HOST[:PORT] (repeatable)"
    And the help output contains "Select the VMM (firecracker, hvf, libkrun, or qemu)"
    And the help output contains "Record check interval in seconds (not yet enforced)"
    But the help output does not contain "Mutually exclusive with"
    And the help output does not contain "production-safe call surface"

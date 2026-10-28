Feature: backend component table contract

  `mvmctl backend` reads the per-backend component table: what this host
  supports, what is installed, and which backend install picks by default.
  The verbs that change the install answer unsupported hosts and idempotent
  no-ops without touching VM state, so every scenario here is hermetic.

  Scenario: list renders every backend with its host support
    When I run mvmctl with "backend list" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "firecracker"
    And the output contains "libkrun"
    And the output contains "hvf"
    And the output contains "qemu"
    And the output contains "default on this host"

  Scenario: add refuses a backend that cannot run on a native host
    When I run mvmctl with "backend add web-linux" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "not supported on this host"
    And the error output contains "browser"

  Scenario: add an unknown backend lists the known names
    When I run mvmctl with "backend add zvm" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "unknown backend"
    And the error output contains "libkrun"

  Scenario: adding a backend with no host components is an idempotent no-op
    When I run mvmctl with "backend add wasm" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "nothing to install"
    When I run mvmctl with "backend add wasm" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "nothing to install"

  Scenario: removing a componentless backend leaves machine state alone
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-backend --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "backend remove wasm"
    Then the command exits with code 0
    And the output contains "nothing to remove"
    When I run mvmctl in the isolated mvm home with "machine ls"
    Then the command exits with code 0
    And the output contains "bdd-backend"

  Scenario: detect prints the install-time default
    When I run mvmctl with "backend detect --plain" and an isolated mvm home
    Then the command exits with code 0
    And the output does not contain "backend"

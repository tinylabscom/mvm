@sdk
Feature: Runtime SDK live transport
  In live mode the imperative Sandbox surface shells every operation to
  `mvmctl machine …`. That argv is the contract between the language SDKs and
  the CLI, and it is the same contract in every language.

  These scenarios drive the built artifacts — the installed Python package and
  the emitted TypeScript ESM — against a recording `mvmctl` double. No microVM
  boots. Running the built artifact rather than the sources is deliberate: a
  source-level runner supplies module interop the published package does not
  have, and so cannot see a packaging defect.

  Scenario Outline: live mode drives the documented mvmctl verb sequence
    When I run the "<language>" SDK live-transport fixture
    Then the SDK fixture exits successfully
    And the recorded mvmctl argv matches the golden live session

    Examples:
      | language   |
      | Python     |
      | TypeScript |

  Scenario: both languages drive the CLI identically
    When I run the "Python" SDK live-transport fixture
    And I run the "TypeScript" SDK live-transport fixture
    Then the two recorded argv traces are identical

  Scenario: every recorded invocation names a real mvmctl machine verb
    When I run the "Python" SDK live-transport fixture
    Then every recorded invocation names a machine verb the CLI defines

  Scenario Outline: a sealed machine refuses the dev-only verbs before any CLI call
    When I run the "<language>" SDK refusal fixture against a sealed machine
    Then the SDK fixture exits successfully
    And the SDK refused every dev-only and invalid-mode operation
    And no process or filesystem verb reached the CLI

    Examples:
      | language   |
      | Python     |
      | TypeScript |

  Scenario: the two SDK surfaces diverge only where a human signed off
    When I collect the Python and TypeScript public surfaces
    Then the shared surface agrees between the two languages
    And any divergence matches the reviewed divergence list
    And every Rust-owned env-var name reaches the surfaces it claims

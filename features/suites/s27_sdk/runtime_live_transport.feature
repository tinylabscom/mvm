@sdk
Feature: Runtime SDK live transport
  In live mode the imperative Sandbox surface turns every operation into one
  call on the host library, libmvm_hostlib, loaded in-process. The SDK never
  runs mvmctl. The sequence of methods and requests is the contract between
  the language SDKs and the library, and it is the same in every language.

  These scenarios drive the built artifacts — the installed Python package and
  the emitted TypeScript ESM — with the SDK's one C call replaced by an
  in-process recorder. No library loads and no microVM boots. Running the
  built artifact rather than the sources is deliberate: a source-level runner
  supplies module interop the published package does not have, and so cannot
  see a packaging defect.

  Scenario Outline: live mode drives the documented host-library call sequence
    When I run the "<language>" SDK live-transport fixture
    Then the SDK fixture exits successfully
    And the recorded host-library calls match the golden live session

    Examples:
      | language   |
      | Python     |
      | TypeScript |

  Scenario: both languages drive the host library identically
    When I run the "Python" SDK live-transport fixture
    And I run the "TypeScript" SDK live-transport fixture
    Then the two recorded call traces are identical

  Scenario Outline: every recorded call names a method the host library defines
    When I run the "<language>" SDK live-transport fixture
    Then every recorded call names a method the host library defines

    Examples:
      | language   |
      | Python     |
      | TypeScript |

  Scenario Outline: a sealed machine refuses the dev-only operations before any guest call
    When I run the "<language>" SDK refusal fixture against a sealed machine
    Then the SDK fixture exits successfully
    And the SDK refused every dev-only and invalid-mode operation
    And no guest method reached the host library

    Examples:
      | language   |
      | Python     |
      | TypeScript |

  Scenario: the Tier A constructors agree with the golden IR document
    When I run the "Python" Tier A constructor fixture
    And I run the "TypeScript" Tier A constructor fixture
    Then both Tier A constructor surfaces match the golden IR document

  Scenario: the two SDK surfaces diverge only where a human signed off
    When I collect the Python and TypeScript public surfaces
    Then the shared surface agrees between the two languages
    And any divergence matches the reviewed divergence list
    And every Rust-owned env-var name reaches the surfaces it claims

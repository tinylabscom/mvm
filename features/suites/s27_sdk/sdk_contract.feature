@sdk
Feature: Cross-language SDK contract
  The decorator and runtime SDKs share Rust-owned wire contracts while
  retaining native Python and TypeScript ergonomics.

  Scenario Outline: decorator SDK emits the canonical workload document
    When I run the "<language>" SDK "decorator" fixture
    Then the SDK fixture exits successfully
    And the SDK fixture emits the canonical decorator document

    Examples:
      | language   |
      | Python     |
      | TypeScript |

  Scenario Outline: runtime SDK records the canonical operations
    When I run the "<language>" SDK "runtime" fixture
    Then the SDK fixture exits successfully
    And the SDK fixture records command and file operations

    Examples:
      | language   |
      | Python     |
      | TypeScript |

  Scenario: generated SDK artifacts are current
    When I run the SDK codegen drift check
    Then the SDK codegen drift check passes

  Scenario: the network constructors reach one verdict in every language
    When I run the Python SDK network-constraint fixture
    Then the SDK fixture exits successfully
    And every constructor case reaches the verdict the shared corpus states

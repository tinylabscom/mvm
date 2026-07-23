Feature: Workload semantic identity

  `mvmctl build address` prints a Workload IR's content identity: the
  `sha256(JCS(ir))` semantic address and the matching ir-hash. The identity is
  a property of what the workload means, not how its JSON was written, so two
  encodings of the same workload must address alike, two different workloads
  must not, and an unrecognized schema must fail closed.

  Scenario: Reordered keys and whitespace do not change the address
    When I compute the workload address of fixture "hello.min.json"
    Then the command exits with code 0
    When I compute the workload address of fixture "hello.reordered.json"
    Then the command exits with code 0
    And the workload address of "hello.reordered.json" equals "hello.min.json"

  Scenario: A meaningfully different workload has a different address
    When I compute the workload address of fixture "hello.min.json"
    Then the command exits with code 0
    When I compute the workload address of fixture "goodbye.json"
    Then the command exits with code 0
    And the workload address of "goodbye.json" differs from "hello.min.json"

  Scenario: The semantic address matches the ir-hash
    When I compute the workload address of fixture "hello.min.json"
    Then the command exits with code 0
    And the semantic address of "hello.min.json" matches its ir-hash

  Scenario: An unsupported schema version fails closed
    When I compute the workload address of fixture "bad-schema.json"
    Then the command exits with code 1
    And the error output contains "schema"

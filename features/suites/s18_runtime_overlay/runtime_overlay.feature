Feature: s18_runtime_overlay

  Conformance scenario for MVM-SEC-06.

  @MVM-SEC-06 @build @wip
  Scenario: Pre-built dev image overlay is hash-verified
    Given the scenario is registered for MVM-SEC-06
    When the suite for MVM-SEC-06 is implemented
    Then the witness tests pass

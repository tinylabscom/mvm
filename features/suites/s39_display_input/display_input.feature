Feature: s39_display_input

  Conformance scenario for MVM-SEC-24.

  @MVM-SEC-24 @build
  Scenario: A workload's display accepts input only under a signed, attended grant
    Given the scenario is registered for MVM-SEC-24
    When the suite for MVM-SEC-24 is implemented
    Then the witness tests pass

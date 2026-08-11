Feature: s28_admission_budget

  Conformance scenario for MVM-SEC-18.

  @MVM-SEC-18 @build 
  Scenario: A boot that would exceed the host's headroom is refused
    Given the scenario is registered for MVM-SEC-18
    When the suite for MVM-SEC-18 is implemented
    Then the witness tests pass

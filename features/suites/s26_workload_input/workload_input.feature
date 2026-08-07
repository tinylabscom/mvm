Feature: s26_workload_input

  Conformance scenario for MVM-SEC-17.

  @MVM-SEC-17 @build 
  Scenario: Workload stdin is reachable only through a signed plan grant
    Given the scenario is registered for MVM-SEC-17
    When the suite for MVM-SEC-17 is implemented
    Then the witness tests pass

Feature: s37_cumulative_ledger

  Conformance scenario for MVM-SEC-22.

  @MVM-SEC-22 @build 
  Scenario: Cumulative action budgets ride signed and keep plan bytes stable when absent
    Given the scenario is registered for MVM-SEC-22
    When the suite for MVM-SEC-22 is implemented
    Then the witness tests pass

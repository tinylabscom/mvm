Feature: s6_admission_audit

  Conformance scenario for MVM-SEC-08.

  @MVM-SEC-08 @build @wip
  Scenario: Every workload runs from a signed audited ExecutionPlan
    Given the scenario is registered for MVM-SEC-08
    When the suite for MVM-SEC-08 is implemented
    Then the witness tests pass

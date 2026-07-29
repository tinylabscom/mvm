Feature: s21_host_services

  Conformance scenario for MVM-SEC-12.

  @MVM-SEC-12 @build @wip
  Scenario: Host-side service bindings are plan-gated and audited
    Given the scenario is registered for MVM-SEC-12
    When the suite for MVM-SEC-12 is implemented
    Then the witness tests pass

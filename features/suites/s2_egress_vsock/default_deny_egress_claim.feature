Feature: s2_egress_vsock

  Conformance scenario for MVM-SEC-10.

  @MVM-SEC-10 @build @wip
  Scenario: Default-deny egress admits only policy-approved destinations
    Given the scenario is registered for MVM-SEC-10
    When the suite for MVM-SEC-10 is implemented
    Then the witness tests pass

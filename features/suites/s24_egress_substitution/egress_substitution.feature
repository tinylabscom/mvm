Feature: s24_egress_substitution

  Conformance scenario for MVM-SEC-16.

  @MVM-SEC-16 @build @wip
  Scenario: Egress substitution keeps raw secrets off the guest
    Given the scenario is registered for MVM-SEC-16
    When the suite for MVM-SEC-16 is implemented
    Then the witness tests pass

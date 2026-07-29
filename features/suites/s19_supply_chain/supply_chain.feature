Feature: s19_supply_chain

  Conformance scenario for MVM-SEC-07.

  @MVM-SEC-07 @some-true @wip
  Scenario: Cargo dependencies are audited on every PR
    Given the scenario is registered for MVM-SEC-07
    When the suite for MVM-SEC-07 is implemented
    Then the witness tests pass

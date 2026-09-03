Feature: s19_supply_chain

  Conformance scenarios for MVM-SEC-07 and MVM-SEC-20.

  @MVM-SEC-07 @some-true 
  Scenario: Cargo dependencies are audited on every PR
    Given the scenario is registered for MVM-SEC-07
    When the suite for MVM-SEC-07 is implemented
    Then the witness tests pass

  @MVM-SEC-20 @build
  Scenario: Published release artifacts are signed and refused when unsigned
    Given the scenario is registered for MVM-SEC-20
    When the suite for MVM-SEC-20 is implemented
    Then the witness tests pass

Feature: s15_guest_privilege

  Conformance scenario for MVM-SEC-02.

  @MVM-SEC-02 @build 
  Scenario: Guest binaries cannot elevate to uid 0
    Given the scenario is registered for MVM-SEC-02
    When the suite for MVM-SEC-02 is implemented
    Then the witness tests pass

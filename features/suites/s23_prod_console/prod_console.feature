Feature: s23_prod_console

  Conformance scenario for MVM-SEC-15.

  @MVM-SEC-15 @build 
  Scenario: No interactive access to a sealed production microVM
    Given the scenario is registered for MVM-SEC-15
    When the suite for MVM-SEC-15 is implemented
    Then the witness tests pass

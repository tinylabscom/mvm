Feature: s14_host_shares

  Conformance scenario for MVM-SEC-01.

  @MVM-SEC-01 @build 
  Scenario: Host shares beyond explicit allow-list are refused
    Given the scenario is registered for MVM-SEC-01
    When the suite for MVM-SEC-01 is implemented
    Then the witness tests pass

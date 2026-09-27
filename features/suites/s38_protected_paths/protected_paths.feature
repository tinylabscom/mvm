Feature: s38_protected_paths

  Conformance scenario for MVM-SEC-23.

  @MVM-SEC-23 @build 
  Scenario: Protected-path gate refuses guest-authored changes to CI/test/build files
    Given the scenario is registered for MVM-SEC-23
    When the suite for MVM-SEC-23 is implemented
    Then the witness tests pass

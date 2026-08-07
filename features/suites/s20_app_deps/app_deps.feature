Feature: s20_app_deps

  Conformance scenario for MVM-SEC-11.

  @MVM-SEC-11 @build 
  Scenario: App-dep volumes are hash-locked CVE-scanned and SBOM-enumerated
    Given the scenario is registered for MVM-SEC-11
    When the suite for MVM-SEC-11 is implemented
    Then the witness tests pass

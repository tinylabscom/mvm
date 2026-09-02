Feature: s33_content_addressed_assets

  Conformance scenario for MVM-SEC-19.

  @MVM-SEC-19 @build
  Scenario: Every workload asset is content-identified and share drift fails closed
    Given the scenario is registered for MVM-SEC-19
    When the suite for MVM-SEC-19 is implemented
    Then the witness tests pass

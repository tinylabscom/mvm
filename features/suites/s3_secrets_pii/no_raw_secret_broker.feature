Feature: s3_secrets_pii

  Conformance scenario for MVM-SEC-13.

  @MVM-SEC-13 @build @wip
  Scenario: No raw secret value crosses the broker channel
    Given the scenario is registered for MVM-SEC-13
    When the suite for MVM-SEC-13 is implemented
    Then the witness tests pass

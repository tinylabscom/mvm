Feature: s3_secrets_pii

  Conformance scenario for MVM-SEC-13.

  @MVM-SEC-13 @build 
  Scenario: The managed substitution path hands the guest placeholders, never raw secret values
    Given the scenario is registered for MVM-SEC-13
    When the suite for MVM-SEC-13 is implemented
    Then the witness tests pass

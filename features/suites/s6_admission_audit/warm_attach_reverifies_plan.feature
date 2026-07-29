Feature: Warm-attach plan re-verification

  Attaching to a warm standby pool re-verifies the signed execution plan
  before the VMM is allowed to resume. A tampered or wrongly-signed plan
  fails closed.

  Scenario: a tampered plan fails signature verification
    Given a signed execution plan for tenant "tenant-a"
    When the plan JSON is tampered with an extra field
    And the plan is verified
    Then plan verification fails with a signature error

  Scenario: a plan signed by an unknown signer fails verification
    Given a signed execution plan for tenant "tenant-a" by signer "host:other"
    When the plan is verified
    Then plan verification fails with an unknown signer error

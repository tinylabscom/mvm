Feature: Every workload runs from a signed, audited execution plan

  mvmctl synthesizes and signs an execution plan before dispatching any
  workload, and every admission — success or failure — is recorded as a
  chain-signed entry in the audit log.

  Scenario: Admission of a workload is recorded in the chain-signed audit log
    Given an isolated mvm home
    And a workload plan was admitted in the audit chain
    When I run mvmctl in the isolated mvm home with "trust audit verify --verbose --tenant local"
    Then the command exits with code 0
    And the audit chain verifies clean

  Scenario: A tampered audit chain is detected on verify
    Given an isolated mvm home
    And a workload plan was admitted in the audit chain
    When the audit chain is tampered
    And I run mvmctl in the isolated mvm home with "trust audit verify --verbose --tenant local"
    Then the command exits with code 1
    And the audit chain verify fails with a tampering error

  Scenario: A caller commitment is bound into the signed audit chain
    Given an isolated mvm home
    And a caller-committed workload plan was admitted in the audit chain
    When I run mvmctl in the isolated mvm home with "trust audit verify --verbose --tenant local"
    Then the command exits with code 0
    And the audit chain verifies clean
    And the audit entry carries the exact caller commitment

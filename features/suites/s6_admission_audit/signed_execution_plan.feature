Feature: Every workload runs from a signed, audited execution plan

  mvmctl synthesizes and signs an execution plan before dispatching any
  workload, and every admission — success or failure — is recorded as a
  chain-signed entry in the audit log.

  @wip
  Scenario: Admission of a workload is recorded in the chain-signed audit log
    Given a scenario awaiting its step implementation

  @wip
  Scenario: A tampered audit chain is detected on verify
    Given a scenario awaiting its step implementation

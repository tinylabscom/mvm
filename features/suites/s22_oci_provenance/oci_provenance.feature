Feature: s22_oci_provenance

  Conformance scenario for MVM-SEC-14.

  @MVM-SEC-14 @build @wip
  Scenario: OCI image provenance is recorded in the chain-signed audit log
    Given the scenario is registered for MVM-SEC-14
    When the suite for MVM-SEC-14 is implemented
    Then the witness tests pass

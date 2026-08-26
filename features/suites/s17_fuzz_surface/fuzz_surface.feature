Feature: s17_fuzz_surface

  Conformance scenario for MVM-SEC-05.

  @MVM-SEC-05 @build
  Scenario: Vsock framing, supervisor config JSON, and datapath ingress are fuzzed
    Given the scenario is registered for MVM-SEC-05
    When the suite for MVM-SEC-05 is implemented
    Then the witness tests pass

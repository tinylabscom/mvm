Feature: s17_fuzz_surface

  Conformance scenario for MVM-SEC-05. Adversarial inputs against the
  attacker-reachable parser surfaces must fail closed (error or deny) and
  must never panic. The real cargo-fuzz targets own the exhaustive coverage;
  this scenario spot-checks the same functions with a deterministic corpus so
  the BDD gate proves they are wired and panic-free.

  @MVM-SEC-05 @build
  Scenario: Vsock framing, supervisor config JSON, and datapath ingress are fuzzed
    Given a deterministic adversarial corpus for MVM-SEC-05
    When each corpus entry is parsed by its corresponding surface
    Then no parse panics or aborts

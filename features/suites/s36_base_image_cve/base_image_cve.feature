Feature: s36_base_image_cve

  Conformance scenario for MVM-SEC-21.

  The claim's witnesses are the pull-path scan and the admission gate
  themselves: the inventory parsers, the OSV correlation, and the
  prod-refusal behavior are unit-tested against seeded caches and a mock
  OSV client, because a live scenario would depend on a registry, a
  network, and the current state of the CVE feed. What is checked here
  is that the claim stays registered and its witnesses stay resolvable.

  @MVM-SEC-21 @build
  Scenario: Base images are CVE-scanned at pull and gated at production admission
    Given the scenario is registered for MVM-SEC-21
    When the suite for MVM-SEC-21 is implemented
    Then the witness tests pass

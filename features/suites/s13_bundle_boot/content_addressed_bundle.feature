Feature: s13_bundle_boot

  Conformance scenario for MVM-SEC-09.

  @MVM-SEC-09 @build @wip
  Scenario: Published bundles install and re-verify by content address
    Given the scenario is registered for MVM-SEC-09
    When the suite for MVM-SEC-09 is implemented
    Then the witness tests pass

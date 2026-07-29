Feature: s4_verified_boot

  Conformance scenario for MVM-SEC-03.

  @MVM-SEC-03 @build @wip
  Scenario: A tampered rootfs ext4 fails to boot
    Given the scenario is registered for MVM-SEC-03
    When the suite for MVM-SEC-03 is implemented
    Then the witness tests pass

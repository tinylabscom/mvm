Feature: Runtime overlay integrity verification

  The runtime overlay is a read-only virtio-blk device that carries the guest
  agent, seccomp shim, runner, and per-language SDK runtime binaries. Before a
  microVM can attach it, the overlay artifact must be hash-verified against its
  checksum manifest; a tampered artifact must fail closed.

  @MVM-SEC-06 @build
  Scenario: A cached runtime overlay resolves when intact
    Given an isolated mvm home with a verified runtime overlay in the cache
    When the runtime overlay is resolved for the current arch
    Then the runtime overlay resolves successfully

  @MVM-SEC-06 @build
  Scenario: A tampered runtime overlay is refused with an integrity error
    Given an isolated mvm home with a verified runtime overlay in the cache
    When a byte in the cached runtime overlay ext4 is flipped
    And the runtime overlay is resolved for the current arch
    Then the runtime overlay resolution fails with an integrity error

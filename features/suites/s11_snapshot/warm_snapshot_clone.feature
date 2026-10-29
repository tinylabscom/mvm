Feature: Warm-snapshot clone

  A warm snapshot is materialized into an instance by cloning a pre-built,
  content-addressed artifact (copy-on-write), not by rebuilding it from
  scratch — the storage-layer basis for a warm start being faster than a
  cold boot.

  Scenario: cloning a warm snapshot yields an independent copy-on-write instance
    Given a content-addressed warm snapshot built from a template rootfs artifact
    When the warm snapshot is cloned into a fresh instance
    Then the instance byte-equals the warm snapshot
    And mutating the instance does not change the stored warm snapshot
    And re-storing the identical artifact reuses the existing snapshot rather than rebuilding it

  @snapshot_chain_v2
  Scenario: a CoW child's content id derives from its parent's chunk manifest plus its delta
    Given a v2 content-addressed warm snapshot built from a template tree
    When a child cloned from the snapshot is mutated by a few blocks and stored from the parent's manifest
    Then the child's content id equals a from-scratch manifest hash of its bytes
    And the parent snapshot still verifies against its stored bytes

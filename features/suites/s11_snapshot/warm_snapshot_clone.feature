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

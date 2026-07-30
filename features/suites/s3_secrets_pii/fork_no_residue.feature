Feature: Fork memory residue prevention

  A warm fork materializes the child's rootfs only from the parent's sealed
  checkpoint content. Any state written to the parent after the checkpoint
  must not leak into the child.

  Scenario: a post-checkpoint parent mutation does not appear in the forked child
    Given a clean warm parent recorded in the pool with a signed audit-chain entry
    And the parent's source directory receives a post-checkpoint residue file
    When the parent is claimed with an admitted child plan
    Then the child's rootfs is materialized from the parent's own content
    And the residue file is absent from the child's rootfs

Feature: Warm-claim guarded fork

  A warm claim forks a clean, audit-chain-verified parent into a fresh child
  through the runner's guarded claim seam, and refuses to fork a parent the
  chain does not attest to.

  Scenario: a guarded warm claim forks a fresh child and refuses an unaudited parent
    Given a clean warm parent recorded in the pool with a signed audit-chain entry
    When the parent is claimed with an admitted child plan
    Then the claim yields a fresh child identity distinct from the parent
    And the child's rootfs is materialized from the parent's own content
    And the child is delivered a fresh, non-zero generation token bound to the parent
    And the child's signed verb grant is delivered with its final identity
    Given a clean warm parent recorded in the pool with no signed audit-chain entry
    When the parent is claimed with an admitted child plan
    Then the claim is refused and no child is forked

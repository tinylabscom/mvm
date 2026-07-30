Feature: Fork identity replay refusal

  A warm fork must produce a fresh child identity bound to a fresh, signed
  plan. Replaying an older plan or reusing the parent identity must be
  refused.

  Scenario: a guarded warm claim produces a fresh child identity and refuses an unaudited parent
    Given a clean warm parent recorded in the pool with a signed audit-chain entry
    When the parent is claimed with an admitted child plan
    Then the claim yields a fresh child identity distinct from the parent
    And the child is delivered a fresh, non-zero generation token bound to the parent
    Given a clean warm parent recorded in the pool with no signed audit-chain entry
    When the parent is claimed with an admitted child plan
    Then the claim is refused and no child is forked

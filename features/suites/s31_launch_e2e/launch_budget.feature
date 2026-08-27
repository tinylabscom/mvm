Feature: the launch budget stays observable on every run

  The README advertises a millisecond-scale start. The number that defines it is
  `dispatch_window` — guest-dispatchable, excluding process startup and teardown
  — which `MVM_PHASE_TIMING=1` emits on every launch.

  The warm hard ceiling is asserted from the CLI's shared contract; the cold
  window is recorded but not asserted here. Prepared-cold percentile and
  per-sample budgets belong to the benchmark matrix, not to one warm-claim
  scenario. Keeping the contracts separate prevents the 200 ms prepared-cold
  target from being mislabeled as the strict sub-300 ms warm-claim ceiling.

  Background:
    Given an artifact-warm mvm home

  @live
  Scenario: a cold transient launch reports its dispatch window
    When I launch "machine run --image alpine -- true"
    Then the launch succeeds
    And the guest control plane came up
    And the dispatch window is recorded

  @live
  Scenario: a warm-residency launch meets the documented start budget
    When I launch "machine run --image alpine -- true" with env "MVM_RESIDENCY" set to "warm"
    Then the launch succeeds
    And the guest control plane came up
    And the dispatch window is recorded
    And the warm launch meets its hard dispatch ceiling

Feature: the launch budget stays observable on every run

  The README advertises a millisecond-scale start. The number that defines it is
  `dispatch_window` — guest-dispatchable, excluding process startup and teardown
  — which `MVM_PHASE_TIMING=1` emits on every launch.

  The warm budget is asserted; the cold window is recorded but not asserted. Cold
  dispatch on this host is a known open number tracked separately from whether
  the launch modes work, and a suite that went red on it would go red for a
  reason unrelated to correctness — and would then stop being run, which is how
  the last regression survived.

  Background:
    Given an artifact-warm mvm home

  @live
  Scenario: a cold transient launch reports its dispatch window
    When I launch "machine run --image alpine -- true"
    Then the launch succeeds
    And the guest control plane came up
    And the dispatch window is recorded

  # `@perf_budget` gates the *threshold*, not the measurement: the two scenarios
  # above still record a dispatch window everywhere. A 200 ms budget on a host
  # with rotational storage measures the disk rather than the launch path.
  @live @perf_budget
  Scenario: a warm-residency launch meets the documented start budget
    When I launch "machine run --image alpine -- true" with env "MVM_RESIDENCY" set to "warm"
    Then the launch succeeds
    And the guest control plane came up
    And the dispatch window is recorded
    And the guest became dispatchable within 200 ms

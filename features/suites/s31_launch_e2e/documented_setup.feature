Feature: The documented setup commands run on a real host

  The README opens with three commands a new user types before anything else:
  `bootstrap`, and the two arms of `build kernel build`. Every other live
  scenario depends on their output, which is exactly why they went untested —
  "the suite would not run at all if bootstrap were broken" is true, and it is
  also how a *partial* failure hides. A bootstrap that acquires the kernel but
  leaves the overlay stale still lets the suite pass on a home warmed by an
  earlier, working build; nothing asserts the command itself reports success.

  Both are idempotent against a warm home, so running them here re-verifies the
  cached artifacts rather than re-fetching hundreds of megabytes.

  @live
  Scenario: bootstrap succeeds and reports a ready host
    Given an artifact-warm mvm home
    When I launch "bootstrap"
    Then the launch succeeds

  @live
  Scenario: the documented workload kernel download resolves
    Given an artifact-warm mvm home
    When I launch "build kernel build --which workload --source download"
    Then the launch succeeds

  # `doctor` is the command the README tells a reader to run when either of the
  # above misbehaves, so a release in which it cannot itself run is a release
  # whose troubleshooting advice is wrong.
  @live
  Scenario: doctor reports on the host the setup commands just prepared
    Given an artifact-warm mvm home
    When I launch "doctor"
    Then the launch succeeds

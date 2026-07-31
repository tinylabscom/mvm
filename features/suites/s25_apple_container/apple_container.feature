Feature: Apple Container backend contract

  The apple-container backend is the HVF workload runner with Apple's
  prebuilt container kernel substituted for the boot image — same universal
  initramfs, same agent-as-PID-1, same activation flow as every other
  backend. The kernel is a fetched binary artifact cached under
  "apple-container", so resolution fails closed with a typed error that
  says what is missing, where it belongs, and how to fetch it. Auto-select
  prefers the apple-container backend on the HVF tier, but only when its
  kernel is cached — without the artifact the tier falls back to the plain
  HVF backend. Once its kernel is cached the launch's kernel image is
  always that cached kernel, never a caller-supplied one.

  Scenario: A missing container kernel fails closed with a hint-carrying error
    Given an isolated mvm home for the apple-container backend
    When I start the apple-container backend with a minimal config
    Then the start fails with a missing-artifact error naming the container kernel
    And the error names the artifact cache path under "apple-container"
    And the error carries the fetch hint

  Scenario: Auto-select skips apple-container when its kernel is not cached
    Given an isolated mvm home for the apple-container backend
    When I ask for the auto-selected backend
    Then the selected backend is not apple-container

  Scenario: The cached container kernel always wins the launch's kernel image
    Given an isolated mvm home for the apple-container backend
    And an apple-container kernel is cached in the isolated home
    When I apply the backend's kernel substitution to a caller config
    Then the kernel path is the cached apple-container kernel, not the caller's kernel

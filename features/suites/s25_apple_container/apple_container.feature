Feature: Apple Container backend contract

  The apple-container backend is the HVF workload runner with Apple's
  prebuilt container kernel substituted for the boot image — same universal
  initramfs, same agent-as-PID-1, same activation flow as every other
  backend. The kernel is a fetched binary artifact cached under
  "apple-container", so resolution fails closed with a typed error that
  says what is missing, where it belongs, and how to fetch it. Because the
  kernel is fetched rather than built by mvm, it is trusted only with a
  matching digest sidecar — a "vmlinux.blake3" beside the kernel naming
  the lowercase-hex BLAKE3 of its bytes, the same attestation honesty the
  initramfs sidecars already enforce. A kernel whose sidecar is missing,
  malformed, or disagrees with its bytes is refused with a typed
  untrusted-artifact error and never makes the backend available.
  Auto-select never lands on the apple-container backend — it is opt-in
  only, selected explicitly with "--hypervisor apple-container" — and the
  availability probe itself requires the verified artifact. Once its
  kernel is cached and attested the launch's kernel image is always that
  cached kernel, never a caller-supplied one. The backend is admitted to
  the workload funnel — the egress endpoint, broker registration, and
  activation gate are the HVF runner's verbatim; only the kernel image
  differs.

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

  Scenario: The admitted workload funnel accepts the apple-container backend
    When I ask the admitted workload funnel for the apple-container backend
    Then the funnel accepts it as a workload backend of kind apple-container

  Scenario: A kernel whose bytes do not match its sidecar fails closed with the digest error
    Given an isolated mvm home for the apple-container backend
    And an apple-container kernel is cached with a sidecar that does not match its bytes
    When I start the apple-container backend and capture the attestation failure
    Then the failure is the untrusted-artifact digest error
    And the failure names the pinned and actual digests

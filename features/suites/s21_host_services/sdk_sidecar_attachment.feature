Feature: SDK sidecar attaches only for admitted SDK host-service bindings

  The glibc host-services cdylib the language SDKs dlopen ships as an optional
  read-only sidecar, not in the base rootfs or the static-musl runtime overlay.
  Whether a workload gets it is decided from the signed execution plan's
  host-service bindings alone.

  Scenario: a workload that binds no SDK host service gets no sidecar
    Given a workload plan that binds no host service
    When the launch path resolves the SDK sidecar
    Then no SDK sidecar is attached
    And admission accepts the launch with no sidecar attachment
    And the assembled workload cmdline names no SDK sidecar device

  Scenario: an unrelated host-service binding does not attach the sidecar
    Given a workload plan that binds host service "broker.v1"
    When the launch path resolves the SDK sidecar
    Then no SDK sidecar is attached
    And admission refuses a sidecar attachment for this plan

  Scenario: a workload that binds an SDK host service gets the sidecar read-only
    Given a verified SDK sidecar in the cache
    And a workload plan that binds host service "host.audit.v1"
    When the launch path resolves the SDK sidecar
    Then the SDK sidecar is attached read-only at "/mvm/sdk"
    And admission accepts the launch with the sidecar attachment
    And the assembled workload cmdline names the SDK sidecar device the backend attached

  Scenario: a required sidecar that is missing from the cache fails the launch closed
    Given an empty SDK sidecar cache
    And a workload plan that binds host service "host.secrets.v1"
    When the launch path resolves the SDK sidecar
    Then the launch is refused and the error names the binding that required it

  Scenario: a tampered sidecar fails the launch closed
    Given a verified SDK sidecar in the cache
    And the cached SDK sidecar image is byte-flipped
    And a workload plan that binds host service "host.time.v1"
    When the launch path resolves the SDK sidecar
    Then the launch is refused and the error reports an integrity mismatch

  Scenario: a downloaded mvmctl acquires the published sidecar and boots
    Given an empty SDK sidecar cache
    And a published SDK sidecar release artifact
    And a workload plan that binds host service "host.audit.v1"
    When the launch path acquires the SDK sidecar from the published release
    Then the SDK sidecar is attached read-only at "/mvm/sdk"
    And admission accepts the launch with the sidecar attachment
    And the assembled workload cmdline names the SDK sidecar device the backend attached

  Scenario: a published sidecar whose archive does not match its checksum is refused
    Given an empty SDK sidecar cache
    And a published SDK sidecar release artifact whose archive checksum does not match
    And a workload plan that binds host service "host.audit.v1"
    When the launch path acquires the SDK sidecar from the published release
    Then the launch is refused and the SDK sidecar cache stays empty

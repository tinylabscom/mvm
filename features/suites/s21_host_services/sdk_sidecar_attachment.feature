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

  Scenario: wasm refuses SDK host services at admission in user terms
    Given a verified SDK sidecar in the cache
    And a workload plan that binds host service "host.time.v1"
    When the launch path resolves the SDK sidecar
    Then the SDK sidecar is attached read-only at "/mvm/sdk"
    And wasm admission refuses the requested SDK host service before backend start

  Scenario: the SDK sidecar bypasses user-volume activation beside a wheel mount
    Given a verified SDK sidecar in the cache
    And a workload plan that binds host service "host.time.v1"
    And a read-only directory mount at "/mnt/wheels"
    When the launch path resolves the SDK sidecar
    Then the SDK sidecar is attached read-only at "/mvm/sdk"
    And admission accepts the launch with the sidecar attachment
    And the assembled workload cmdline names the SDK sidecar device the backend attached
    And the user-volume manifest names "/mnt/wheels" but not the SDK mount

  Scenario: a bound host time request crosses the SDK broker transport
    Given a workload plan that binds host service "host.time.v1"
    When the SDK sends a framed host time request to its bound broker
    Then the SDK receives a current host wall clock without a transport error

  Scenario: a wheel mount outside the guest allow-roots is refused before boot
    When I run mvmctl with "run --image python:3.12 --mount .:/wheels:ro --timeout 10 --dry-run -- /bin/true" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "outside the allow-roots"
    And the error output does not contain "guest agent did not become reachable"

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

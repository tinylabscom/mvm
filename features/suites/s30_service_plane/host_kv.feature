Feature: A workload reaches a key-value store without a network path

  The store lives on the host and is reached over the broker channel. A
  workload gets durable storage with no network path and no credential, and
  only if the admitted plan bound the service.

  Scenario: an unbound workload cannot reach the store
    Given a broker registry with no bound services
    When the workload calls "host.kv.v1" verb "get"
    Then the service call is refused as not bound

  Scenario: a bound workload reads back what it wrote
    Given a broker registry binding "host.kv.v1"
    When the workload puts key "session" with 3 bytes
    And the workload gets key "session"
    Then the stored value is returned

  Scenario: a missing key reads as absent rather than failing
    Given a broker registry binding "host.kv.v1"
    When the workload gets key "never-written"
    Then the read reports the key absent

  # The namespace comes from the call context, never a payload field, so one
  # workload cannot address another's by asking.
  Scenario: one workload cannot read another's keys
    Given a broker registry binding "host.kv.v1"
    When workload "w1" puts key "secret" with 3 bytes
    And workload "w2" gets key "secret"
    Then the read reports the key absent

  Scenario: a traversal key is refused before it reaches the filesystem
    Given a broker registry binding "host.kv.v1"
    When the workload gets key "../../etc/passwd"
    Then the service call is refused as a bad request

  Scenario: an unexpected request field fails closed
    Given a broker registry binding "host.kv.v1"
    When the workload sends a get request carrying an unknown field
    Then the service call is refused as a bad request

  # The witness the rest of this file could not give. Every scenario above
  # drives the handler or the registry directly; this one boots a workload and
  # has guest code reach the store the way a real one does: through the sidecar
  # cdylib, over vsock, to the broker. It is `@live` because it needs a real
  # microVM.
  # The fixture is delivered as a read-only ext4 volume rather than a host
  # directory share, so this witness runs on the default Firecracker and HVF
  # backends as well as libkrun.
  @live @sdk_sidecar
  Scenario: a booted workload round-trips a key through the broker
    Given the SDK service-plane fixture is materialized as a read-only disk image
    When I run the SDK service-plane fixture in an isolated live home binding service "host.kv.v1"
    Then the command exits with code 0
    And the output contains "KV-OK"

  # Binding is what makes the store reachable, so the refusal has to be
  # observable from inside a guest too -- not only at the registry.
  # The read-only fixture volume keeps this on the same in-guest broker path as
  # the positive witness without requiring a backend-specific directory share.
  @live @sdk_sidecar
  Scenario: an unbound workload is refused from inside the guest
    Given the SDK service-plane fixture is materialized as a read-only disk image
    When I run the SDK service-plane fixture in an isolated live home binding service "host.time.v1"
    Then the command exits with code 1
    And the output contains "not bound"

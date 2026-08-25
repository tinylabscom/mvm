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

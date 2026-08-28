Feature: A catalog runtime declares the host services it needs

  An operator should not have to know that a runtime wants a store and pass the
  flag every time, learning it from a failure the first time. The entry says so
  once and the binding reaches the signed plan.

  Scenario: no bundled runtime declares a binding
    Given the built-in runtime catalog
    Then no bundled runtime declares a host-service binding

  Scenario: a declared binding is parsed onto the resolved runtime
    Given a runtime catalog whose entry declares service "host.kv.v1"
    When the runtime is resolved by name
    Then the resolved runtime carries service "host.kv.v1"

  # Parsed at resolution, so a malformed entry is a catalog error rather than a
  # signed plan carrying a binding no handler could satisfy.
  Scenario: a malformed declared service refuses at resolution
    Given a runtime catalog whose entry declares service "not a service"
    When the runtime is resolved by name
    Then resolution is refused naming the entry

  # Ok(None) would report "nothing detected" for an entry that plainly matched,
  # and the run would proceed on a different image than the catalog intended.
  Scenario: a matched entry with malformed bindings errors instead of reporting no match
    Given a runtime catalog whose entry declares service "not a service"
    When the runtime is detected by its command
    Then detection is refused rather than reporting no match

  @live @sdk_sidecar
  Scenario: a workload may bind the key-value store at launch
    When I run mvmctl in an isolated live home with "machine run --name bdd-kv-bind --image alpine --host-service host.kv.v1 --timeout 120 -- /bin/echo mvm-bdd-kv-bound"
    Then the command exits with code 0
    And the output contains "mvm-bdd-kv-bound"

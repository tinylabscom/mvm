Feature: Workload lifecycle correctness

  A transient workload tears down cleanly on entrypoint exit, and its
  reported exit code is sourced from the workload result rather than guessed
  at the host boundary. Healthchecks on a persistent machine are actively
  probed by the host.

  Scenario: A transient run tears down on entrypoint exit with the sourced exit code
    # The wasm backend runs the module under host wasmtime, so this exercises
    # real exit-code propagation and teardown on a macOS host without a VM.
    When I run mvmctl in an isolated live home with "machine run --hypervisor wasm --manifest examples/wasm-exit-code/fixture/mvm.toml"
    Then the command exits with code 7
    And the isolated mvm home has no transient request state directories

  @live
  Scenario: A persistent machine with a healthcheck is actively probed
    # Healthchecks require a guest agent + vsock, so this scenario boots a real
    # microVM and is gated by MVM_BDD_LIVE.
    Given an isolated mvm home
    When I run mvmctl in an isolated live home with "machine run --name bdd-healthcheck --image alpine --healthcheck 'true' --detach -- /bin/sleep 300"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine wait --for probes bdd-healthcheck --timeout 60"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-healthcheck --yes"
    Then the command exits with code 0

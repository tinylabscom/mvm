Feature: Declared health checks are actively probed

  A machine that declares a health check should have it run on an interval and
  its result reported back to the host.

  # Not yet witnessed here. The CLI surface is probed:
  #
  #   * `mvmctl machine run --healthcheck/--health-interval/--health-retries`
  #     persist into the machine spec (`mvm-runtime`'s
  #     `machine::persist::MachineSpec::health_check`), and the resident
  #     host-agent daemon's health watcher runs the check on that interval
  #     and restarts an unhealthy machine (`mvm-hostd`'s `health_probe`,
  #     unit-tested there). What this scenario lacks is step code that boots
  #     a persistent machine.
  #   * `mkGuest`'s `healthChecks` attribute is accepted and carried in
  #     `passthru.mvm.unenforced`, explicitly not acted on.
  #   * `mvm-agentd`'s `probes` module has the serde types and a drop-in
  #     loader, and no command execution or interval loop.
  #
  # Un-tag this and write the steps once a live machine can be booted here.
  @wip
  Scenario: A persistent machine with a healthcheck is actively probed
    Given a scenario awaiting its step implementation

Feature: Declared health checks are actively probed

  A machine that declares a health check should have it run on an interval and
  its result reported back to the host.

  # BLOCKED — no prober exists. This is not an unwritten test; it is an
  # unimplemented feature, and the scenario is kept so the gap stays visible:
  #
  #   * `mvmctl machine run --healthcheck/--health-interval/--health-retries`
  #     parse and persist into the machine spec (`mvm-runtime`'s
  #     `machine::persist::MachineSpec::health_check`). The flag help says
  #     "Record check interval", "Record failures before unhealthy" — record,
  #     not run.
  #   * `mkGuest`'s `healthChecks` attribute is accepted and carried in
  #     `passthru.mvm.unenforced`, explicitly not acted on.
  #   * `mvm-agentd`'s `probes` module has the serde types and a drop-in
  #     loader, and no command execution or interval loop.
  #
  # Health checking is declared on three surfaces and executed on none.
  # Un-tag this and write the steps in the same change that lands the prober.
  @wip
  Scenario: A persistent machine with a healthcheck is actively probed
    Given a scenario awaiting its step implementation

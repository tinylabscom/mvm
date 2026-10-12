Feature: A detached machine's output is collected for the VM lifetime

  Collection must be owned by the runtime for the life of the VM, not by the
  CLI invocation that happened to boot it. A machine booted detached and later
  reached from another process must still leave a durable, readable record.

  # BLOCKED — the collector is VM-lifetime now, but workload output is not
  # one of its sources yet. This is not an unwritten test; it is an
  # unimplemented feature, and the scenario keeps the gap visible:
  #
  #   * Every fresh boot and every warm-claimed child has a host collector
  #     owned for the VM's life, independent of the CLI that booted it; a
  #     detached machine's agent diagnostics are durably readable through
  #     `mvmctl machine telemetry` (see guest_diagnostics_collected.feature,
  #     and the live Firecracker and HVF witnesses in
  #     `specs/telemetry/certification.md`).
  #   * The guest's stdout/stderr producers (`ProducerId::Stdout`/`Stderr`)
  #     are reserved but unwired, so a detached workload's output reaches
  #     neither the collector nor any other durable copy. The stream plane's
  #     gap regression `a_machine_booted_by_another_process_has_no_durable_copy_here`
  #     still holds.
  #
  # Un-tag this and write the steps in the same change that wires workload
  # stdio into guest capture.
  @wip
  Scenario: Output of a machine booted by another process is durably readable
    Given a scenario awaiting its step implementation

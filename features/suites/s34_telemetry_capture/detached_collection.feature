Feature: A detached machine's output is collected for the VM lifetime

  Collection must be owned by the runtime for the life of the VM, not by the
  CLI invocation that happened to boot it. A machine booted detached and later
  reached from another process must still leave a durable, readable record.

  # BLOCKED — collection is process-local today. This is not an unwritten
  # test; it is an unimplemented feature, and the scenario keeps the gap
  # visible:
  #
  #   * `mvm-hostd`'s stream plane registers captures per process: a call
  #     dispatched into a machine some other process booted gets a
  #     record-nothing sink, so the bytes reach the caller and nothing else —
  #     pinned by the gap regression
  #     `a_machine_booted_by_another_process_has_no_durable_copy_here`, which
  #     asserts today's deficient behavior and must flip into the positive
  #     contract in the same change that lands the VM-lifetime collector.
  #   * The per-VM Telemetry vsock endpoint is already provisioned on every
  #     backend; what is missing is a guest listener and a host collector
  #     supervised independently of any CLI attachment.
  #
  # Un-tag this and write the steps in the same change that lands the
  # VM-lifetime host collector.
  @wip
  Scenario: Output of a machine booted by another process is durably readable
    Given a scenario awaiting its step implementation

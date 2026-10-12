@telemetry_collection
Feature: A detached machine's output is collected for the VM lifetime

  Collection must be owned by the runtime for the life of the VM, not by the
  CLI invocation that happened to boot it. A machine booted detached and later
  reached from another process must still leave a durable, readable record.

  The workload's stdout and stderr are offered to guest capture by the agent's
  pipe readers, carried over the authenticated capture session, sealed by the
  host collector, and read back with no guest RPC. The live witness on
  Firecracker is in `specs/telemetry/certification.md`. The stream plane's
  own gap regression `a_machine_booted_by_another_process_has_no_durable_copy_here`
  still holds: that plane keeps no per-VM copy; this collector does.

  Scenario: Output of a machine booted by another process is durably readable
    Given an isolated mvm home
    And a machine "detached" whose detached workload wrote to stdout and stderr
    When I run mvmctl in the isolated mvm home with "machine telemetry detached"
    Then the command exits with code 0
    And the output contains "stdout bdd-out-line"
    And the output contains "stderr bdd-err-line"

Feature: Workload lifecycle correctness

  A transient microVM tears down cleanly on entrypoint exit, and its
  reported exit code is sourced from the vsock-audited workload result
  rather than guessed at the host boundary.

  @wip
  Scenario: A transient run tears down on entrypoint exit with the sourced exit code
    Given a scenario awaiting its step implementation

  @wip
  Scenario: A persistent machine with a healthcheck is actively probed
    Given a scenario awaiting its step implementation

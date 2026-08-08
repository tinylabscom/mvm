@sdk
Feature: Durable agent session contract
  Agent adapters share bounded, replayable history while live deltas and
  private prompt bytes remain outside durable session records.

  Scenario: prompt retry and durable history are safe
    Given a newly opened durable agent session
    When I submit the private prompt "private credential"
    And I retry the same prompt
    Then the prompt retry is acknowledged without re-execution
    And durable history excludes prompt bytes

  Scenario: a reconnect can rebuild state after adapter restart
    Given a newly opened durable agent session
    When I submit the private prompt "restart-safe"
    And I complete the prompt successfully
    And I reconnect from the durable cursor
    Then adapter restart restores the completed state

  Scenario: live output is ephemeral and cancellation is durable
    Given a newly opened durable agent session
    When I emit the live delta "transient output"
    Then the live delta is absent from durable history
    When I cancel and confirm the session
    Then the durable session state is canceled

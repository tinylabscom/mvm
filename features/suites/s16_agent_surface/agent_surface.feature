Feature: s16_agent_surface

  Conformance scenario for MVM-SEC-04.

  @MVM-SEC-04 @build @wip
  Scenario: Production guest agent builds exclude do_exec
    Given the scenario is registered for MVM-SEC-04
    When the suite for MVM-SEC-04 is implemented
    Then the witness tests pass

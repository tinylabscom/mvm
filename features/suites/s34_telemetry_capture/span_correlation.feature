@telemetry_collection
Feature: Guest spans reach the host with their parent and their events

  A span the guest agent opens must reach host collection as a span, not as
  a loose sequence of events: its parent recorded, its trace shared with that
  parent, the events emitted inside it correlated to it, and its close
  recorded. The guest agent's capture subscriber tracks open spans in a
  fixed-capacity table and never waits; the authenticated capture session
  carries the records, the host collector seals them, and the operator reads
  them back without touching the guest.

  Scenario: A child span and its event are shown inside their parent
    Given an isolated mvm home
    And a machine "spans" whose guest agent emitted an event inside a child span
    When I run mvmctl in the isolated mvm home with "machine telemetry spans"
    Then the command exits with code 0
    And the output contains "span open bdd-parent"
    And the output contains "span open bdd-child"
    And the span "bdd-parent" is shown as the parent of span "bdd-child"
    And the event "bdd event in child" is shown inside span "bdd-child"
    And the span "bdd-child" is shown closed
    And the span "bdd-parent" is shown closed
    And the output does not contain "incomplete spans"

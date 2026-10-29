@telemetry_collection
Feature: Events outside any span are collected as standalone records

  Every guest event must reach host collection, including events emitted
  outside any span, as an event of its own — not attached to a fabricated span
  and not dropped. The guest agent's capture subscriber records it, the
  authenticated capture session carries it, the host collector seals it, and
  the operator reads it back without touching the guest.

  Scenario: An event emitted outside any span reaches the host collector
    Given an isolated mvm home
    And a machine "events" whose guest agent emitted an event outside any span
    When I run mvmctl in the isolated mvm home with "machine telemetry events"
    Then the command exits with code 0
    And the output contains "events: collector collecting"
    And the output contains "event warn"
    And the output contains "bdd standalone event"
    And the output does not contain "span="

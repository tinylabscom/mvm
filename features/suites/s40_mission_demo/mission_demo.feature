Feature: The three-node mission demo contains, terminates and rebuilds

  The scripted demo (`crates/mvm-hostd/tests/mission_demo.rs`) runs an aircraft,
  a ship and a ground vehicle, each with its own state directory and signed
  audit chain. These scenarios run that script and assert on what it reports.

  What this does not show, and the demo says so itself: node-to-node delivery
  is a loopback TCP transport between two node services in one test process
  (the guest mailbox is served by a separate host process), not Iroh or a
  relay (tracked in #4633), not different physical hosts, and no VM boots.

  Scenario: The compromised workload is contained and replaced in the audit timeline
    When the scripted mission demo runs
    Then the demo passes
    And the evidence timeline lists, in order, launch, the denials, quarantine, replacement and relaunch

  Scenario: The demo states what it simulates
    When the scripted mission demo runs
    Then the demo passes
    And the demo output says the mailbox is local-only and the VMs are simulated

  Scenario: Two nodes deliver a sealed message over a loopback TCP transport
    When the scripted mission demo runs
    Then the demo passes
    And the cross-node delivery test ran and passed

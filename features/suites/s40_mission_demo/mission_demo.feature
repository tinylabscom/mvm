Feature: The three-node mission demo contains, terminates and rebuilds

  The scripted demo (`crates/mvm-hostd/tests/mission_demo.rs`) runs an aircraft,
  a ship and a ground vehicle, each with its own state directory and signed
  audit chain. These scenarios run that script and assert on what it reports.

  What this does not show, and the demo says so itself: the mailbox transport
  is in memory (the vsock service and relay are tracked in #4629 and #4633),
  and no VM boots. There is no live node-to-node delivery here.

  Scenario: The compromised workload is contained and replaced in the audit timeline
    When the scripted mission demo runs
    Then the demo passes
    And the evidence timeline lists, in order, launch, the denials, quarantine, replacement and relaunch

  Scenario: The demo states what it simulates
    When the scripted mission demo runs
    Then the demo passes
    And the demo output says the mailbox transport and the VMs are simulated

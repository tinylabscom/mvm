Feature: The three-node mission demo contains, terminates and rebuilds

  The scripted demo (`crates/mvm-hostd/tests/mission_demo.rs`) runs an aircraft,
  a ship and a ground vehicle, each with its own state directory and signed
  audit chain. These scenarios run that script and assert on what it reports.

  What this does not show, and the demo says so itself: the three nodes are
  simulated nodes in one process, their VMs are gated and audited but none
  boots, and node-to-node delivery is a loopback TCP transport (not Iroh, #4633,
  and not different physical hosts). A booted guest's mailbox was witnessed by
  hand, separately, on a Firecracker host (many messages per VM) and on an HVF
  host (macOS 26+ Apple Silicon; one message per VM, a re-witness is pending);
  neither is a CI lane, and the "Demo status" section of
  specs/contracts/host-interface-distributed-execution.md records both.
  The production helper scenario below exercises the real local journal and
  guest wire over a loopback socket; it is not a booted-VM or host-blind witness.

  Scenario: The compromised workload is contained and replaced in the audit timeline
    When the scripted mission demo runs
    Then the demo passes
    And the evidence timeline lists, in order, launch, the denials, quarantine, replacement and relaunch

  Scenario: The demo states what it simulates
    When the scripted mission demo runs
    Then the demo passes
    And the demo output says the nodes and VMs are simulated and the mailbox is not cross-host

  Scenario: Two nodes deliver a sealed message over a loopback TCP transport
    When the scripted mission demo runs
    Then the demo passes
    And the cross-node delivery test ran and passed

  Scenario: A production helper persists a local receipt and guest ACK
    When the production mailbox helper witness runs
    Then the production mailbox helper witness passes

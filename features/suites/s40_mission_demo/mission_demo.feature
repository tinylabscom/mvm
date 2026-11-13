Feature: The three-node mission demo contains, terminates and rebuilds

  The scripted demo (`crates/mvm-hostd/tests/mission_demo.rs`) runs an aircraft,
  a ship and a ground vehicle, each with its own state directory and signed
  audit chain. These scenarios run that script and assert on what it reports.

  What this does not show, and the demo says so itself: the three nodes are
  simulated nodes in one process, their VMs are gated and audited but none
  boots, and node-to-node delivery is a loopback TCP transport (not Iroh, #4633,
  and not different physical hosts). The legacy guest mailbox was witnessed
  manually on Firecracker and HVF; those manual runs are not CI lanes. The
  tagged live scenario below instead boots Firecracker to witness the
  trusted-host local-durable path. It is not a cross-host or HVF witness.
  The "Demo status" section of
  specs/contracts/host-interface-distributed-execution.md records the earlier runs.
  The production helper scenario below exercises the real local journal and
  guest wire over a loopback socket; it is not a booted-VM or host-blind witness.
  The live scenario checks a real guest's Send and Receive/ACK, then runs that
  separate host-process restart test. It does not restart the helper while the
  booted guest is still running.

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

  @live @firecracker @ci_live @mailbox_live
  Scenario: a booted guest verifies local durability and acknowledges a delivery
    When the booted local-durable mailbox witness runs
    Then the booted local-durable mailbox witness passes
    And the production helper recovers the signed ACK and same-ID retry

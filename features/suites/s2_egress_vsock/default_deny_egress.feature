Feature: Default-deny egress through the auditable vsock seam

  No untrusted workload reaches the network unless explicitly admitted by
  policy, and every workload backend mediates egress through the vsock seam
  rather than a bypassable host NIC/TAP.

  @wip
  Scenario: An unadmitted workload cannot reach the network
    Given a scenario awaiting its step implementation

  @wip
  Scenario: An admitted allow-rule reaches only its approved endpoint
    Given a scenario awaiting its step implementation

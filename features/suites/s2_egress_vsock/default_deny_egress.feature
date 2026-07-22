Feature: Default-deny egress through the auditable vsock seam

  No untrusted workload reaches the network unless explicitly admitted by
  policy, and every workload backend mediates egress through the vsock seam
  rather than a bypassable host NIC/TAP.

  Scenario: Host mediates egress over vsock, not a NIC
    When I run mvmctl with "doctor"
    Then the output contains "network-backend: OK (direct vsock only; no host gateway binary is part of the active runtime contract)"
    And the output contains "network policy default (claim 10): OK (deny_all (claim 10 holds — egress refused unless explicitly admitted))"

  Scenario Outline: An unadmitted workload defaults to deny on every backend
    When I run mvmctl with "machine run --image alpine --name bdd-egress-deny-<backend> -d --hypervisor <backend> --dry-run"
    Then the command exits with code 0
    And the output contains "network: deny-all"
    And the output contains "enforced: flow-drop"

    Examples:
      | backend     |
      | hvf         |
      | libkrun     |
      | firecracker |

  Scenario Outline: Every workload backend mediates admitted egress over the vsock seam, not a NIC
    When I run mvmctl with "machine run --image alpine --name bdd-egress-allow-<backend> -d --hypervisor <backend> --allow-host example.com --dry-run"
    Then the command exits with code 0
    And the output contains "network: allow-list:example.com:443"
    And the output contains "enforced: <backend>:l4-host-port"

    Examples:
      | backend |
      | hvf     |
      | libkrun |

  # Firecracker is not yet vsock-only on main: an OCI --image run with an
  # allow-host rule under --hypervisor firecracker refuses admission instead
  # of confirming vsock-mediated egress, because the firecracker backend does
  # not yet advertise the vsock/no-routable-guest-nic/host-vsock-proxy
  # capability set the other two backends do. This scenario states the
  # definition-of-done a later firecracker driver change flips to passing —
  # drop the @wip tag once it does, and fold this row back into the
  # Scenario Outline above.
  @wip
  Scenario: Firecracker mediates admitted egress over the vsock seam, not a NIC
    When I run mvmctl with "machine run --image alpine --name bdd-egress-allow-firecracker -d --hypervisor firecracker --allow-host example.com --dry-run"
    Then the command exits with code 0
    And the output contains "network: allow-list:example.com:443"
    And the output contains "enforced: firecracker:l4-host-port"

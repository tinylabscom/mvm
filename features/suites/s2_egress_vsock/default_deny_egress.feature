Feature: Default-deny egress through the auditable vsock seam

  No untrusted workload reaches the network unless explicitly admitted by
  policy, and every workload backend mediates egress through the vsock seam
  rather than a bypassable host NIC/TAP.

  Scenario: Host mediates egress over vsock, not a NIC
    When I run mvmctl with "doctor"
    Then the output contains "network-backend: OK (direct vsock only; no host gateway binary is part of the active runtime contract)"
    And the output contains "network policy default (claim 10): OK (deny_all (claim 10 holds — egress refused unless explicitly admitted))"

  Scenario Outline: An unadmitted workload defaults to deny on every backend
    When I run mvmctl in an isolated live home with "machine run --image alpine --name bdd-egress-deny-<backend> -d --hypervisor <backend> --dry-run"
    Then the command exits with code 0
    And the output contains "network: deny-all"
    And the output contains "enforced: flow-drop"

    Examples:
      | backend     |
      | hvf         |
      | libkrun     |
      | firecracker |

  Scenario Outline: Every workload backend mediates admitted egress over the vsock seam, not a NIC
    When I run mvmctl in an isolated live home with "machine run --image alpine --name bdd-egress-allow-<backend> -d --hypervisor <backend> --allow-host example.com --dry-run"
    Then the command exits with code 0
    And the output contains "network: allow-list:example.com:443"
    And the output contains "enforced: <backend>:l4-host-port"

    Examples:
      | backend |
      | hvf     |
      | libkrun |
      | firecracker |

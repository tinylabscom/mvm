Feature: Admitted egress completes end-to-end over the vsock seam

  An allow-listed destination reached through the in-guest proxy connects and
  returns real bytes: the host confirms the outbound connect before the guest
  reports success, and it tries every admitted address so an unreachable IPv6
  pin never strands the request.

  @live
  Scenario: An admitted https destination returns its page body
    When I run mvmctl with "machine run --image alpine --allow-host example.com -- wget -q -O - https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"

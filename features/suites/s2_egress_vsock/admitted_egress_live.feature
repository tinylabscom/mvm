Feature: Admitted egress completes end-to-end over the vsock seam

  An allow-listed destination reached through the in-guest proxy connects and
  returns real bytes: the host confirms the outbound connect before the guest
  reports success, and it tries every admitted address so an unreachable IPv6
  pin never strands the request.

  @live @tls_tunnel_client
  Scenario: An admitted name resolves and connects through the in-seam resolver
    When I run mvmctl with "machine run --image curlimages/curl:8.21.0 --allow-host example.com -- curl -fsSL https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"

  @live @tls_tunnel_client
  Scenario: An admitted IPv6 literal falls back to its pinned IPv4 sibling
    When I run mvmctl with "machine run --image curlimages/curl:8.21.0 --allow-host one.one.one.one -- curl -kfsSL -H Host:one.one.one.one https://[2606:4700:4700::1111]/cdn-cgi/trace" with a 120 second timeout
    Then the command exits with code 0
    And the output contains "fl="

  @live
  Scenario: A non-admitted name is refused, not resolved
    When I run mvmctl with "machine run --image curlimages/curl:8.21.0 --allow-host example.com -- curl -fsSL https://not-admitted.test"
    Then the command exits with code 22

  @live @tls_tunnel_client
  Scenario: DNS queries land in the chain-signed audit log
    When I run mvmctl with "machine run --image curlimages/curl:8.21.0 --allow-host example.com -- curl -fsSL https://example.com"
    Then the command exits with code 0
    When I run mvmctl with "trust audit verify"
    Then the command exits with code 0
    When I run mvmctl with "trust audit tail --chain --lines 50"
    Then the command exits with code 0
    And the output contains "dns.resolved"

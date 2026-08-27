Feature: HVF admitted egress is observable and does not hang

  The per-VM substitution endpoint initializes a rustls crypto provider before
  making outbound HTTPS requests. Without it the endpoint panics, the guest's
  egress client writes to a dead UDS, and the workload hangs until an external
  timeout kills it. Endpoint diagnostics must also be capturable on disk instead
  of being discarded to /dev/null.

  @live @tls_tunnel_client
  Scenario: Admitted HTTPS egress completes instead of hanging
    When I run mvmctl with "machine run --image alpine --allow-host httpbin.org -- wget -q -O - https://httpbin.org/get" with a 120 second timeout
    Then the command exits with code 0
    And the output contains "httpbin.org"

  @live
  Scenario: A multi-wheel pandas install arrives without truncation
    When I run mvmctl with "machine run --image python:3.12 --allow-host pypi.org:443 --allow-host files.pythonhosted.org:443 -- python -m pip install --no-cache-dir pandas" with a 300 second timeout
    Then the command exits with code 0
    And the output contains "Successfully installed"

  @live
  Scenario: Substitution endpoint diagnostics are written to /tmp
    When I run mvmctl with "machine run --name bdd-subst-log --image alpine --allow-host httpbin.org -- wget -q -O - https://httpbin.org/get" with a 120 second timeout
    Then the command exits with code 0
    And the file "/tmp/mvm-substitution-endpoint-bdd-subst-log.log" exists
    And the file "/tmp/mvm-substitution-endpoint-bdd-subst-log.log" contains "substitution endpoint bound"

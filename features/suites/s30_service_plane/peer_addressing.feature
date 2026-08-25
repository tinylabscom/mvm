Feature: A workload addresses a peer by name over the one egress decision point

  A workload microVM has no NIC. Every outbound connection is decided at one
  host-side gate, and east-west traffic reuses that path rather than opening a
  second one: the guest dials a name, the host resolves it, and the guest never
  learns an address.

  These scenarios drive the real `EgressGate`, so no VM starts and they gate on
  every PR. A two-VM witness is a separate, still-missing piece.

  Scenario: a gate with no peer bindings admits no peer
    Given a workload gate with no peer bindings
    When the workload dials peer "db.mvm.peer" on port 5432
    Then the peer dial is refused
    And the refusal says no peers are admitted

  Scenario: an admitted peer route resolves to the peer's ingress address
    Given a workload gate binding peer "db.mvm.peer" port 5432 to "127.0.0.1:34567"
    When the workload dials peer "db.mvm.peer" on port 5432
    Then the peer dial is allowed to "127.0.0.1" port 34567

  # A binding authorizes one route, not a host: the same peer on another port
  # is a destination nobody signed for.
  Scenario: a bound peer on an unbound port is refused
    Given a workload gate binding peer "db.mvm.peer" port 5432 to "127.0.0.1:34567"
    When the workload dials peer "db.mvm.peer" on port 5433
    Then the peer dial is refused
    And the refusal names the admitted route "db.mvm.peer:5432"

  Scenario: an unbound peer name is refused
    Given a workload gate binding peer "db.mvm.peer" port 5432 to "127.0.0.1:34567"
    When the workload dials peer "cache.mvm.peer" on port 5432
    Then the peer dial is refused

  # The branch is claimed on the suffix alone, so a malformed peer name is
  # refused at peer resolution rather than looked up as a public host.
  Scenario: a malformed peer name is refused, not resolved as a host
    Given a workload gate binding peer "db.mvm.peer" port 5432 to "127.0.0.1:34567"
    When the workload dials peer "-db.mvm.peer" on port 5432
    Then the peer dial is malformed

  Scenario: admitting a peer does not widen ordinary egress
    Given a workload gate binding peer "db.mvm.peer" port 5432 to "127.0.0.1:34567"
    When the workload dials host "127.0.0.1" on port 34567
    Then the egress dial is refused

  Scenario Outline: every peer decision is attributed to the peer route
    Given a workload gate with no peer bindings
    When the workload dials peer "<target>" on port 5432
    Then the decision is attributed to the "peer" route

    Examples:
      | target        |
      | db.mvm.peer   |
      | -db.mvm.peer  |

  Scenario: an ordinary host is attributed to the egress route
    Given a workload gate with no peer bindings
    When the workload dials host "api.example.com" on port 443
    Then the decision is attributed to the "egress" route

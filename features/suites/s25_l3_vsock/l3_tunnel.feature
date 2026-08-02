Feature: L3 TUN-over-vsock tunnel

  The opt-in l3-vsock mode gives a workload a real IP stack without giving
  it a NIC. Every packet still crosses the vsock boundary and is admitted by
  the host before it reaches host networking.

  These scenarios are decidable without a VM: they exercise the launch
  guard, the admission core, the DNS binding store, and the session/lease
  identity model directly, so they run in the hermetic lane.

  Scenario: the guest gets no network device in l3-vsock mode
    Given a machine that selects the l3-vsock network mode
    Then the backend it selects advertises no routable guest NIC
    And the launch specification carries no guest network-device field

  Scenario: a backend that only drains a NIC cannot serve the tunnel
    Given a machine that selects the l3-vsock network mode
    When it is checked against a backend that drains a NIC instead of omitting one
    Then the launch is refused naming the missing tunnel capability

  Scenario: selecting l3-vsock never falls back to the brokered mode
    Given a machine that selects the l3-vsock network mode
    When it is checked against a backend that offers only the brokered mode
    Then the launch is refused rather than degraded

  Scenario: an egress rule does not imply the l3-vsock mode
    Given a machine run that declares an allowed host but no network mode
    Then the selected network mode is the socket-aware default

  Scenario: a packet with an admitted destination and port is forwarded
    Given an admitted L3 session that allows "93.184.216.34:443"
    When the guest sends a TCP packet to "93.184.216.34:443"
    Then the packet is forwarded to the host network

  Scenario: a packet to an unadmitted port is refused
    Given an admitted L3 session that allows "93.184.216.34:443"
    When the guest sends a TCP packet to "93.184.216.34:8080"
    Then the packet is refused with reason "port_not_admitted"

  Scenario: a packet to an unadmitted destination is refused
    Given an admitted L3 session that allows "93.184.216.34:443"
    When the guest sends a TCP packet to "1.2.3.4:443"
    Then the packet is refused with reason "destination_not_admitted"

  Scenario: a spoofed source address is refused
    Given an admitted L3 session that allows "93.184.216.34:443"
    When the guest sends a TCP packet from a source it was not assigned
    Then the packet is refused with reason "spoofed_source"

  Scenario: cloud metadata stays unreachable even under an open policy
    Given an admitted L3 session with unrestricted egress
    When the guest sends a TCP packet to "169.254.169.254:80"
    Then the packet is refused with reason "link_local_denied"

  Scenario: private ranges are denied by default
    Given an admitted L3 session with unrestricted egress
    When the guest sends a TCP packet to "10.0.0.5:80"
    Then the packet is refused with reason "private_range_denied"

  Scenario: IP fragments are refused rather than reassembled
    Given an admitted L3 session that allows "93.184.216.34:443"
    When the guest sends a fragmented packet to "93.184.216.34:443"
    Then the packet is refused with reason "fragment_refused"

  Scenario: unsolicited inbound traffic is dropped
    Given an admitted L3 session that allows "93.184.216.34:443"
    When an unsolicited packet arrives for the guest
    Then the inbound packet is refused with reason "unsolicited_inbound"

  Scenario: return traffic for an admitted flow is delivered
    Given an admitted L3 session that allows "93.184.216.34:443"
    When the guest sends a TCP packet to "93.184.216.34:443"
    And the peer replies on the same flow
    Then the inbound packet is delivered to the guest

  Scenario: a declared ingress mapping admits a new inbound flow
    Given an admitted L3 session that allows "93.184.216.34:443"
    And a declared TCP ingress mapping to guest port 80
    When an inbound packet arrives for guest port 80
    Then the inbound packet is delivered to the guest

  Scenario: controlled DNS opens only what it resolved
    Given an admitted L3 session with deny-all egress
    When the host resolver admits "api.example.com" as "93.184.216.34"
    Then the guest may reach "93.184.216.34:443"
    But the guest may not reach "93.184.216.99:443"

  Scenario: a DNS answer that rebinds into loopback is refused
    Given an admitted L3 session with deny-all egress
    Then binding "evil.example.com" to "127.0.0.1" is refused

  Scenario: a DNS answer that rebinds into a private range is refused
    Given an admitted L3 session with deny-all egress
    Then binding "intranet.example.com" to "192.168.1.10" is refused

  Scenario: a restart inherits no session, address, or flow state
    Given an admitted L3 session that allows "93.184.216.34:443"
    And the guest has an established flow
    When the machine restarts
    Then the new session differs from the previous one
    And the new session has no flows

  Scenario: a lease cannot be replayed onto a later boot
    Given a locally issued network lease for one VM boot
    When the same lease is presented for a different boot of that machine
    Then the lease is refused

  Scenario: a lease cannot be used on another node
    Given a locally issued network lease for one VM boot
    When the same lease is presented on a different node
    Then the lease is refused

  Scenario: an expired lease fails closed
    Given a locally issued network lease for one VM boot
    When the lease validity window has passed
    Then the lease is refused

  Scenario: losing the control plane never opens networking up
    Then no control-plane loss policy permits traffic after lease expiry

  Scenario: a host backend that cannot serve the plan fails admission
    Given a forwarding backend that only translates host sockets
    When a plan requires arbitrary packet forwarding
    Then admission reports the missing forwarding capabilities

  Scenario: control and packet traffic use separate vsock services
    Then the network control and network data services use different ports
    And neither shares the machine-control service port

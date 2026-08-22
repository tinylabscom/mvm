Feature: One transport between a guest and its host endpoint

  Every byte a guest sends its host endpoint crosses one authenticated FlowMux
  session on the NetworkFlow vsock port. The guest cannot speak anything else,
  so the host must not offer anything else — and the material the session needs
  must actually be produced by the host that pins it.

  These scenarios are hermetic: each one drives the real host writer and the
  real guest reader through library calls, boots no VM, and touches no network,
  so they gate every PR rather than waiting on the `@live` lane. That matters
  here specifically. The regression these exist for shipped a guest that
  required a signing key no host code wrote, and every test in the tree stayed
  green because nothing compared the two sides.

  # The failure was not "a key was wrong". It was "the guest read a file the
  # host never wrote". So the assertion is that the host's output satisfies the
  # guest's own reader — not that each side is internally consistent.
  Scenario: The guest reader finds what the host writer produced
    Given a host-minted FlowMux identity drive
    When the guest identity reader inspects it
    Then the drive carries the guest signing key
    And the drive carries the host-signer trust anchor
    And the guest finds the drive by the label the host stamped

  # A per-boot identity that repeats across boots is not per-boot.
  Scenario: Each boot mints a distinct guest identity
    Given a host-minted FlowMux identity drive
    And a second host-minted FlowMux identity drive
    Then the two drives carry different guest keys

  # The private halves must not leak host-side. The guest signing key belongs
  # only in the drive; the host signer's key belongs only in the keystore.
  Scenario: The inheritable identity carries no private key
    Given a host-minted FlowMux identity drive
    When the host persists the half a warm child inherits
    Then the persisted identity carries no guest signing key
    And the persisted identity carries no host signing key

  # This is the mode-selection fork that let the two sides disagree. There is
  # no third answer any more: "raw" is not selectable and the guest cannot
  # speak it.
  Scenario: A boot with an identity selects the authenticated transport
    When the host builds an endpoint config with a FlowMux identity
    Then the endpoint is told to serve "flow_mux"
    And the endpoint config carries the guest verifying key

  Scenario: No endpoint config can select the retired raw protocol
    When the host builds an endpoint config with a FlowMux identity
    And the host builds an endpoint config without a FlowMux identity
    Then no endpoint config selects "raw"

  # The regression that started this: a guest made FlowMux-only while every
  # host spawn site still selected the old protocol. Both halves were
  # internally consistent, so nothing failed until someone booted a VM. This
  # compares the two sides instead of each side against itself.
  Scenario: There is exactly one guest→host protocol
    When the one-protocol gate inspects the tree
    Then it finds no retired line-marker protocol
    And every guest dialer of the egress port is a FlowMux client

  # `ping` and secret substitution used to dial the same port and speak
  # something else. Both are typed flows on the session now, so the opcodes
  # they need must be part of the contract rather than an extension.
  Scenario: The session carries every guest verb
    When the wire contract is enumerated
    Then a typed HTTP flow is part of it
    And a one-shot ICMP echo is part of it

  # A placeholder with nothing to resolve it is worse than no network: the
  # guest sends `mvm-secret-<hex>` to a real upstream.
  Scenario: A secret-bearing workload boots only when substitution is live
    Given an endpoint config carrying a secret
    Then it refuses to serve without a substitution service
    And it is admitted with one

  # An endpoint reports ready before the guest boots, so "ready" alone never
  # meant a guest had reached it.
  Scenario: A launch whose endpoint carried no session is refused
    Given a per-VM state dir whose endpoint is running
    Then a launch is refused because no guest authenticated
    But a launch is admitted once a session is recorded

  # Guest-agent readiness and FlowMux authentication are independent events.
  # A healthy launch must wait for the latter instead of sampling its marker
  # once and falsely diagnosing a missing identity drive.
  Scenario: Allow-host does not race FlowMux authentication
    Given an allow-host endpoint that authenticates after agent readiness
    Then the launch is admitted without the FlowMux identity-drive error

  # A boot with nothing to mediate has no endpoint at all, and must not be
  # caught by the check above.
  Scenario: A launch with no endpoint at all is not refused
    Given a per-VM state dir with no endpoint
    Then the launch is admitted

  Scenario: Declared ingress is an authenticated FlowMux operation
    Given a signed exact TCP ingress mapping
    Then the mapping targets only guest loopback
    And an admitted host-initiated stream names only that mapping
    But an undeclared host-initiated stream is refused

  Scenario: TLS ingress keeps private material behind the endpoint
    Given a signed TLS ingress mapping with a same-plan keystore reference
    Then the TLS ingress material binding is admitted
    And the serialized mapping contains only the secret reference

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

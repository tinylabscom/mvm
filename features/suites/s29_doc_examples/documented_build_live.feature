Feature: The documented flake build runs for real

  `mvmctl machine build --flake .` is the build command the README and the Nix
  guide teach, and the hermetic tiers can only prove it parses. Building runs
  `nix build` inside the builder VM, so the witness is opt-in via
  `MVM_BDD_LIVE` like every other real-VM scenario.

  This is what backs the `machine build` entry's `live` tier in
  `tiers.toml`; without it, that tier would be a label with nothing behind it.

  @live @release_gate_flake
  Scenario: the documented flake build produces an image
    When I run mvmctl in an isolated live home with "machine build --flake examples/exit_code"
    Then the command exits with code 0

  # The last step of the README's "from dev loop to attested image" flow, and
  # the only one nothing ran: `build compile` was covered, `machine build` was
  # covered, and booting the result under its own entrypoint was not. The
  # hermetic suite proves `--entrypoint` is *refused* against an OCI image,
  # which is the opposite claim from the flake form working.
  #
  # Shares this feature rather than the launch suite because the builder VM is
  # the expensive part and this scenario reuses what the one above just built.
  @live @release_gate_flake
  Scenario: the documented entrypoint launch runs the compiled workload
    When I run mvmctl in an isolated live home with "machine run --entrypoint --flake examples/exit_code"
    Then the command exits with code 7

  # The image a builder VM produced, sealed on the host that ran it and
  # installed somewhere else. The builder is untrusted and never holds the
  # signing key: `bundle export` signs on the host, after the build is done,
  # and a second home that trusts only the signer's public half verifies and
  # installs the result without booting it. Reuses the build above.
  @live
  Scenario: the documented flake build seals into a host-signed bundle another home installs
    When I run mvmctl in an isolated live home with "machine build --flake examples/exit_code"
    Then the command exits with code 0
    When I seal the live build of "examples/exit_code" into a bundle
    Then the command exits with code 0
    When I install the sealed bundle into a fresh home that trusts its builder
    Then the command exits with code 0
    And the install reports a bundle content address

Feature: The documented flake build runs for real

  `mvmctl machine build --flake .` is the build command the README and the Nix
  guide teach, and the hermetic tiers can only prove it parses. Building runs
  `nix build` inside the builder VM, so the witness is opt-in via
  `MVM_BDD_LIVE` like every other real-VM scenario.

  This is what backs the `machine build` entry's `live` tier in
  `tiers.toml`; without it, that tier would be a label with nothing behind it.

  @live
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
  @live
  Scenario: the documented entrypoint launch runs the compiled workload
    When I run mvmctl in an isolated live home with "machine run --entrypoint --flake examples/exit_code"
    Then the command exits with code 7

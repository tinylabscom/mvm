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

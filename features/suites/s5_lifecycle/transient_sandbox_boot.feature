Feature: Transient sandbox boot

  A transient microVM can be launched successfully from both OCI and Nix
  sources, can reach an admitted host, and cleans up its host state directory
  after the guest exits. These scenarios boot a real VM, so they are opt-in via
  `MVM_BDD_LIVE`.

  @live
  Scenario: machine run boots a transient sandbox from an OCI image
    When I run mvmctl in an isolated live home with "machine run --name bdd-oci-boot --image alpine --timeout 120 -- /bin/echo mvm-bdd-oci-hello"
    Then the command exits with code 0
    And the output contains "mvm-bdd-oci-hello"

  @live
  Scenario: machine run boots a transient sandbox from a Nix flake
    When I run mvmctl in an isolated live home with "machine run --name bdd-nix-boot --flake examples/exit_code --timeout 120"
    Then the command exits with code 7

  @live
  Scenario: machine run reaches an admitted host with ping
    When I run mvmctl in an isolated live home with "machine run --name bdd-egress-ping --image alpine --allow-host google.com --timeout 120 -- /bin/ping -c 1 google.com"
    Then the command exits with code 0
    And the output contains "1 received"

  @live
  Scenario: machine run removes the transient VM state directory on guest exit
    Given an isolated mvm home
    When I run mvmctl in an isolated live home with "machine run --name bdd-transient-cleanup --image alpine --timeout 120 -- /bin/echo mvm-bdd-cleanup-marker"
    Then the command exits with code 0
    And the output contains "mvm-bdd-cleanup-marker"
    And the isolated mvm home does not contain directory "vms/bdd-transient-cleanup"

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

  # The universal initramfs made the agent PID 1 and, for a while, carried over
  # only the mounting half of the older init. A workload booted with `lo` down
  # and nothing listening on the loopback proxy port, so every egress attempt
  # failed as `Network unreachable` — while the proxy environment variables were
  # still exported, which made it read as a broken network rather than as a
  # policy denial. This is that regression, as a scenario.
  @live
  Scenario: a workload reaches an admitted host over the mediated egress path
    When I run mvmctl in an isolated live home with "machine run --name bdd-egress-https --image alpine --allow-host example.com --timeout 180 -- wget -q -O- https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"

  # Unqualified, so the mediated stand-in on PATH satisfies it. A NIC-less guest
  # has no raw socket, so the image's own ping fails at `socket()`; the host
  # performs the echo over vsock on the guest's behalf.
  @live
  Scenario: machine run reaches an admitted host with an unqualified ping
    When I run mvmctl in an isolated live home with "machine run --name bdd-egress-ping-path --image alpine --allow-host google.com --timeout 180 -- ping -c 1 google.com"
    Then the command exits with code 0
    And the output contains "1 received"

  # Still open, and for one specific reason: `/bin/ping` by absolute path is not
  # satisfied by a PATH-order stand-in, and the bind mount that would satisfy it
  # cannot apply here. `/bin/ping` on a busybox image is a symlink to the
  # multi-call binary, replacing that link needs a write, and the rootfs is
  # read-only under verity. The unqualified scenario above is the same egress
  # path within reach today.
  @live @wip
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

  @live
  Scenario: machine run cleans the request state after claiming a warm standby
    Given an isolated mvm home
    And warm residency is enabled
    When I run mvmctl in an isolated live home with "machine run --image alpine --timeout 120 -- /bin/echo mvm-bdd-warm-seed"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine run --image alpine --timeout 120 -- /bin/echo mvm-bdd-warm-claim"
    Then the command exits with code 0
    And the output contains "Claimed a warm standby ("
    And the isolated mvm home has no transient request state directories

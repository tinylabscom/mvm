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
  Scenario: a named machine observes that name as its guest hostname
    When I run mvmctl in an isolated live home with "machine run --name bdd-guest-hostname --image alpine --timeout 120 -- /bin/hostname"
    Then the command exits with code 0
    And the output contains "bdd-guest-hostname"

  # The verified OCI root stays read-only. Scratch space is a dedicated tmpfs
  # carried from the universal initramfs across the root pivot.
  @live
  Scenario: a sealed OCI workload has writable scratch space
    When I run mvmctl in an isolated live home with "machine run --name bdd-oci-scratch --image alpine --timeout 120 -- mktemp /tmp/mvm-bdd.XXXXXX"
    Then the command exits with code 0
    And the output contains "/tmp/mvm-bdd."

  @live
  Scenario: machine run boots a transient sandbox from a Nix flake
    When I run mvmctl in an isolated live home with "machine run --name bdd-nix-boot --flake examples/exit_code"
    Then the command exits with code 7

  # Only a tier with no wall-clock mechanism refuses this. libkrun and HVF have
  # a per-VM supervisor of ours that outlives the launch and can hold the
  # deadline, so `negotiate_grants` finds no gap and admission accepts the
  # grant — the workload then runs and exits 7, which is correct there and is
  # what the scenario above already witnesses.
  #
  # Untagged, this ran on HVF and asserted a refusal that never came. It looked
  # green for a while regardless, because the exit code it asserts is 1 and a
  # separate bug — a baked entrypoint the host waited for and never dispatched —
  # also exited 1. Two wrongs reading as one right is exactly what a capability
  # gate is for.
  @live @unenforceable_wall_clock
  Scenario: a sealed flake refuses a timeout the backend cannot enforce
    When I run mvmctl in an isolated live home with "machine run --name bdd-nix-timeout --flake examples/exit_code --timeout 120"
    Then the command exits with code 1
    And the error output contains "cannot enforce every declared grant"

  # The universal initramfs made the agent PID 1 and, for a while, carried over
  # only the mounting half of the older init. A workload booted with `lo` down
  # and nothing listening on the loopback proxy port, so every egress attempt
  # failed as `Network unreachable` — while the proxy environment variables were
  # still exported, which made it read as a broken network rather than as a
  # policy denial. This is that regression, as a scenario.
  @live @tls_tunnel_client
  Scenario: a workload reaches an admitted host over the mediated egress path
    When I run mvmctl in an isolated live home with "machine run --name bdd-egress-https --image curlimages/curl:8.21.0 --allow-host example.com --timeout 180 -- curl -fsSL https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"

  # An unqualified allow entry covers the protocol-default HTTPS port.
  @live
  Scenario: machine run reaches an admitted host with an unqualified HTTPS grant
    When I run mvmctl in an isolated live home with "machine run --name bdd-egress-https-unqualified --image curlimages/curl:8.21.0 --allow-host example.com --timeout 180 -- curl -fsSL https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"

  # Explicitly naming port 443 exercises the endpoint-qualified policy shape.
  @live
  Scenario: machine run reaches an admitted host with a port-qualified HTTPS grant
    When I run mvmctl in an isolated live home with "machine run --name bdd-egress-https-qualified --image curlimages/curl:8.21.0 --allow-host example.com:443 --timeout 180 -- curl -fsSL https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"

  @live
  Scenario: machine run removes the transient VM state directory on guest exit
    Given an isolated mvm home
    When I run mvmctl in an isolated live home with "machine run --name bdd-transient-cleanup --image alpine --timeout 120 -- /bin/echo mvm-bdd-cleanup-marker"
    Then the command exits with code 0
    And the output contains "mvm-bdd-cleanup-marker"
    And the isolated mvm home does not contain directory "vms/bdd-transient-cleanup"

  # The cached default development image is shared by every launch that names
  # it and is hashed at admission, so a launch must leave its bytes exactly as
  # it found them. The first run populates the cache when it is empty; the
  # second is the witness.
  @live @firecracker
  Scenario: a transient run leaves the cached default development rootfs byte-identical
    When I run mvmctl in an isolated live home with "run --no-detect -- /bin/true"
    Then the command exits with code 0
    And the cached default development rootfs digest is recorded
    When I run mvmctl in an isolated live home with "run --no-detect -- /bin/true"
    Then the command exits with code 0
    And the cached default development rootfs digest is unchanged
    And the last admitted plan names the cached default development rootfs digest

  # Opt-in (`MVM_BDD_WARM_CLAIM`), and the only scenario that exercises a warm
  # claim end to end. It was gated while a forked child could not answer the
  # post-restore identity handshake; that is fixed on HVF and Firecracker, and
  # the gate now only keeps a slow live claim out of runs that did not ask for
  # one.
  @live @warm_claim
  Scenario: machine run cleans the request state after claiming a warm standby
    Given the live mvm home request state is recorded
    And warm residency is enabled
    When I run mvmctl in an isolated live home with "pool warm 1 --image alpine"
    Then the command exits with code 0
    # `--verbose` because the claim notice is opt-in `[mvm]` chatter, printed to
    # stderr. Without both, this scenario could not pass on any host even when
    # the claim succeeded.
    When I run mvmctl in an isolated live home with "--verbose machine run --image alpine --timeout 120 -- /bin/echo mvm-bdd-warm-claim"
    Then the command exits with code 0
    And the output contains "mvm-bdd-warm-claim"
    And the error output contains "Claimed a warm standby ("
    # A claimed child's run must be bound into the audit chain like a cold
    # boot's. Checked on both streams so a change in where logs go cannot turn
    # this into a check of nothing.
    And the output does not contain "sealed transcript is not anchored"
    And the error output does not contain "sealed transcript is not anchored"
    And the live mvm home has no new transient request state directories

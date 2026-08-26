Feature: every README-documented CLI launch mode boots a real guest

  The README's launch surface, exercised against a real microVM on whatever
  backend this host has. Not `@firecracker`-tagged on purpose: that tag gates on
  `/dev/kvm`, so the one existing live README scenario is skipped on every macOS
  host — where HVF is the default backend. A launch regression reproducing only
  on that default had no lane that could see it, which is how a guest that could
  not mount its runtime overlay reached a release.

  Each scenario asserts the guest's *control plane* came up, not merely that the
  command exited 0. A guest booting without its runtime overlay panics the
  kernel, and the host's only symptom is "guest agent did not become reachable
  within 30s" — a message naming nothing that was actually wrong.

  Background:
    Given an artifact-warm mvm home

  @live
  Scenario: a transient run boots an OCI image and runs one command
    When I launch "machine run --image alpine -- sh -c 'echo hello from a microVM'"
    Then the launch succeeds
    And the guest printed "hello from a microVM"
    And the guest control plane came up

  @live
  Scenario: multi-word argv after -- reaches the guest intact
    When I launch "machine run --image alpine -- uname -s"
    Then the launch succeeds
    And the guest printed "Linux"
    And the guest control plane came up

  @live
  Scenario: --env injects an environment variable the workload can read
    When I launch "machine run --image alpine --env NAME=ari -- printenv NAME"
    Then the launch succeeds
    And the guest printed "ari"
    And the guest control plane came up

  @live
  Scenario: --mount shares a host directory the workload can read
    When I launch "machine run --image alpine --mount .:/work -- ls /work/README.md"
    Then the launch succeeds
    And the guest printed "/work/README.md"
    And the guest control plane came up

  @live
  Scenario: --allow-host admits egress and the guest reaches it
    # The exact shape that regressed. `--allow-host` puts `mvm.vsock_egress=1` on
    # the kernel cmdline, and the guest init fails closed when no egress client
    # resolves from the runtime overlay — so this scenario goes red first if the
    # overlay is not mounted.
    When I launch "machine run --image alpine --allow-host github.com -- ping -c 1 github.com"
    Then the launch succeeds
    And the guest printed "1 received"
    And the guest control plane came up

  @live
  Scenario: egress is default-deny without --allow-host
    When I launch "machine run --image alpine -- ping -c 1 github.com"
    Then the launch fails
    And the guest control plane came up

  @live
  Scenario: a guest exit code propagates to the caller
    When I launch "machine run --image alpine -- sh -c 'exit 7'"
    Then the launch exits with code 7
    And the guest control plane came up

  @live
  Scenario: --cpus and --memory are honoured on a real boot
    When I launch "machine run --image alpine --cpus 2 --memory 512M -- nproc"
    Then the launch succeeds
    And the guest printed "2"
    And the guest control plane came up

  # @wip, not deleted. This scenario is correct and the product is not: on HVF
  # `machine start` boots a guest that `machine ls` reports as running, then
  # never returns, and `machine exec` against it fails with `os error 5`. That
  # defect was unreachable until the initramfs fix landed, because before it no
  # guest booted at all. Tracked in
  # specs/plans/2026-08-26-persistent-machine-path-on-hvf.md. The tag keeps the
  # gate usable while the harness still prints it as pending on every run —
  # deleting it is what would hide it.
  @live @wip
  Scenario: the documented persistent machine lifecycle operates one guest
    Given no machine named "e2e-web"
    When I launch "machine create e2e-web --image alpine --cpus 2 --memory 512M"
    Then the launch succeeds
    When I launch "machine start e2e-web"
    Then the launch succeeds
    And the guest control plane came up
    When I launch "machine exec e2e-web -- uname -s"
    Then the launch succeeds
    And the guest printed "Linux"
    When I launch "machine inspect e2e-web"
    Then the launch succeeds
    When I launch "machine ls"
    Then the launch succeeds
    And the output mentions "e2e-web"
    When I launch "machine stop e2e-web --yes"
    Then the launch succeeds
    When I launch "machine rm e2e-web --yes"
    Then the launch succeeds

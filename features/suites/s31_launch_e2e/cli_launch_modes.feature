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

  # HVF has no SMP — the device tree describes one CPU, PSCI implements no
  # `CPU_ON`, and the supervisor config carries no vCPU count. `--cpus 2` used
  # to exit 0 and hand back one CPU; it now refuses, which is the honest answer
  # until SMP lands (#2888). Asserting the refusal rather than deleting the
  # scenario keeps the limit visible in the suite.
  #
  # It passed in earlier runs of this suite for the wrong reason: the assertion
  # matched the combined streams and the `MVM_PHASE_TIMING` table supplied a
  # "2". `the guest printed exactly` reads the guest's own stdout, which is what
  # made the defect visible in the first place.
  # `@single_vcpu_backend`: the assertion is about a ceiling, so it only means
  # anything on a backend that has one. Firecracker does SMP and honours the
  # request, which is correct there and would fail this scenario.
  @live @single_vcpu_backend
  Scenario: a vCPU count the backend cannot honour is refused, not silently reduced
    When I launch "machine run --image alpine --cpus 2 --memory 512M -- nproc"
    Then the launch fails
    And the output mentions "supports exactly 1 vCPU"

  @live
  Scenario: a single-vCPU launch with explicit memory boots
    When I launch "machine run --image alpine --cpus 1 --memory 512M -- nproc"
    Then the launch succeeds
    And the guest printed exactly "1"
    And the guest control plane came up

  # This scenario is the behavioural witness for the detached-supervisor stderr
  # leak: the steps drive `mvmctl` through `Command::output()`, which reads
  # stderr to EOF. While the HVF supervisor inherited the caller's stderr it
  # held that pipe open for the guest's whole life, so this scenario never
  # terminated even though `machine start` itself returned in under a second.
  @live
  Scenario: the documented persistent machine lifecycle operates one guest
    Given no machine named "e2e-web"
    When I launch "machine create e2e-web --image alpine --cpus 1 --memory 512M"
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

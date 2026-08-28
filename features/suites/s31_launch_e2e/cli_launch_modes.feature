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

  # The `-it` shape from the README, and the one every scenario above was
  # structurally unable to reach: `-t` refuses without a terminal on stdin, so
  # a suite driving `Command::output()` stops at the CLI's own gate and never
  # asks the guest for a console. `openpty()` failed on every OCI image for as
  # long as that was true.
  #
  # `tty` is asserted rather than just the echo: a console that was never
  # allocated still runs the command and still prints, so only the `/dev/pts/N`
  # answer distinguishes a real PTY from a pipe.
  @live
  Scenario: an interactive run gets a real pseudo-terminal in the guest
    When I launch "machine run --image alpine -it -- /bin/sh -c 'tty; echo console-ok'" on a terminal
    Then the launch succeeds
    And the guest console is a pseudo-terminal
    And the guest printed "console-ok"
    And the guest control plane came up

  # The same defect stated as the mount it actually is, on the non-interactive
  # path so it runs on a host with no terminal to give — a CI runner, or this
  # suite under `just bdd`. devtmpfs supplies /dev/ptmx and the image supplies
  # an empty /dev/pts directory, which together look like a working PTY setup
  # and are not one; only /proc/mounts tells them apart.
  @live
  Scenario: the guest mounts devpts so a console can be opened
    When I launch "machine run --image alpine -- sh -c 'grep /dev/pts /proc/mounts'"
    Then the launch succeeds
    And the guest printed "devpts /dev/pts devpts"
    And the guest control plane came up

  # The other half of what devtmpfs does not create. bash process substitution
  # (`< <(...)`) opens /dev/fd/N, and a guest running no udev has no such
  # symlink unless PID 1 lays it down.
  @live
  Scenario: the /dev/fd family resolves in the guest
    When I launch "machine run --image alpine -- sh -c 'readlink /dev/fd && readlink /dev/stdout'"
    Then the launch succeeds
    And the guest printed "/proc/self/fd"
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

  # The README's headline "install a dependency at boot" example combines
  # --allow-host with --mount, and no scenario carried both: the allow-host one
  # had no mount and the mount one had no egress. A flag pair is its own code
  # path — the mount is set up by the same launch that installs the egress
  # policy — so covering them separately covers neither.
  #
  # The payload is a fetch rather than a `pip install`: the shape under test is
  # "read the mount while reaching an admitted host", and making CI depend on a
  # package index would trade a launch regression for an upstream outage.
  @live
  Scenario: --allow-host and --mount together on one launch
    When I launch "machine run --image alpine --allow-host github.com --mount .:/work -- sh -c 'ls /work/README.md && ping -c 1 github.com'"
    Then the launch succeeds
    And the guest printed "/work/README.md"
    And the guest printed "1 received"
    And the guest control plane came up

  # The README sizes a machine and admits a host in the same command. `--cpus`
  # and `--memory` were covered without egress, and egress without sizing.
  @live
  Scenario: --cpus, --memory and --allow-host on one launch
    When I launch "machine run --image alpine --cpus 2 --memory 512M --allow-host github.com -- sh -c 'echo $(nproc) && ping -c 1 github.com'"
    Then the launch succeeds
    And the guest printed "2"
    And the guest printed "1 received"
    And the guest control plane came up

  # `-vvv` is in the README's egress example. Verbosity changes what the launch
  # path logs and nothing had ever run a guest with it set, so a panic behind a
  # log statement would only ever have reproduced for a user.
  @live
  Scenario: -vvv does not disturb a launch that admits a host
    When I launch "machine run --image alpine -vvv --allow-host github.com -- ping -c 1 github.com"
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

  # The README documents `--cpus`, and on HVF it used to exit 0 and hand back
  # one CPU whatever was asked for (#2888).
  #
  # Both counts are asserted because they were both wrong together: `nproc` and
  # `/proc/cpuinfo` agreed at 1 before SMP, so a fix that moved only one would
  # be reading something other than the machine. They are combined into a
  # single token so one line pins both — a disagreement shows up as "2/1"
  # rather than passing on whichever the assertion happened to read.
  #
  # An earlier revision of this scenario passed for the wrong reason: the
  # assertion matched the combined streams and the `MVM_PHASE_TIMING` table
  # supplied a "2". `the guest printed exactly` reads the guest's own stdout,
  # which is what made the defect visible in the first place.
  @live
  Scenario: --cpus is honoured on a real boot
    When I launch "machine run --image alpine --cpus 2 --memory 512M -- sh -c 'echo $(nproc)/$(grep -c ^processor /proc/cpuinfo)'"
    Then the launch succeeds
    And the guest printed exactly "2/2"
    And the guest control plane came up

  @live
  Scenario: a single-vCPU launch with explicit memory boots
    When I launch "machine run --image alpine --cpus 1 --memory 512M -- sh -c 'echo $(nproc)/$(grep -c ^processor /proc/cpuinfo)'"
    Then the launch succeeds
    And the guest printed exactly "1/1"
    And the guest control plane came up

  # Over the backend's ceiling is clamped and reported, never refused.
  #
  # Refusing would make a portable `--cpus 9999` succeed on Linux and fail on
  # macOS for a reason the user cannot act on — and HVF's own default of 2 once
  # sat above a ceiling of 1, which failed *every* launch on this backend. The
  # warning is the point: the silent version booted a guest on fewer CPUs than
  # its admitted plan claimed, with nothing to explain it.
  #
  # The request is absurd on purpose. HVF's ceiling comes from
  # `hv_vm_get_max_vcpu_count`, so it is a property of the host and not a
  # constant this suite can name — an earlier revision asserted "supports at
  # most 4", which was a number a bug had produced and which went stale the
  # moment the bug was fixed. A count no machine will ever have exercises the
  # clamp on any host, and the assertion checks that the ceiling was reported
  # rather than what it happens to be here.
  @live
  Scenario: a vCPU request beyond the backend ceiling is clamped and reported
    When I launch "machine run --image alpine --cpus 9999 -- sh -c 'echo clamped-and-booted'"
    Then the launch succeeds
    And the output mentions "supports at most"
    And the output mentions "9999 requested"
    # Last line, not the whole of stdout: the clamp warning is chrome and
    # legitimately precedes the guest's output on the same stream. A fixed
    # token rather than the granted count, which is whatever this host allows.
    And the guest's last line is "clamped-and-booted"
    And the guest control plane came up

  # `--memory` was never verified on this path either, and it cannot be checked
  # at 512M: that is also the built-in default, so a guest that ignored the flag
  # entirely would report the expected number. 1024M is the smallest request
  # that tells the two apart. The floor is well under the ask because the kernel
  # reserves a slice of RAM before it reports `MemTotal`, and how much varies by
  # kernel version — 800 MiB separates "got a gigabyte" from "got the 512 MiB
  # default" without pinning a number that drifts.
  @live
  Scenario: --memory is honoured on a real boot
    When I launch "machine run --image alpine --memory 1024M -- sh -c 'M=$(grep MemTotal /proc/meminfo | tr -cd 0-9); [ $M -gt 819200 ] && echo mem-ok || echo mem-only-$M'"
    Then the launch succeeds
    And the guest printed exactly "mem-ok"
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
    # Documented in the same README block as the verbs around it, and the only
    # one of them nothing ran. It patches the machine and relaunches, so a
    # break here reads as a dead machine rather than a bad flag.
    When I launch "machine reconfigure e2e-web --memory 1G"
    Then the launch succeeds
    When I launch "machine inspect e2e-web"
    Then the launch succeeds
    When I launch "machine ls"
    Then the launch succeeds
    And the output mentions "e2e-web"
    When I launch "machine stop e2e-web --yes"
    Then the launch succeeds
    When I launch "machine rm e2e-web --yes"
    Then the launch succeeds

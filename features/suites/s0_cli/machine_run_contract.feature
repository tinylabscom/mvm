Feature: machine run request contract

  `machine run` is the verb a workload reaches mvm through, so the answers it
  gives before booting anything are part of its contract. Every scenario here is
  hermetic: each one is decided from the request alone, boots no VM, and touches
  no network, so they gate every PR rather than waiting on the `@live` lane.

  That distinction is the point. The boot-shape scenarios in
  `s5_lifecycle/transient_sandbox_boot.feature` are `@live` and skipped by
  default, so a change can break every guest boot with a green suite. What can be
  decided without a VM is decided here instead.

  Scenario: machine run without a source names every way to give it one
    When I run mvmctl with "machine run" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "--image"
    And the error output contains "--manifest"
    And the error output contains "--flake"

  Scenario: machine run without a command names the three ways to supply one
    When I run mvmctl with "machine run --image alpine" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "-- <cmd>"
    And the error output contains "--detach"
    And the error output contains "-it -- /bin/sh"

  # --entrypoint dispatches a baked /etc/mvm/entrypoint, which an OCI image does
  # not have; silently ignoring the flag would run something other than what was
  # asked for.
  Scenario: machine run refuses --entrypoint against an OCI image
    When I run mvmctl with "machine run --image alpine --entrypoint" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "drop --entrypoint"

  # "No SSH in microVMs, ever" is a project invariant, not a preference, so the
  # allow-list refuses TCP/22 before anything is admitted rather than leaving it
  # to a later layer.
  Scenario: machine run refuses an allow-host on the SSH port
    When I run mvmctl with "machine run --image alpine --allow-host example.com:22 -- /bin/true" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "TCP/22"
    And the error output contains "SSH sessions are banned in microVMs"

  # An interactive PTY needs a terminal to attach to. Refusing up front beats
  # booting a VM and discovering there is nothing to attach.
  Scenario: machine run refuses an interactive PTY without a terminal
    When I run mvmctl with "machine run --image alpine -it -- /bin/sh" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "needs a terminal on stdin"

  # Declared ingress is signed before boot and belongs to the persistent
  # machine runtime, so the foreground CLI may detach without orphaning it.
  Scenario: machine run accepts declared ingress with detached ownership
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine run --image alpine --port 8080:3000 --detach --dry-run --name bdd-detached-ingress"
    Then the command exits with code 0
    And the output contains "no VM will be booted"
    And the output contains "machine: bdd-detached-ingress"
    And the isolated mvm home does not contain directory "vms/bdd-detached-ingress"

  # Egress-enabling dry runs are deliberately absent. `--allow-host` / `--net`
  # make the dry run resolve an *available* egress-capable backend, so the
  # command's exit status depends on whether the host has a usable VMM — it
  # succeeds on a developer machine and fails on a runner with none. That is a
  # host fact, not a request fact, and a scenario asserting either way passes
  # only where it was written. Whether a dry run should need a bootable backend
  # at all is a separate question, recorded in the sprint notes.
  Scenario: machine run dry-run reports the plan and boots nothing
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine run --image alpine --dry-run --name bdd-dry-run -- /bin/true"
    Then the command exits with code 0
    And the output contains "no VM will be booted"
    And the output contains "profile: standard"
    And the isolated mvm home does not contain directory "vms/bdd-dry-run"

  # Deny-all is the default posture, and a dry run is where an operator checks
  # it before committing to a boot.
  Scenario: machine run defaults to deny-all egress
    When I run mvmctl with "machine run --image alpine --dry-run -- /bin/true" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "network: deny-all"

  # The security profile and the resources are what the operator asked for, not
  # a default silently substituted for them.
  Scenario: machine run dry-run echoes the requested profile and resources
    When I run mvmctl with "machine run --image alpine --dry-run --profile restrictive --cpus 4 --memory 1G -- /bin/true" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "profile: restrictive"
    And the output contains "cpus=4"
    And the output contains "memory=1G (1024 MiB)"

  # A sized disk persists at the caller's path. Unlike a directory snapshot,
  # writes are not thrown away, and foreground teardown flushes the guest before
  # the VMM releases the image.
  Scenario: machine run accepts a writable sized disk
    When I run mvmctl with "machine run --image alpine --dry-run --mount /tmp/mvm-bdd-output.img:/data:64M:rw -- /bin/true" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "no VM will be booted"

  # Inference decides which image boots. It must not decide anything else: a
  # detected run carries the same profile and the same deny-all egress as one
  # that named its image, or the convenience would be a policy bypass.
  Scenario: a detected runtime does not relax the run's posture
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "run --dry-run --runtime node -- npm test"
    Then the command exits with code 0
    And the output contains "profile: standard"
    And the output contains "network: deny-all"

  # A typo must not silently boot the bundled default and leave the user
  # reading a "command not found" from a guest they never asked for.
  Scenario: an unknown runtime name is refused and lists the known ones
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "run --runtime pyhton -- true"
    Then the command exits with code 1
    And the error output contains "unknown runtime"
    And the error output contains "python"

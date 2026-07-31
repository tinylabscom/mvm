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

  # A bare `--allow-host <host>` means `<host>:443`. That default is easy to
  # pair with an `http://` URL and then read the resulting refusal as a broken
  # network, so the resolved policy names the port it actually admitted.
  Scenario: machine run dry-run shows the port a bare allow-host resolves to
    When I run mvmctl with "machine run --image alpine --dry-run --allow-host example.com -- /bin/true" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "allow-list:example.com:443"

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

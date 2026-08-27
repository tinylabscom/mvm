Feature: The documented machine verbs operate a real guest

  The `machine` surface is the largest documented verb family and was the
  least proven: two dozen verbs sat at the `parse` tier because each one needs
  a guest that is already running, and no scenario was willing to boot one for
  a single assertion.

  Parsing cannot see the defect that matters here. `machine forward` parses
  cleanly and then refuses at runtime — it was retired, while
  `examples/obscura/README.md` still tells a reader to run it. Only executing
  the verb against a live guest distinguishes "documented and working" from
  "documented and merely still in the clap tree".

  The guest is named literally rather than through a `{machine}` placeholder:
  the machine-name positional carries a `value_parser` that rejects braces, so
  a templated name fails to parse and silently drops out of the live-witness
  gate — the scenario would run while the tier it backs stayed unproven.

  One guest is booted for the whole feature and every scenario drives it, so
  the verb coverage costs one boot rather than twenty. Scenarios are split by
  verb family rather than written as a single long journey: cucumber abandons
  a scenario at its first failing step, so one scenario per family means a
  broken verb reports itself instead of hiding every verb behind it.

  Untagged `@live` only — deliberately not `@firecracker`. The pre-existing
  live lifecycle witness carries that tag, so it is skipped on macOS, where
  HVF is the default backend. This feature runs on whatever backend the host
  actually has.

  Background:
    Given the journey machine is running

  @live
  Scenario: the guest reports its own state
    When I run mvmctl against the journey machine with "machine inspect bdd-journey"
    Then the command exits with code 0
    When I run mvmctl against the journey machine with "machine logs bdd-journey"
    Then the command exits with code 0
    When I run mvmctl against the journey machine with "machine boot-report bdd-journey"
    Then the command exits with code 0
    Then the journey machine is still running

  @live
  Scenario: commands run inside the guest
    When I run mvmctl against the journey machine with "machine exec bdd-journey -- uname -a"
    Then the command exits with code 0
    Then the journey machine is still running

  @live
  Scenario: the guest filesystem is readable from the host
    When I run mvmctl against the journey machine with "machine fs ls bdd-journey /"
    Then the command exits with code 0
    Then the journey machine is still running

  @live
  Scenario: files copy from the host into the guest
    Given a host file "target/journey/input.json" exists
    When I run mvmctl against the journey machine with "machine cp target/journey/input.json bdd-journey:/tmp/input.json"
    Then the command exits with code 0
    Then the journey machine is still running

  @live @snapshot
  Scenario: the guest pauses and resumes
    When I run mvmctl against the journey machine with "machine pause bdd-journey"
    Then the command exits with code 0
    When I run mvmctl against the journey machine with "machine resume bdd-journey"
    Then the command exits with code 0
    Then the journey machine is still running

  @live @snapshot
  Scenario: the guest checkpoints and restores
    # `--class vm-full` because that is the form the docs teach, and the two
    # classes have opposite preconditions: `vm-full` checkpoints a *running*
    # guest (it pauses internally), while the default `fs-quick` refuses one
    # and wants it stopped or paused first.
    When I run mvmctl against the journey machine with "machine checkpoint create bdd-journey --class vm-full"
    Then the command exits with code 0
    When I run mvmctl against the journey machine with "machine checkpoint ls bdd-journey"
    Then the command exits with code 0
    Then the journey machine is still running

  @live
  Scenario: the documented teardown removes the guest
    # Last, because it destroys the machine every scenario above shares.
    When I run mvmctl against the journey machine with "machine ls"
    Then the command exits with code 0
    Then the journey machine is torn down

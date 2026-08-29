Feature: README CLI contract

  The README's user-facing surface — the verbs, subcommands, and flags it shows,
  the refusals it promises, and the security-claim count it advertises — must
  match the real `mvmctl` binary. Every scenario here is checkable in PR CI
  without `/dev/kvm`: it drives `mvmctl --help` / `<verb> --help`, exercises a
  refusal path that fails before any VM boot or network fetch, or cross-reads two
  in-tree docs.

  Behaviours the README can only prove live are deliberately out of this suite's
  scope and are covered by the live-KVM smokes instead: an actual `machine run`
  booting a guest to completion, the dm-verity tamper panic before userspace,
  default-deny egress enforcement on a running guest, and secret substitution
  over vsock. None of those can run where there is no `/dev/kvm`.

  Scenario: the README's documented top-level verbs are discoverable
    When I run mvmctl with "--help"
    Then the command exits with code 0
    And the help output lists the "machine" verb
    And the help output lists the "build" verb
    And the help output lists the "kernel" verb
    And the help output lists the "doctor" verb
    And the help output lists the "bootstrap" verb
    And the help output lists the "run" verb

  Scenario: the subsystems the reference documents are discoverable from --help
    # Each of these was documented in the CLI reference while `hide = true`, so
    # the tool could not tell you the subsystem had a CLI at all. `secret` is the
    # entry point to host-side credential substitution and `trust` owns
    # `trust receipt verify`.
    When I run mvmctl with "--help"
    Then the command exits with code 0
    And the help output lists the "secret" verb
    And the help output lists the "trust" verb
    And the help output lists the "image" verb
    And the help output lists the "cache" verb

  Scenario: the SDK transport survives `run` becoming a listed verb
    # `run` is no longer hidden and its summary now describes the transient-run
    # verb a user sees. What this scenario protects is the transport underneath:
    # the Python and TS SDKs shell to `run --mode live/plan`, so the flag and
    # its meaning must survive any rewording of the verb itself.
    When I run mvmctl with "run --help"
    Then the command exits with code 0
    And the help output contains "--mode"
    And the help output contains "SDK transport mode"

  Scenario: `trust audit verify` is a real command
    When I run mvmctl with "trust audit --help"
    Then the command exits with code 0
    And the help output lists the "verify" verb

  Scenario: the persistent-machine subcommands the README documents exist
    When I run mvmctl with "machine --help"
    Then the command exits with code 0
    And the help output lists the "create" verb
    And the help output lists the "start" verb
    And the help output lists the "exec" verb
    And the help output lists the "logs" verb
    And the help output lists the "reconfigure" verb
    And the help output lists the "stop" verb
    And the help output lists the "rm" verb
    And the help output lists the "ls" verb
    And the help output lists the "inspect" verb

  Scenario: the `machine run` flags the README's examples use exist
    When I run mvmctl with "machine run --help"
    Then the command exits with code 0
    And the help output contains "--image"
    And the help output contains "--flake"
    And the help output contains "--allow-host"
    And the help output contains "--cpus"
    And the help output contains "--memory"
    And the help output contains "--mount"
    And the help output contains "--entrypoint"
    And the help output contains "-i, --interactive"

  Scenario: every README CLI example resolves against the real CLI
    Then every README CLI example resolves to a command and its options

  Scenario: every CLI option has a BDD help witness
    Then every CLI command option has a BDD help witness

  Scenario: every README code block declares its coverage witness
    Then every README code block has an explicit coverage witness

  # Per example, not per command path. The tier ladder is keyed on the verb, so
  # one live `machine run` discharged all twelve documented `machine run`
  # variants — including the `-it` form, whose guest console was broken on every
  # OCI image the whole time it looked covered.
  Scenario: every README example is executed or carries a reviewed exemption
    Then every README example is executed or carries a reviewed exemption

  Scenario: `build compile` exposes the documented IR flags
    When I run mvmctl with "build compile --help"
    Then the command exits with code 0
    And the help output contains "--from-ir"
    And the help output contains "--out"

  Scenario: `kernel build --which workload` is a documented option
    When I run mvmctl with "kernel build --help"
    Then the command exits with code 0
    And the help output contains "--which"
    And the help output contains "workload"

  Scenario: `run --image --prod` refuses a mutable OCI tag before any network fetch
    # Backs the README OCI section: `--prod` refuses mutable tags before fetch.
    # The guard is a pure reference-string check, so it never boots a VM or
    # touches the network — exactly the CI-checkable slice of claim 14.
    When I run mvmctl in a clean home with "run --image alpine:latest --prod -- echo hi"
    Then the command exits with code 1
    And the error output contains "requires a digest-pinned reference"

  Scenario: `image pull --prod` refuses a mutable tag before any network fetch
    When I run mvmctl in a clean home with "image pull --prod alpine:latest"
    Then the command exits with code 1
    And the error output contains "requires a digest-pinned reference"

  Scenario: the README's claim count matches the machine-checked ledger
    # The README summarizes fifteen numbered claims; the in-tree conformance
    # catalog is the machine-checked claim -> witness ledger. Locking them
    # together fails this scenario the moment either drifts.
    Then the README and the claim catalog agree on 15 numbered claims

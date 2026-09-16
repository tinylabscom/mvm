Feature: The Claude Code example runs as a policy-confined workbench

  `examples/claude-code/` ships an interactive dev-tier profile whose whole
  point is the posture around it: no guest NIC, default-deny egress with an
  explicit allow-list, a sized workspace disk instead of a host share, and a
  console that counts as guest activity. Each of those is asserted here
  against a real boot of the example flake, because none of them is visible
  to the parse tier — a policy that admits everything and a workspace that
  vanishes on stop both exit 0.

  The egress probes speak HTTP CONNECT to the guest's own loopback proxy
  (the only egress path a NIC-less guest has). A denied host must answer
  `403 Forbidden` immediately — the policy-refusal shape, distinct from the
  `502 Bad Gateway` an unreachable-but-admitted upstream gets — and an
  allow-listed host must answer `200 Connection established`, which means
  the gate admitted the connect and the host-side endpoint reached the real
  upstream's port 443. No TLS byte and no API credential is involved: the
  admitted-at-the-gate assertion deliberately stops at the connect, so the
  scenario runs where no Anthropic API key exists.

  One scenario rather than one per assertion: the guest is persistent state
  shared across steps, and cucumber rebuilds the world per scenario — a
  split would either re-boot per scenario (minutes each) or smuggle the
  machine through process globals. The leading reclaim steps make an
  aborted earlier run's leftovers harmless; their exits are deliberately
  not asserted.

  Requires the example image in the target home's build cache (first boot
  builds it through the builder VM) and real internet egress for the
  admitted-connect probe, like the other live egress scenarios.

  @live
  Scenario: the workbench boots, refuses non-admitted egress as policy, and keeps its workspace
    # Reclaim anything an aborted earlier run left behind. Not asserted.
    When I run mvmctl in an isolated live home with "machine stop bdd-claude --yes"
    And I run mvmctl in an isolated live home with "machine rm bdd-claude --yes"
    Given a fresh claude-code workspace image at "/tmp/mvm-bdd-claude-workspace.img"
    # The README's interactive-lane launch, minus the secrets mount (no key
    # exists in this lane, and the wrapper only reads one when present).
    When I run mvmctl in an isolated live home with "machine run --flake examples/claude-code --name bdd-claude -d --profile dev --allow-host api.anthropic.com:443 --mount /tmp/mvm-bdd-claude-workspace.img:/work:64M:rw"
    Then the command exits with code 0
    # The baked wrapper is on the guest PATH where the console session finds it.
    When I execute workbench command "command -v claude" in machine "bdd-claude"
    Then the command exits with code 0
    And the output contains "/usr/local/bin/claude"
    # Default-deny surfaces as policy, immediately — not as a timeout and not
    # as an unreachable-upstream 502.
    When I probe the egress gate of workbench machine "bdd-claude" for "github.com:443"
    Then the output contains "HTTP/1.1 403"
    And the output does not contain "HTTP/1.1 200"
    # The allow-listed API host is admitted at the gate: the endpoint dials
    # the real upstream and the tunnel opens. No API call is made through it.
    When I probe the egress gate of workbench machine "bdd-claude" for "api.anthropic.com:443"
    Then the output contains "HTTP/1.1 200"
    # The workspace volume holds bytes across a full stop/start cycle.
    When I execute workbench command "printf bdd-workbench-persisted > /work/marker" in machine "bdd-claude"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine stop bdd-claude --yes"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-claude"
    Then the command exits with code 0
    When I execute workbench command "cat /work/marker" in machine "bdd-claude"
    Then the command exits with code 0
    And the output contains "bdd-workbench-persisted"
    # A console attach is guest activity: it must refresh the name-registry
    # `last_active` stamp the reaper's idle logic keys off. The reaper itself
    # runs in no local-mvmctl process (it is an unconsumed primitive there),
    # so the wiring into its input is the part a live run can witness.
    When I attach a one-shot console command to machine "bdd-claude"
    Then the command exits with code 0
    And the console attach refreshed the workbench activity marker
    # Documented teardown.
    When I run mvmctl in an isolated live home with "machine stop bdd-claude --yes"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine rm bdd-claude --yes"
    Then the command exits with code 0

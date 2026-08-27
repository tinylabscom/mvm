Feature: the README's SDK entry points reach the same launch path

  Besides the CLI verbs, the README documents two other ways in: the runtime SDK
  driven through `mvmctl run --mode plan|live`, and the decorator SDK compiled by
  `mvmctl build compile`. Each is a separate seam into the same launch path, and
  each can break without the CLI scenarios noticing.

  The Rust `MvmClient` library seam is the third, and it is covered by
  `crates/mvm-client/tests/local_backend_e2e.rs` instead of here: driving it
  through a subprocess would prove nothing about linking against the crate,
  which is the whole claim the README makes for it.

  Background:
    Given an artifact-warm mvm home

  @live
  Scenario: a runtime-SDK script admits as a signed plan without booting
    # `--ack-divergence kill-dropped` because the fixture uses the README's
    # `with mvm.Sandbox.create(...)` form, whose context-manager exit calls
    # `sb.kill()`. Plan mode reports that as a divergence — replay lifetime is
    # the orchestrator's TTL — and refuses until it is acknowledged. Keeping the
    # `with` form and acknowledging is what a reader of the README would do.
    When I launch "run --mode plan --ack-divergence kill-dropped crates/mvm-conformance/fixtures/e2e/sandbox_script.py"
    Then the launch succeeds
    And the output mentions "ADMITTED"
    And the output mentions "no microVM booted"

  # The README's claim-4 contract, now literally true: "Interactive surfaces
  # (exec, commands.start, console) are dev-tier only; they refuse with
  # SandboxDevOnly when the run needs DevOnly verbs but admission offers only
  # the restricted ProdSafe grant — no silent fallback."
  #
  # The script does boot a real guest — `Sandbox.create` returns — and is then
  # refused at the SDK's own gate, which is where the README says the refusal
  # happens. It used to get past that gate (the envelope reported the image's
  # posture rather than the grant's) and be refused by the *guest* instead, with
  # a verb-grant error. Same security either way; only one of them is the
  # documented behaviour a caller can program against.
  @live
  Scenario: a runtime-SDK script is refused DevOnly surfaces under a ProdSafe grant
    When I launch "run --mode live crates/mvm-conformance/fixtures/e2e/sandbox_script.py"
    Then the launch fails
    And the output mentions "SandboxDevOnly"
    And the output mentions "build_mode='prod'"

  @live
  Scenario: a decorator workload compiles from its source file
    When I launch "build compile examples/python/hello-app/app.py -o /tmp/mvm-e2e-hello-app"
    Then the launch succeeds

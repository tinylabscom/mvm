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

  # @wip for the same reason as the persistent-lifecycle scenario: the SDK's
  # live transport shells `machine run -d --up-json --name ... --ttl ...`, so it
  # rides the persistent path and inherits its hang. See
  # specs/plans/2026-08-26-persistent-machine-path-on-hvf.md.
  @live @wip
  Scenario: a runtime-SDK script boots a real guest in live mode
    When I launch "run --mode live crates/mvm-conformance/fixtures/e2e/sandbox_script.py"
    Then the launch succeeds
    And the guest control plane came up

  @live
  Scenario: a decorator workload compiles from its source file
    When I launch "build compile examples/python/hello-app/app.py -o /tmp/mvm-e2e-hello-app"
    Then the launch succeeds

# The claim-10 gate is a required argument of the substitution service

Issues #3301 and #3302 (its last open item). Task T15 of
`specs/plans/2026-09-15-agent-sandbox-drive-plane.md`.

`SubstitutionService` held its egress gate as an `Option`, attached after
construction by `with_egress_gate` or `with_shared_egress_gate`. A service built
without one skipped the claim-10 check and the peer-destination refusal, and
forwarded any request that carried no placeholder, to any host. The endpoint
hit this case in production: `EndpointNetworkProjection::from_config` produced a
gate only when the config carried a `network_policy` or the egress mode was
`FlowMux`. A `Wire` config (the serde default) with no policy produced no gate.

Now:

- `SubstitutionService::new` and `FromPlanInputs` take a required
  `Arc<EgressGate>`. The two attach methods are deleted, so a service that
  forwards without deciding the destination can no longer be built.
- `prepare_flow` runs the peer refusal and the claim-10 check on every request.
  The TLS intermediate stays optional.
- A config with no `network_policy` projects `EgressGate::default_deny()`
  whatever its egress mode. `EndpointNetworkProjection::gate()` replaces the
  fallible `flowmux_gate()`, because there is no longer a case where the gate is
  missing.

## Tests

A test that is not about claim 10 now builds its service under a gate that
admits exactly the destinations it sends to. The helper is
`network_endpoint_proxy/test_support/gate.rs`. It replaces the two per-module
copies (`prepare.rs`'s `gate_admitting` and the terminator's `pinned_gate`), and
the integration tests include the same file by path. It pins each hostname to
its own TEST-NET-1 address, so no test does DNS. It does not use an
unrestricted gate, because an unrestricted gate would resolve through the host.

Every refusal test that could now be satisfied by the gate instead of the check
it names asserts that check's own message. Each was confirmed against the
message it produces:

- `endpoint_refuses_unbound_destination_and_never_forwards` (prepare),
  `network_endpoint_refuses_unbound_destination` (egress_secret_leak_gate),
  the unbound-destination audit test in `audit.rs`, and
  `endpoint_bin_serves_substitution_and_refuses_unbound_destination`: the
  binding's `not in the secret's allowed_hosts`. The gate admits the unbound
  host in each one. The binary test uses a literal public address in its
  policy, because the endpoint resolves policy host names at startup.
- The compressed-body tests in `redaction.rs` and `audit.rs`: `fail-closed`.
- `gate_deny_all_refuses_before_forward`: `claim-10`, against a public
  address, so the refusal comes from the deny-all policy and not from the
  mandatory-deny loopback range.
- `terminated_connect_is_refused_when_policy_denies_the_destination`: the 502
  body carries `claim-10`. It previously accepted any 502.
- The AI budget tests already asserted `AI egress budget`. The terminator's
  421 and 501 refusals are decided before the service is reached, so the gate
  cannot produce them.

New witnesses:

- `an_endpoint_config_without_a_policy_denies_every_destination_in_every_mode`
- `from_plan_service_refuses_an_unadmitted_destination_without_a_placeholder`
- `a_peer_destination_is_refused_by_every_service`. This replaces
  `no_gate_installed_forwards_as_before`, which pinned the behaviour being
  removed.

## Validation

- `cargo nextest run --no-fail-fast -p mvm-hostd -p mvm-vmm -p mvm-runtime`:
  3583 run, 3582 passed. The one failure,
  `a_vcpus_time_survives_the_thread_that_earned_it`, is a macOS-only HVF test
  in code this change does not touch. It is intermittent (it failed again when
  run alone, then passed in the next run) and is filed as #3446.
- The same run for `mvm-vmm` and `mvm-runtime` with their `test-support`
  features: 1642 run, 1642 passed. `mvm-hostd` has no such feature.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo build -p mvm-hostd --examples`, `just check-gated`,
  `xtask check-all` and `xtask check-no-spec-refs-in-comments` all pass. The
  `network-perf` example was also type-checked with its feature on.

Not in this change: a claim-10 refusal still leaves no chain-signed entry
(#3300).

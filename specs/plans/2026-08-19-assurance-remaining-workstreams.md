# Assurance: the remaining workstreams

Backing: preview
Validation: none

A pick-up-cold checklist for the three workstreams left in
`specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md`. That plan is
the source of truth for what landed and why; this one is the task list.

Status: **W9b one hop from done. W5b open. W8 blocked outside this repo.**

## What already holds

Worth knowing before touching any of it, because each of these was learned the
expensive way.

- **A session may only be opened by the process that hosts the broker
  registry.** `install_host_assurance_plane` is called only by
  `register_bound_handlers`, which only `mvm-host-agent` and `mvm-broker` call.
  Anything else gets `SessionRefusal::NoPlane`.
- **`RegisterVm` is the carrier**, not `broker::config::SubprocessConfig`.
  Nothing in production constructs the latter, and it is unsigned where
  `RegisterVm` is host-signed.
- **`ControlRequest` is signed over its JCS canonical bytes.** Any new field
  must be skip-serialized when absent or every pre-existing signature breaks.
- **The broker never receives a plan.** `PlanIdentity` carries the six fields
  `supervisor::for_plan` reads, and nothing more.
- **A record the host cannot write means the probe does not happen.**
  `AuditUnavailable` is a refusal, not a warning.

## W9b — populate `RegisterVm.assurance`

Everything downstream is done: the field exists, `daemon::register` opens the
session, and the sink records through the audit-signer. What is missing is a
producer.

- [ ] Decide the carrier from the supervisor to `mvm-vmm`. Two candidates, and
      the choice is not obvious:
      - `HostAgentServicesParams` — where `services` already travels, so it is
        the matching precedent. **Cross-repo**: mvmd constructs this struct, and
        its main is already broken on a related mismatch, so adding a field
        without a default will break their build again.
      - `VmStartConfig` — already carries `PlanBinding { plan_json, audit_dir,
        signing_key_path }` into `mvm-vmm` via
        `spec_map::workload_plan_binding`, so the admitted plan is *already*
        there. Check whether mvmd constructs `VmStartConfig` too before
        assuming this avoids the cross-repo break.
- [ ] Mint the session at admission: build the `MvmBinding`, intersect the
      authority, resolve the operator's declared destinations, and derive the
      `PlanIdentity`. `assurance_session::open`'s body is the reference — it
      already does all four for the in-process path.
- [ ] Attach it to the chosen carrier and set `RegisterVm.assurance` in
      `host_agent_spawn.rs`.
- [ ] Test: a registration carrying a session opens one on the daemon's
      handler, and a probe dispatched against that session is recorded.
- [ ] Test: a registration without one changes nothing (the signed-bytes test
      already exists; extend it to the daemon path).
- [ ] Delete the now-dead in-process open in `admit_and_start` if it turns out to be
      unreachable, or document why the library path keeps it.

## W5b — a guest-side observer

`observer_verified` currently means "MVM recorded a probe and an effect was
attempted". That is honest evidence the trial ran; it is not an independent
observer of what happened *inside* the guest, which is what the assurance
contract means. Until this lands, every live trial is `INCONCLUSIVE` for
`ObserverMissing` — and
`evidence_from_a_real_session_still_evaluates_inconclusive_today` pins that.

- [ ] Decide what the guest can report that the host cannot already see.
      The host owns the egress decision and the audit chain; the guest owns
      whether the effect *took hold* — a process started, a file appeared, a
      connection was attempted from inside.
- [ ] Decide the transport. The guest agent already speaks the broker channel
      (`mvm_agentd::assurance`), so a report verb there is the cheap route.
      **The guest is untrusted**: whatever it says must be corroborated, not
      believed. Design the corroboration before the transport.
- [ ] Extend `HostObservation` with the corroborated guest signal, keeping the
      existing rule that a candidate contradicting the observer is
      `INCONCLUSIVE` rather than silently overridden.
- [ ] Populate `observer_verified` from that corroboration, and update its
      doc comment, which currently states the limit plainly.
- [ ] Update the pinning test. When it changes, that should be the *only*
      thing that starts certifying.

## W8 — the framed-stdio provider

**Blocked outside this repo**, and not by a little. `mvm-security assurance
plan` reports seven brokers it cannot reach (`immutable_snapshot`,
`builder_microvm`, `subject_microvm`, `guest_observer`, `host_observer`,
`execution_receipts`, `artifact_sealing`), and the counterparty's own
broker-backed execution milestone (M3) is unstarted. No amount of MVM-side work
produces a certifying campaign until that moves.

- [ ] Confirm with the assurance side whether M3 is being picked up, and which
      brokers they expect MVM to serve versus stub.
- [ ] Ship an MVM-side binary speaking `mvm.security.campaign-request/v1` over
      framed stdio, returning `mvm.security.provider-response/v1`.
      `apps/mvm-security/src/broker.rs` in the counterparty is the reader; the
      exact key sets are already asserted by
      `the_emitted_record_matches_the_counterparty_field_set`.
- [ ] Map a campaign request onto an admitted run: build the workload, open the
      session, run the declared probes, assemble the evidence, emit
      `mvm.security.trial-evidence/v1`.
- [ ] Keep the outcome honest. The provider reports evidence; it does not
      decide. `PREVENTED`/`CONTAINED` stay derived, and missing evidence stays
      `INCONCLUSIVE`.

## Verification, for any of the above

The full set, because two of these lanes have caught real bugs that
`--all-targets` did not:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace -j 6
cargo test --workspace --doc
# the feature lane `--all-targets` cannot see
cargo nextest run --features test-support --lib \
  -p mvm-backends -p mvm-runtime -p mvm-client -p mvm-cli -p mvm-vmm
cargo nextest run -p mvmctl --features test-support --test audit_emissions_live
cargo check -p mvm-cli --features test-support --example verification_loop
# every gate CI runs
grep -rho 'xtask -- [a-z0-9-]*' .github/workflows/*.yml | sed 's/xtask -- //' | sort -u
```

Two standing traps: run the xtask gate loop **separately** from `nextest` (they
share `MVM_HOME` and racing them fails unrelated `mvm-core` tests), and move any
`graft/` index aside first (`check_no_gateway_names` and
`check_l3_expansion_freeze` scan without honouring `.gitignore`).

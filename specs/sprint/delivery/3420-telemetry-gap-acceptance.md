# Telemetry gap acceptance: executable regressions and the pending contracts

Issue #3420, the W1 acceptance-tests item of
`2026-09-17-host-mediated-telemetry`; epic #3419 remains open.

Four executable regressions now pin the known capture gaps by asserting
today's deficient behavior. Each carries a doc comment saying it documents a
gap, not desired behavior, and must flip into the positive contract in the
same change that lands the fix:

- `an_event_outside_any_span_is_dropped_with_no_record_and_no_loss_evidence`
  (`mvm-observability`): the OTLP layer exports nothing for an outside-span
  event, and the drop is not even counted as a loss.
- `span_event_state_grows_unbounded_until_close` (`mvm-observability`): a
  span retains every event in an unbounded vector; only closed spans meet a
  bounded queue.
- `a_machine_booted_by_another_process_has_no_durable_copy_here`
  (`mvm-hostd`): the stream plane's registry is process-local, so a call into
  a detached machine gets a record-nothing sink — bytes reach the caller, no
  transcript exists. This is the detached-CLI acceptance regression the issue
  evidence called for.
- `boot_diagnostics_are_emitted_but_the_sealed_agent_discards_them`
  (`mvm-agentd`): the agent's boot path really emits through the `tracing`
  facade (proved by counting under a scoped collector, hand-rolled so the
  sealed crate gains no subscriber dependency even in tests), while the
  sealed bin installs no subscriber.

The not-yet-enabled contracts are the new `s34_telemetry_capture` conformance
suite: three `@wip` scenarios (standalone-event collection, detached
VM-lifetime collection, guest diagnostics reaching the authenticated
collector), following the repo's pending idiom — no claim ID tag, a one-step
stub, and a comment block naming what exists, what does not, and the paired
regression to flip. The BDD runner reports them in its explicit pending
tally; they are not `#[ignore]`d tests presented as product support, and the
claim register is untouched because register rows require resolving
witnesses.

## Validation

- The four gap regressions pass, asserting current behavior.
- `cargo test -p mvm-conformance` (meta gates, 113 tests) accepts the new
  suite; `check-conformance` reports the model unchanged (20 claims).
- `cargo fmt --all -- --check`, workspace clippy (pinned 1.97.1, warnings
  denied), full workspace tests via `just test` (14,423 tests, zero
  failures, 27 skipped), pinned-toolchain doctests, all 72 `check-all`
  repository gates and `just check-gated` pass.

This slice changes no runtime behavior: it adds tests, three `@wip` feature
files and spec bookkeeping only. Passing gap regressions certify nothing —
they are evidence the gaps exist, kept green so their flip is loud. Remaining
W1: hardware-qualified baseline measurements and regression budgets. W2–W7
remain open. Do not close #3420 or #3419 on this delivery alone.

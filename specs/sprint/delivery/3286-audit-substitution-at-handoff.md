# A substitution is audited when the credential is sent

Issue #3286. Task T9 of `specs/plans/2026-09-15-agent-sandbox-drive-plane.md`.

`secret.substituted` used to be written only once the upstream response had
finished. A forward that failed after sending the request (an upstream reset, a
timeout, a response over the size cap) left the destination holding the real
key and the chain saying nothing about it. That is exactly the case an operator
most needs to see.

Now each of the three request paths (`process`, `process_stream`,
`process_body_stream`, which is what a terminated CONNECT flow uses) calls
`audit_handoff` immediately before it calls the forwarder. That writes one
`secret.substituted` per substituted secret. When the forward ends, one
`secret.forward_outcome { destination, outcome }` follows:

| `outcome` | When |
| --- | --- |
| `completed` | the response reached the workload in full |
| `upstream_failed` | the forwarder returned an error before a response head |
| `request_failed` | the streamed request body could not be delivered |
| `response_failed` | the upstream body failed partway |
| `response_refused` | a fail-closed transform refused the response |
| `canceled` | the workload stopped reading |

The outcome is a fixed label chosen at the call site (`ForwardOutcome`). Error
text is never recorded, because an upstream error can quote the request URL. A
flow that substituted nothing records no outcome.

"Sent" means handed to the forward leg, as decided on #3302. That over-reports
a forward that failed before anything reached the wire (connection refused, a
DNS failure). It never under-reports one that did. Hooking the exact socket
write in `mvm-http` would remove the over-report and is left for later.

The response relay task used to have seven bare `return;` exits. Its body is now
an inner `async` block that yields the outcome, and the outcome is written once
after the block, so a new exit cannot skip it.

ADR-023's "every substitution emits a `secret.substituted` entry", false until
this change, now says when it is emitted. The agent-sandbox guide's description
of the gap is replaced with the new behaviour, and its audit table gains
`secret.forward_outcome`. `substitution_is_audited_when_upstream_fails_after_send`
joins claim 16's witnesses in ADR-001 and `model/claims.toml`, and
`CONFORMANCE.md` is regenerated.

## Witnesses

- `substitution_is_audited_when_upstream_fails_after_send`: a terminated flow
  whose forwarder records the request and then fails. The real credential
  reached the forward leg; the chain holds `secret.substituted` before
  `secret.forward_outcome` = `upstream_failed`; and neither the credential nor
  the error text is on the chain. Removing the hand-off audit from
  `process_body_stream` makes it fail.
- `a_completed_forward_records_the_substitution_once_then_completed`
- `a_response_that_fails_partway_is_recorded_after_the_substitution`
  (`response_failed`, streaming path)
- `a_forward_without_a_substitution_records_no_outcome`
- `every_forward_outcome_has_a_distinct_label`

## Validation

- `cargo nextest run --no-fail-fast -p mvm-hostd`: 1955 run, 1955 passed.
- `cargo clippy -p mvm-hostd --all-targets -- -D warnings`: clean.
- `xtask check-claim-catalog` and `xtask check-conformance`: clean.

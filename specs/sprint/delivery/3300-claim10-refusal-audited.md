# A claim-10 refusal is recorded in the chain-signed log

Issue #3300. Task T16 of `specs/plans/2026-09-15-agent-sandbox-drive-plane.md`.

Until now a request the claim-10 gate refused on the substitution path left no
entry in the chain-signed log, so a workload probing destinations it was never
admitted to produced a clean chain. The neighbouring refusals, fail-closed
redaction and a dropped placeholder, were already recorded.

`prepare_flow` now writes `secret.flow_refused { destination, reason }`
(the entry the terminated flow already used for its own refusals) whenever it
refuses a request:

| Refusal | `reason` | `destination` |
| --- | --- | --- |
| The policy does not admit the `host:port` | `policy_denied` | the refused `host:port` |
| The URL has no parseable `host:port` | `malformed` | the host if one parsed, else `unparseable` |
| The destination is a peer name | `peer_destination` | the peer name |

`policy_denied` is the word the FlowMux connect path already records in
`host.flow.denied` for the same decision. A small pure function,
`claim10_refusal`, picks the reason from the gate's verdict, so the label comes
from a fixed set and never from the request. No entry carries the path, the
query, a header value, a placeholder or the body.

Every transport reaches `prepare_flow`: the typed HTTP flow, the streamed flow,
and the terminated flow. So the terminated flow's 502 arm is covered by the same
change, and a witness at that level proves it. Two other refusals that reach
that 502 are not covered here. A forward that fails after the request was sent
is #3286's `secret.forward_outcome`. The AI budget refusal already writes its
own entry.

The agent-sandbox guide's audit table now lists `secret.flow_refused`, which it
had omitted entirely, including the terminator's existing reasons.

One ordering to know about, not changed here: when a request's body must be
replayed (request signing or body replacement), `process_body_stream` buffers
the whole body, up to its cap, before `prepare_flow` runs the gate. Nothing
reaches the wire before the gate decides, but the host does that buffering for
a destination it is about to refuse.

## Witnesses

- `a_claim10_refusal_is_named_by_a_fixed_label`
- `a_claim10_refusal_is_recorded_in_the_chain_signed_log`, which also asserts
  that path, query, header, body, placeholder and secret markers are absent
- `a_malformed_destination_refusal_is_recorded_in_the_chain_signed_log`
- `a_peer_refusal_is_recorded_in_the_chain_signed_log`
- `an_admitted_request_records_no_refusal`
- `a_policy_refusal_on_a_terminated_flow_is_recorded_in_the_chain_signed_log`,
  which verifies the chain's signatures before reading it

## Validation

- `cargo nextest run --no-fail-fast -p mvm-hostd`: 1950 run, 1950 passed.
- `cargo fmt --all -- --check` and
  `cargo clippy -p mvm-hostd --all-targets -- -D warnings`: clean.

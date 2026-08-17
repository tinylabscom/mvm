# FlowMux tells you which half is stale

`2821e2dd4` made the in-guest client FlowMux-only while every host spawn site
still served Raw. Both halves were correct in isolation; together they were a
dead network, and the symptom an operator saw was `ECONNREFUSED` with nothing
naming either build. The frame header's `PROTOCOL_VERSION` did not catch it —
the bytes never disagreed, the expectations did.

So `Hello` and `HelloAck` now carry a
`mvm_contract::protocol::network_flow::hello::Handshake`: a
`BEHAVIOR_REVISION` both sides compile in, and a label for the build that sent
it. `agree` refuses a session whose halves differ and names both, because
every legitimate deployment builds both from the same tree — the host binary
embeds the guest's — so a difference is a stale artifact, never a supported
configuration. The host says `GoAway` with the reason before hanging up, so
the guest reports the same mismatch rather than a bare disconnect.

Two defects surfaced while wiring it, both in the same "nothing detects this"
family:

- The guest client published `SessionState::Ready` at construction, before the
  handshake had been *sent*. A caller could open a flow into a session that
  had agreed nothing. It now starts `Connecting`.
- A pump error — a handshake refusal included — reached a `warn!` and stopped
  there. Callers were already told `Ready` and never learned otherwise, so the
  message naming both builds went nowhere. `SessionState::Dead` now carries the
  reason and `await_ready` returns it.

Fixing the first exposed a third: `active_client` waited on the reconnect
owner's watch while reading readiness from the client's own. It only ever
worked because a fresh client was born `Ready`; against a `Connecting` one it
parked forever. It now waits on whichever moves.

The mock in `addon_dns`'s tests had the mirror-image bug — `let _tx = tx;`
under a comment claiming it held the sender open, dropping it at return. The
real counterparty holds it for the session's life. Same lesson as the rest:
a test double that does not fail the way the real thing fails is not
testing the thing.

Witnesses: `a_guest_from_another_revision_is_refused_by_name`,
`a_guest_with_no_handshake_at_all_is_refused`,
`the_hello_ack_carries_the_host_handshake` (host);
`a_host_from_another_revision_is_refused_by_name`,
`a_host_that_never_answers_the_handshake_says_so`,
`a_fresh_client_is_connecting_until_the_host_answers` (guest); twelve unit
tests on the payload codec and `agree`. The guest set is behind
`--features addons`, which the `Lint feature coverage` lane builds.

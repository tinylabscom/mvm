# Plan 2167 — Durable agent session and event contract

Status: COMPLETE

## Scope

Deliver one versioned, transport-neutral contract for durable agent sessions.
Keep machine lifecycle and transcript/audit persistence as separate existing
systems, and expose the contract through the client and SDK surfaces.

## Completed work

- [x] Define strict public session, request, and idempotency identifiers.
- [x] Define lifecycle states, commands, typed errors, retention limits, and
      versioned durable/ephemeral event envelopes.
- [x] Persist only prompt digests, bounded metadata, and committed transcript
      and audit references; never persist prompt or output bytes.
- [x] Implement idempotent retry handling, cursor history, stale-cursor
      detection, retention eviction, cancellation confirmation, and history
      replay after adapter restart.
- [x] Re-export the contract from `mvm-client` and `mvm-sdk`.
- [x] Add serialization, malformed-envelope, security, reconnect, retry,
      retention, cancellation, and restart tests.
- [x] Add the non-`@wip` BDD scenario for the complete contract witness.
- [x] Run formatting, package checks/tests, workspace checks, workspace
      all-targets tests, normal workspace all-targets Clippy, and the new BDD
      scenarios before opening the pull request. The repository-wide
      doctest-only phase remains a pre-existing mvm-cli wiring failure: its
      rustdoc build cannot resolve legacy sibling-crate exports.

## Compatibility boundary

The existing machine session API remains responsible for VM residency. The
existing stream/transcript and audit stores remain responsible for output
bytes and tamper evidence. Adapters translate those stores into
`CommittedOutput` references and use `AgentSessionJournal::from_history` when
they restart. The later policy, capability, Studio, and parent-epic issues
consume these types without defining another session or transcript format.

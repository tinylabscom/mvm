# Agent session and event contract v1

Status: implemented in `mvm-contract::protocol::agent_session`.

This is the shared semantic contract for an agent workload session. It is
transport-neutral: a gateway, local adapter, CLI, and SDK may choose different
wire transports, but they exchange the same identifiers, commands, event
envelopes, cursors, and error codes.

## Boundary and ownership

An agent session is not a machine session. `mvm-core::domain::session` keeps a
microVM alive and records machine lifecycle. This contract describes the
logical interaction history of an agent workload inside that machine.

The contract is not a second persistence system. Adapters persist transcript
records through the existing stream/transcript path and audit entries through
the existing audit path. They construct `CommittedOutput` only after both
records have committed, then append the durable `OutputAvailable` reference.
The durable event is publishable only after the session event record itself is
committed. A reconnect reader therefore sees references to records that are
already readable and auditable, never a promise of a future write.

`mvm-client` and `mvm-sdk` re-export this module now so all callers share the
same types. Existing machine lifecycle, stream readers, transcript sealing,
and `AgentProtocol` adapter boundaries remain compatible. This contract does
not silently change gateway or CLI routing: those surfaces continue to call
their existing adapter boundary until they explicitly adopt these commands
and envelopes. Adapter execution and Studio presentation are consumers of
this contract, not alternate definitions of it.

## Identifiers and versioning

`AgentSessionId` is the stable public identity. `AgentRequestId` identifies one
logical operation, and `IdempotencyKey` identifies a caller retry window. None
of these may contain an adapter-private identifier, credential, slash, or
uppercase character. Adapter IDs and raw credentials never appear in this
contract.

Every event carries `protocol_version = 1` and exactly one sequence:

- durable events carry a monotonically increasing `durable_sequence`;
- live events carry an adapter-process-local `live_sequence` and are never
  retained or replayed;
- sequence values are never reused after retention eviction.

Unknown versions are rejected. New versions must define a migration or an
explicit incompatibility before they are admitted by an adapter.

## Lifecycle and commands

`AgentSessionJournal::open` emits `Opened` and enters `Ready`. The command
surface then supports `Prompt`, `Cancel`, `Unload`, `Restore`, and `Delete`.
Prompt execution transitions `Ready → Running → Completed`, `Failed`, or
`Canceled`. Cancellation is two-phase: `Cancel` emits `CancelRequested` and
enters `Canceling`; the adapter confirms that execution stopped with
`confirm_cancel`, which emits `Canceled`. Unload and restore are explicit
durable transitions. Delete is terminal.

Every mutating command carries a request ID and idempotency key. The first
accepted key records its request fingerprint and event sequence range. A
retry with the same key and bytes returns that range with `applied = false`;
it never executes the adapter again. Reusing a key for different bytes or a
different operation is a typed `duplicate_request` error.

## Durable versus ephemeral data

Durable events are the replayable history:

- `Opened` records only a workload digest;
- `PromptAccepted` records only a SHA-256 prompt digest;
- completion, cancellation, unload/restore, deletion, and closed failure
  codes record no adapter diagnostic text;
- `OutputAvailable` records stream kind/sequence/hash plus the audit
  sequence/hash of an already committed output record.

Ephemeral events are bounded live deltas and progress notifications. They are
not written to history and may be dropped during disconnect. Their bytes are
never copied into a durable event by the reference journal.

## Reconnect, retention, and partial delivery

Readers call `history(cursor, limit)`. A missing cursor starts at the oldest
retained durable event; a cursor resumes strictly after its sequence. Pages
are capped at 256 events. If retention has evicted the requested predecessor,
the reader receives `stale_cursor` and must restart from the reported retained
boundary or obtain an application-level summary. A cursor for another session
or one ahead of the journal is malformed.

Retention is bounded by event count, approximate encoded bytes, and optional
event age. Eviction removes old records only; it never renumbers later
events. Adapter restart reconstructs the state machine from contiguous durable
history with `from_history`. A transport may surface `partial_delivery` or
`adapter_failure`, but it must not fabricate a durable sequence for bytes it
did not commit.

## Security requirements

The ordinary session history must not contain prompt bytes, output bytes,
credentials, adapter-private IDs, or unbounded diagnostics. Authentication
and authorization happen at the gateway/adapter boundary; this module's
`unauthorized` error is the stable refusal vocabulary, not an authorization
mechanism. Live and history reads must apply the caller's authorization and
the contract's page/delta bounds before returning data.

The conformance tests prove that prompt bytes are absent from serialized
history, live bytes are absent from history, output events contain only
committed references, retries do not duplicate execution, old cursors become
stale without sequence reuse, and state survives a history-based restart.

## Error vocabulary

The stable codes are `malformed_event`, `stale_cursor`, `duplicate_request`,
`adapter_failure`, `cancellation`, `partial_delivery`, `unauthorized`,
`invalid_state`, `limit_exceeded`, `not_found`, `unsupported_version`, and
`session_deleted`. Messages are sanitized contract text and must not contain
request payloads or adapter diagnostics.

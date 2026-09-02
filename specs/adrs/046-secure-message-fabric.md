# ADR-046 — The secure message fabric is the local workload communication data plane

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

**Status:** Proposed  
**Date:** 2026-08-15  
**Owner:** `mvm` maintainers  
**Implemented by:** `specs/plans/2026-08-18-secure-message-fabric.md`  
**Distributed counterpart:** a separately numbered `mvmd` ADR and plan consume the contracts and deterministic state machine defined here.  
**Supersedes:** ADR-035 for guest↔host transport, inter-workload routing,
`StreamEdge`, stdin as a workflow protocol, stdout/stderr as return protocols,
and the raw VMM-console payload path. ADR-035 remains historical rationale for
redaction, bounded telemetry retention, explicit gaps, hash chaining, sealed
roots, fan-out, and operator debugging.  
**Complements:** ADR-001, ADR-014, ADR-019, ADR-020, ADR-031, ADR-037,
ADR-040, ADR-041, and ADR-042.  
**Consumed by:** ADR-045 and its plan, which depend on this fabric and define
no message types of their own.  
**Reconciled by:** ADR-051, which names the shared workload actor model and
records that this ADR's vocabulary is the one that wins.

## Context

`mvm` runs one workload per microVM and currently exposes several communication
mechanisms that were built for different purposes:

- guest control RPC;
- host-delivered process stdin;
- guest-captured process stdout and stderr;
- structured trace output;
- a VMM console fallback;
- static stdout→stdin stream edges;
- live readers and durable transcript storage;
- planned workload mailboxes and streaming replies.

Those mechanisms do not share one identity, authorization, framing, durability,
recovery, tracing, archive, or security model. POSIX file descriptors are also
the wrong abstraction for a distributed agent system:

- stdout does not identify a recipient;
- stdin does not identify a sender;
- byte streams have no durable message boundary;
- a process crash makes acceptance and handling ambiguous;
- there is no lease, ACK, NACK, retry, dead-letter, causation, correlation, or
  attempt identity;
- interpreting stdout as control turns untrusted text into authority;
- routing stdout into another VM's stdin creates an implicit executable-control
  surface;
- a raw serial console is a plaintext guest→host exception;
- file-descriptor semantics do not survive placement across hosts.

At the same time, workloads and operators still need ordinary process
compatibility. Programs may continue reading fd 0 and writing fds 1 and 2, and
users must be able to follow output, inspect traces, send explicitly admitted
input, and investigate completed sessions.

The required distinction is:

> POSIX stdin/stdout/stderr remain guest-local process ABIs. They are not
> guest-boundary, workload-to-workload, workflow, or distributed protocols.

`mvm` therefore owns a secure message-fabric **local data plane**. It provides
the complete one-host implementation and the deterministic state-machine
implementation reused by `mvmd`. It does not own fleet consensus, placement,
replica membership, node PKI issuance, or peer transport.

## Threat model

ADR-001 remains authoritative.

In scope:

- malicious, compromised, confused, or prompt-injected guest workloads;
- malformed, replayed, duplicated, oversized, high-rate, or reordered frames;
- hostile same-host processes attempting to impersonate a guest, reader,
  workload, or internal worker;
- stale VM snapshots, stale boot identities, stale assignment generations, and
  delayed ACKs;
- queue, disk, memory, descriptor, CPU, connection, audit, and archive
  amplification;
- SQLite corruption and SQLite/parser vulnerabilities;
- accidental host code that logs, decodes, decompresses, unpacks, templates,
  compiles, or executes message content;
- crashes at every transport, persistence, receipt, archive, and purge boundary;
- a future compromised `mvmd` peer node attempting to present stale or invalid
  committed commands.

Out of scope, unchanged:

- a fully malicious host or hypervisor;
- hardware-backed confidentiality from the host;
- a claim that nontrivial software has no undiscovered vulnerability.

The intended defensible claim is:

> Within the declared threat model, `mvm` has no plaintext, unauthenticated,
> downgrade, or host-executable workload communication path; every accepted
> local transition is bounded, durable according to its lane, and accountable.

## Decision

### 1. One closed message fabric

The fabric has a closed set of lanes. A lane fixes its origin, recipients,
payload visibility, durability, parser, authorization, and archive behavior.

| Lane | Purpose | Host sees application content? | Semantics |
|---|---|---:|---|
| `Mailbox` | commands, events, requests, unary replies | No | at least once; durable; leases and final disposition |
| `FunctionalStream` | progress, streaming replies, bounded data frames | No | durable ordered frames; backpressure or explicit failure |
| `Telemetry` | stdout, stderr, structured traces, admitted guest diagnostics | Yes, under policy | bounded durable retention; explicit gaps; never controls workload |
| `Input` | operator/API input for an admitted workload | Yes | durable acceptance and delivery receipts; one writer; no implicit replay |
| `System` | host-authored lifecycle, monitor, closure, and fabric events | host-authored | protected type; guest cannot mint |

The lifecycle/control protocol remains separately authorized. User data never
becomes a `System` event, launch request, plan, grant, broker call, or lifecycle
operation.

There is no generic guest-defined lane, host-addressable user mailbox, dynamic
opcode registry, or plugin extension bag.

### 2. Stdio is superseded at the boundary

After migration:

```text
workload fd 1 / fd 2
  -> guest stdio adapter
  -> Telemetry record
  -> authenticated encrypted guest session
  -> host redaction, transcript, fan-out, audit, archive

operator/API input
  -> admitted Input record
  -> authenticated encrypted guest session
  -> guest stdio adapter
  -> workload fd 0
```

Normative consequences:

- stdout and stderr are telemetry producers only;
- telemetry is never interpreted as a command, result, workflow transition, or
  lifecycle decision;
- another workload cannot address a process stdin;
- workflows communicate through `Mailbox`, `FunctionalStream`, and artifact
  bindings, not `StreamEdge`;
- `machine run --stdin -` may remain CLI ergonomics but emits typed `Input`
  records rather than opening a raw guest-boundary byte stream;
- function and agent results are mailbox replies or functional streams, not
  stdout return protocols;
- the raw VMM console payload path is removed;
- host-originated VMM diagnostics remain available because they are not
  guest-controlled payloads;
- early guest boot diagnostics require an authenticated encrypted early-boot
  service or are unavailable.

### 3. Functional route bindings replace `StreamEdge`

The functional graph contains:

```text
MailboxBinding
FunctionalStreamBinding
ArtifactBinding
```

A binding names logical workload roles, exact schemas/content classes, bounds,
retention, producer and consumer constraints, and one committed workflow
revision. It never names fd numbers, CIDs, host paths, node addresses, or
physical VM identifiers.

Telemetry and operator input are not workflow dataflow edges. A workflow cannot
hide control or feedback in stdout/stderr.

Fan-in requires an explicit merge workload or merge service. Arbitrary byte
interleaving is unsupported.

### 4. `mvm` owns the portable contracts and deterministic state machine

The canonical shared contracts live in `mvm-contract` and remain suitable for
`no_std + alloc` where possible.

At minimum:

```text
SessionId
ConversationId
MessageId
PayloadCiphertextId
EnvelopeContentId
MailboxId
AttemptId
StreamId
DataGroupId
AssignmentGeneration
CommandId
CommitPosition
TraceId
SpanId
DeliveryToken

FabricLane
MailboxAddress
MailboxSendCapability
MailboxAssignment
FunctionalStreamAssignment
ConversationCommand
ConversationCommandResult
TransitionReceipt
ArchiveManifest
```

The outer data-plane wire format is fixed-width, byte-aligned, network-order,
and manually bounded. It contains one bounded ciphertext field and no generic
maps, recursion, arbitrary strings, nested lengths, compression, dynamic
schemas, or unknown extension bags.

Public content identities are calculated over ciphertext, never plaintext.

The application state machine is deterministic:

```rust
pub trait ConversationStateMachine {
    fn apply_committed(
        &mut self,
        position: CommitPosition,
        command: ConversationCommand,
    ) -> Result<ConversationCommandResult, ApplyError>;

    fn read(
        &self,
        request: ConversationRead,
    ) -> Result<ConversationReadResult, ReadError>;

    fn snapshot(
        &mut self,
        request: SnapshotRequest,
    ) -> Result<StateSnapshot, SnapshotError>;
}
```

The same command at the same `CommitPosition` is idempotent and returns the
same result. A different command at an already applied position is corruption
and quarantines the shard.

`mvm` does not implement Raft, elections, quorum, membership, or cross-host
leader routing.

### 5. Local and hosted execution use the same apply path

Standalone local mode uses a `StandaloneCommitter`:

```text
validate command
assign monotonic local CommitPosition
apply command to the same SQLite state machine
commit transition + audit outbox
return result
```

Hosted mode uses an `MvmdCommittedCommandSource`:

```text
mvmd consensus commits ConversationCommand
mvmd node calls apply_committed(term/index, command)
the same SQLite state machine applies it
```

There is no second mailbox implementation for cloud mode.

A local session is assigned a local `DataGroupId` even though it has no
consensus group. This keeps addresses, archives, and receipts portable.

### 6. Storage is shard-local SQLite, not shared SQLite

A **conversation shard** is the local storage and blast-radius unit. In hosted
mode it corresponds to one `mvmd` conversation data-group replica. In
standalone mode it is a local security-domain shard.

Each shard has one independent SQLite database:

```text
conversation/shards/<data-group-id>/state.sqlite3
conversation/shards/<data-group-id>/segments/
```

Sessions are partitioned by `SessionId` inside that database.

This replaces the earlier per-session-database recommendation because one
replicated state machine needs one atomic `last_applied` and application-state
commit boundary. Session confidentiality and cleanup are preserved with
per-session storage keys and logical deletion.

Each apply transaction atomically persists:

```text
command effect
CommitPosition / last_applied
deduplication and high-water state
audit-outbox record
result needed for idempotent replay
```

No SQLite database, WAL, SHM file, or lock is shared across hosts.

Cross-node movement transfers logical encrypted commands, snapshots, receipts,
and archives, never live SQLite files or pages.

### 7. Session cleanup uses cryptographic erasure

Every active session has a distinct storage data-encryption key. Sensitive
host-visible record wrappers are encrypted before SQLite receives them.
End-to-end mailbox ciphertext remains nested and unchanged.

After a verified archive commit:

1. session rows are deleted from the shard state machine;
2. the active session storage key is destroyed;
3. segment files are removed;
4. a payload-free tombstone remains;
5. low-priority compaction may reclaim old ciphertext pages later.

Confidentiality does not depend on SQLite page overwriting or `VACUUM`.
Physical remnants are ciphertext whose session key no longer exists.

The tombstone preserves:

```text
session ID
final generation
final CommitPosition
archive root
audit-chain head
sender/mailbox high-water marks
closed and purged timestamps
retention/legal-hold state
```

### 8. Hardened SQLite profile and isolation

SQLite is bundled, pinned, and used only behind the project-owned
`ConversationStateMachine`.

The store runs in a resident confined internal role or bounded worker shard:

```text
no external network
no process execution
no shell or dynamic loading
no workload private key
no fleet issuer key
no guest-supplied SQL
no dynamic identifiers
no extensions, FTS, virtual tables, or custom functions
pre-opened shard paths only
hard CPU, heap, page, statement, and file-size limits
```

Required connection posture after compiled migrations:

```text
DEFENSIVE                ON
TRUSTED_SCHEMA           OFF
DQS DDL/DML              OFF
extension loading        impossible
mmap                     OFF
foreign_keys             ON
cell_size_check          ON
journal_mode             WAL
synchronous              FULL
worker_threads           0
attached databases       0
```

Only checked-in static SQL with bound parameters is permitted. Tables are
`STRICT` and use exact length/range constraints.

Initial hard ceilings:

```text
mailbox application ciphertext     256 KiB
functional stream frame ciphertext  64 KiB
logical command batch                4 MiB
SQLite encoded row/BLOB              1 MiB
SQL text                             64 KiB
delivery attempts                  plan-bounded; default 8
```

Disk full, corruption, timeout, invalid schema, stale generation, and audit
failure are typed refusals. None silently drops, evicts, downgrades, or
acknowledges functional data.

### 9. Transport encryption and end-to-end content encryption

Every guest↔host and reader↔host application channel uses TLS 1.3 mutual
authentication:

```text
TLS 1.3 only
no 0-RTT
no TLS 1.2
no anonymous mode
no permissive verifier
no key logging
service-specific ALPN
short-lived boot-scoped identity
exact tenant/node/node-boot/VM/VM-boot/plan/generation/service binding
no plaintext fallback
```

Mailbox and functional-stream content is additionally encrypted
workload-to-workload using a pinned protocol suite.

The exact workload trust domain owns:

```text
mailbox encryption private key
envelope signing private key
```

Those private keys do not enter the host, control agent, guest message role,
SQLite worker, archive worker, audit signer, or `mvmd`.

The guest message role is ciphertext-only. The exact workload SDK verifies,
decrypts, authenticates, and decodes.

### 10. No host execution or message-derived authority

A fabric payload cannot:

- select a host or guest executable;
- alter argv, environment, working directory, plan, grant, mount, UID, network
  policy, seccomp profile, or volume policy;
- invoke a shell, plugin, dynamic loader, template engine, WASM runtime, or
  script engine;
- become a control RPC, broker RPC, lifecycle request, or stdin implicitly;
- address the host, node, controller, operator, or service as a user mailbox;
- cause the guest message role to edit the read-only rootfs or a host share.

Execution and effect authority comes only from the admitted signed plan.

A workload may act on a message using capabilities it already has. The message
does not add capabilities.

### 11. Delivery and stream semantics

Initial mailbox type:

```text
ExclusiveInbox
```

Contract:

```text
delivery       at least once
ordering       FIFO per sender -> mailbox assignment generation
global order   not promised
external exactly once  not promised
```

Lease, ACK, NACK, and extension bind exact:

```text
session
data group
mailbox
message
delivery token
lease generation
consumer VM/boot
assignment generation
```

A message ID alone cannot ACK.

A retried streaming request creates a new `AttemptId` and `StreamId`. Partial
prior attempts remain visible and are never spliced into the successful
attempt.

Functional frames are never silently evicted. Capacity applies bounded
backpressure or returns explicit failure.

Telemetry retains ADR-035's bounded-ring behavior: it never stalls the
workload, may prune old records, and records explicit gaps.

### 12. Audit, tracing, and attestation

Every durable state transition and its immutable audit-outbox record commit in
the same SQLite transaction.

A transition that cannot become auditable does not commit.

Audit records contain identities, content IDs, positions, generations, byte
counts, decisions, reason codes, and timestamps. They do not contain plaintext,
plaintext digests, ciphertext bodies, private keys, CEKs, or payload-derived
error text.

The authoritative path is:

```text
SQLite transition + audit outbox
  -> hash chain / signed checkpoint
  -> inclusion proof
  -> tracing projection
  -> optional OpenTelemetry export
```

`tracing` and OTLP are analysis projections, not the proof of record.

Users can inspect a correlated timeline combining:

```text
mailbox lifecycle
functional stream attempts
telemetry stdout/stderr
structured traces
admitted input
VM lifecycle
audit verification
archive status
```

### 13. Archive before purge

Session close is explicit and generation-fenced:

```text
Active
  -> Closing
  -> Draining
  -> Sealing
  -> ArchiveCommitted
  -> Purging
  -> Closed
```

Failure enters `ArchiveBlocked` or `Quarantined`.

The archive is a canonical logical record container, not a copied live SQLite
database. It is bounded, versioned, immutable, non-extracting, content-
addressed, signed, and read-back verified before active-state purge.

An archive is evidence. It cannot be accepted as:

```text
mailbox input
functional stream input
execution plan
control request
workload artifact for automatic execution
automatic session restore
```

### 14. Performance contract

A mailbox-enabled workload is ready at:

```text
communication_ready
```

This means:

```text
fresh boot identity
authenticated secure fabric session
workload-owned public mailbox keys registered
exact grants installed
private workload endpoint ready
no restored key/session/nonce/sequence/lease state
```

Release gates:

| Measurement | Gate |
| --- | ---: |
| prepared cold to `communication_ready` | p99 ≤ 200 ms |
| warm claim to `communication_ready` | p99 ≤ 50 ms |
| fabric-enabled vs disabled cold delta | p99 ≤ 5 ms |
| fabric-enabled vs disabled warm delta | p99 ≤ 2 ms |
| first local durable 1 KiB mailbox message | p99 ≤ 10 ms |
| committed transition to subscriber notification | p99 ≤ 5 ms |
| idle fabric CPU | event-driven; no fixed polling |
| launch under archive/compaction work | launch SLO still passes |

Host workers are resident before launch. Database migration, process spawn,
integrity scans, archive work, old-session reconciliation, collector export,
and `mvmd` round trips do not run serially in the launch critical path.

Warm snapshots contain code and initialized buffers, never live authority,
keys, nonces, sequences, assignments, leases, messages, or sessions.

Security does not downgrade to meet latency.

### 15. `mvmd` extension boundary

`mvm` supplies:

```text
portable contracts
secure guest and reader channels
guest-local stdio adapters
workload key registration
deterministic ConversationStateMachine
hardened SQLite shard store
local standalone committer/router
local telemetry and archive-shard production
node-local verification and enforcement
```

`mvmd` supplies:

```text
fleet identity and issuing authority
controller consensus
data-group consensus
session-to-group placement
group membership and leader routing
node PKI and peer transport
replica recovery and snapshots
VM placement and boot rebinding
distributed archive closure
```

`mvm` must not import a consensus library or decide fleet membership.

### 16. Workflow coordination

Capability-secure workflow documents must treat the message fabric as a
prerequisite and consumer boundary:

- workflow routes are mailbox, functional-stream, and artifact bindings;
- stdout/stderr are diagnostic telemetry only;
- workflow lifecycle authority is separate from message authority;
- workflow journals do not duplicate mailbox state;
- distributed workflow placement consumes `mvmd` data-group and workload
  binding contracts;
- no workflow plan can widen fabric bounds or create a second transport.

## Alternatives rejected

### Keep stdin/stdout/stderr as the main protocol

Rejected. It is ambiguous, unauditable at application-message granularity,
non-durable, unsafe to distribute, and encourages untrusted text to become
control.

### Use a mandatory external broker or database

Rejected for the base product. It breaks standalone local operation and adds
another credentialed service and availability dependency.

### Use shared SQLite or libSQL as the distribution mechanism

Rejected. SQLite files stay local. A remote-primary or last-writer-wins
database does not provide exact mailbox ownership, lease, ACK, generation,
migration, or failure semantics.

### Put Raft in `mvm`

Rejected. `mvm` owns local deterministic enforcement. Fleet consensus belongs
to `mvmd`.

### One database per session in replicated mode

Rejected as the common implementation. A data-group state machine needs one
atomic apply position and application commit boundary. Per-session
confidentiality and deletion are achieved with per-session keys inside a
shard-local database.

### One data group per mailbox

Rejected by the distributed ADR. Group count, elections, timers, and snapshots
would scale with mailboxes rather than controlled shard count.

### Host-readable mailbox content

Rejected by default. Host-visible debugging comes from explicit telemetry and
traces, not hidden content escrow.

### Exactly-once external side effects

Rejected as a general promise. Stable idempotency identity plus at-least-once
delivery is the contract.

## Consequences

Positive:

- one secure workload boundary replaces overlapping stdio and stream paths;
- local `mvm` remains single-distribution and external-service-free;
- cloud mode reuses the same state machine and wire contracts;
- SQLite remains a node-local implementation detail;
- functional content remains opaque and non-executable to the host;
- all lifecycle transitions are correlated, auditable, and archivable;
- the launch SLO is explicitly protected.

Costs:

- raw guest console payloads are removed;
- existing stream edges and stdio-based result assumptions must migrate;
- SQLite becomes a narrowly scoped bundled dependency;
- at-least-once delivery requires idempotent workloads;
- the guest image gains a separately confined message role;
- production multi-host availability requires `mvmd` consensus;
- the feature is too security-sensitive for one undifferentiated change.

## Claim witnesses required before promotion

No public security claim is promoted until all are green:

- communication-channel catalog and raw-path freeze;
- no production raw transport or console payload path;
- TLS downgrade/identity/replay ladders;
- fixed binary codec fuzzing;
- no-host-execution static dependency and syscall gates;
- guest message-role confinement witnesses;
- SQLite hardening, corruption, full-disk, timeout, and canary tests;
- deterministic command replay and conflicting-position quarantine;
- transition/audit atomicity;
- message, stream, process-crash, and host-worker crash matrix;
- archive read-back verification before purge;
- archive non-replay tests;
- cold/warm/first-message/notification performance gates;
- platform-specific confinement matrix;
- independent cryptographic and application-security review.

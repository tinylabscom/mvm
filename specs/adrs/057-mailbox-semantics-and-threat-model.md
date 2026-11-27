# ADR-057 — Mailboxes are capability-bound, pass-by-value, and host-blind by tier

Backing: preview
Validation: none — this ADR fixes the contract and threat model; implementation
and claim witnesses belong to the dependent mailbox issues.

**Status:** Accepted
**Date:** 2026-10-24
**Owner:** `mvm` maintainers
**Tracks:** [#4622](https://github.com/tinylabscom/mvm/issues/4622) and
[#4627](https://github.com/tinylabscom/mvm/issues/4627)
**Implemented by:** #4628, #4629, #4630, #4631, #4632, #4633, and #4635
**Supersedes:** ADR-046 for mailbox identity, envelope ownership, delivery,
durability, storage, host-blindness, and the `mvmd` boundary. ADR-046 remains a
proposed design for its non-mailbox lanes and their migration.
**Reconciles:** ADR-062 §0. The workload actor model remains, but its inbox uses
the contract and identities defined here.
**Complements:** ADR-001, ADR-014, ADR-020, ADR-023, ADR-042, ADR-045,
ADR-047, and ADR-056.

Acceptance of this architecture is not an implementation or security-claim
promotion. Until its dependent witnesses pass, no release may advertise a
mailbox service, durable delivery, or host-blind mailbox confidentiality.

## Context

MVM needs one small communication substrate for workloads, hosts, and users.
The first concrete use is a running workload asking an authorized user a
question and receiving a correlated response. The same substrate must later
support workload-to-workload and host-to-host delivery without turning a guest
NIC, stdin, telemetry, FlowMux, or a fleet coordinator into a second protocol.

Earlier proposed ADRs established useful constraints but assigned mailbox
authority too broadly:

- ADR-046 combined mailboxes with streams, telemetry, input, system events,
  SQLite shards, and `mvmd` committed-command groups.
- The original workload actor model (now ADR-062 §0) selected ADR-046's
  `mvm_contract::fabric` vocabulary and one `ExclusiveInbox` per workload.
- Prototype mailbox DTOs and crypto live in `mvmd`, even though standalone
  `mvm` must work without `mvmd`.

The mailbox program now has a narrower boundary. It carries immutable values,
has its own typed service, and is usable locally without fleet consensus. MVM
owns the canonical protocol and enforcement. `mvmd`, Iroh, relays, and future
overlays are replaceable orchestration or byte-transport components.

## Decision drivers

1. Sending transfers an immutable value, never a reference into sender-owned
   memory or storage.
2. Authority is explicit and denied by default. An address is not a
   capability.
3. Ordinary hosts, coordinators, and relays route bounded ciphertext and
   cannot mint sender or destination claims.
4. Delivery, retry, ordering, failure observation, storage, and selective
   receive have finite work and finite state.
5. Standalone `mvm` implements the same canonical protocol that optional fleet
   orchestration consumes.
6. The protocol does not promise global order, perfect failure detection, or
   general exactly-once execution.

## Decision

### 1. Repository and crate ownership

The sole canonical wire vocabulary lives under
`mvm_contract::protocol::mailbox`. The module remains `no_std + alloc`
compatible and contains only bounded, transport-neutral values:

```text
MailboxProtocolVersion       MailboxId
AuthorizationDomainId        MailboxAddress
MailboxPrincipal             BootId
ExecutionEpoch               MessageId
CorrelationId                CausationId
OrderingScope                SequenceNumber
MailboxMessageKind           ContentType
CapabilityReference          EncryptionContext
MailboxEnvelope              DestinationReceipt
DeliveryOutcome              MailboxBounds
```

The contract module defines canonical encoding, field bounds, algorithm and
schema identifiers, and signed-byte domains. It does not generate keys,
encrypt, decrypt, access a clock, store records, open sockets, choose routes,
or interpret coordinator placement.

Runtime ownership is divided without adding a crate merely for the design:

| Responsibility | Owner |
| --- | --- |
| Canonical DTOs, versions, bounds, and signed-byte layout | `mvm-contract::protocol::mailbox` |
| Signature, encryption, capability, replay, expiry, and receipt verification | `mvm-core::mailbox` |
| Bounded journal, deduplication, retention, dead-letter, and snapshot primitives | `mvm-core::mailbox` |
| Dedicated framed service and host-service client primitives | `mvm-host-services::mailbox` |
| Guest boot binding and workload-facing endpoint | `mvm-agentd::mailbox` |
| Activation epochs, local queue ownership, teardown, and durable-store orchestration | `mvm-runtime::mailbox` |
| Host API for send, receive, call, cast, reply, and monitor | `mvm-client` |
| Workload-language APIs using the same contract | `mvm-sdk` |
| Fleet enrollment, placement, route hints, and organization policy wrappers | `mvmd` |

No MVM crate imports `mvmd-types`. Canonical values contain no organization,
fleet, node, instance, placement-generation, or coordinator-RBAC identity.
Those are optional `mvmd` wrapper fields outside the signed MVM envelope.

### 2. Identity is split by purpose

Identity substitution is a protocol error. The following concepts are
distinct newtypes and have no implicit conversions:

| Identity | Lifetime and purpose |
| --- | --- |
| `MailboxPrincipal` | Stable signing identity for a workload, user, or admitted service. |
| `MailboxId` | Stable identity of one mailbox within one authorization domain. |
| `MailboxAddress` | Authorization domain, mailbox ID, and recipient principal; contains no route or host. |
| `BootId` | Fresh for every guest boot; binds one set of boot-scoped session keys. |
| `ExecutionEpoch` | Monotonic activation generation for a durable mailbox owner; increments before restart, restore, or movement becomes active. |
| transport identity | Rotatable endpoint identity certified to a principal and epoch for a bounded validity window. |
| route token | Opaque, rotatable lookup value exposed to routers; it is not a mailbox ID or authority. |

Workload root/control and user/control mailboxes are durable by default and
retain their `MailboxId` across an ordinary restart or host movement. A newly
active owner has a new `BootId` and a strictly greater `ExecutionEpoch`.
Messages and capabilities bound to an older epoch are refused after the new
epoch is active.

Transient child mailboxes are ephemeral by default. Restart destroys their
identity and creates a new mailbox unless the signed workload plan explicitly
declares a durable mailbox and grants the caller authority to retain it.

### 3. Envelope and visible routing metadata

The signed inner envelope contains at least:

```text
protocol and algorithm versions
tenant-scoped authorization domain
sender and recipient principals
mailbox ID
sender BootId and ExecutionEpoch
message ID, correlation ID, and causation ID
message kind and reply address
ordering scope and sequence number
issued-at, absolute expiry, and replay nonce
content type and plaintext-length class
capability reference and policy epoch
encryption context
ciphertext commitment
sender signature
```

The payload is immutable bytes. Encoding copies the payload into the encrypted
envelope; later sender mutation cannot affect accepted bytes.

The outer routing frame reveals only what a hop needs:

```text
outer protocol major version
authorization-domain route label
opaque destination route token
delivery ID
ciphertext length and padding class
expiry and hop limit
transport-binding identifier
```

Sender, recipient, mailbox ID, content type, correlation, causation, sequence,
capability, signature, and payload remain inside the ciphertext. Audit records
may contain stable content commitments and typed outcomes, never payload,
plaintext hashes, private keys, or payload-derived errors.

### 4. Capability verification is the authority gate

Knowing a mailbox address or route token grants no operation. A capability is
signed by the authorization-domain authority and binds:

```text
issuer and subject principal
tenant and authorization domain
allowed mailbox or mailbox namespace
send, receive, reply, monitor, or administer operation
allowed message kinds and content types
maximum payload, rate, outstanding calls, and queue contribution
minimum and maximum execution epoch where applicable
policy epoch, not-before, expiry, and revocation identity
delegation depth and attenuation constraints
```

Runtime verification checks the signature, issuer, subject, operation, tenant,
domain, mailbox, principal, epoch, bounds, time window, policy epoch, and
revocation state before payload disclosure or queue allocation. A sender field
inside the envelope never authorizes itself. Delegation may only remove
authority or tighten bounds.

Guest Receive and ACK use a separate, signed Receive capability and a distinct
per-boot guest-held mailbox ACK signing key, not the FlowMux egress identity or
the host's mailbox sealing key. The destination authority enrolls its public
key against the signed plan ID/nonce, recipient, current authenticated guest
boot and reader session, execution/policy epoch, capability ID, and validity
window. The guest must demonstrate possession over a fresh challenge before delivery;
the destination signs a lease binding that session, delivery, ciphertext
commitment, and deadline. ACKs are signed by the enrolled guest key over the
exact lease and are replay-checked and journaled before a terminal disposition.
A transport connection, inherited warm-parent key, or structurally valid
enrollment without signature and current-boot verification authorizes nothing.

### 5. `call`, `cast`, reply, cancellation, and admission

Version 1 has three application message kinds:

- `call` requests exactly one correlated application reply and waits until a
  monotonic local deadline derived from the signed absolute expiry;
- `cast` requests no application reply and returns after local validation and
  the declared admission level;
- `reply` names the original correlation ID and the exact reply capability.

Version 1 has no lossy `best_effort_cast`. Adding one requires a distinct kind,
API name, receipt, and bounds; it may never be an overload behavior for
ordinary `cast`.

Timeout and cancellation are observations, not rollback:

- call timeout does not assert that the remote handler did not execute;
- cancellation is a best-effort correlated message and cannot revoke a result
  or external effect already accepted;
- a late reply is recorded with a terminal `late` disposition and cannot
  satisfy a later call, even if an application reuses a correlation value;
- correlation IDs are unique within the caller principal and execution epoch.

A full, unauthorized, expired, oversized, rate-limited, or shutting-down local
mailbox refuses synchronously before acceptance. A remote destination returns
a destination-signed typed receipt. Successful transport connection is not
mailbox authority.

### 6. Acceptance, delivery, ordering, and deduplication

Delivery is at least once. `MessageId` is stable across retries, and the
receiver retains bounded deduplication state through the message expiry plus
the declared retention window. A duplicate receives a signed `duplicate`
receipt referring to the original terminal disposition.

Receipts distinguish:

```text
accepted_ephemeral
accepted_local_durable
accepted_durable
duplicate
expired
refused
full
unavailable
late
dead_lettered
```

Only the destination mailbox authority may sign destination acceptance. A
relay, source host, transport, or `mvmd` route service cannot manufacture it.

Ordering is FIFO within one sender principal, destination mailbox, execution
epoch, and ordering scope. Gaps block only that scope until the missing
sequence arrives, expires, or receives a terminal disposition. There is no
order across senders, mailboxes, or epochs and no global total order.

`accepted_local_durable` is a distinct version-two destination receipt: the
encrypted envelope, deduplication identity, and required delivery state are
fsynced outside the source VM's lifetime before signing. Its locally fsynced
chain head permits ordinary process-crash recovery but does not detect a whole
host rollback or survive destruction of all host storage. It is available to
standalone MVM without a fleet service or hardware dependency. The existing
version-one `accepted_durable` remains reserved for independently witnessed
rollback protection; an old receipt must never be relabeled as local durability,
and version-one readers reject the new outcome. Neither receipt implies that an
application processed or ACKed the message.

An exact same-ID, same-ciphertext retry of locally accepted history returns the
original signed version-two local receipt, including its original observation
time, after current authority and committed-state checks. Re-signing that body
must reproduce the original bytes; an unprovable acceptance is unknown, not a
new version-one `duplicate` that loses the acceptance tier. Different bytes
under the same ID conflict. Version-one `duplicate` behavior is unchanged.

The guest's local-durable outbox request is sender-owned pending work, not an
acceptance receipt. Its host retains the canonical sealed bytes and records a
bounded dispatch attempt before destination I/O. The guest removes the
pending request only after checking a version-two destination signature bound
to its boot-pinned mailbox authority, execution epoch, and message ID. An
older unit success cannot satisfy this path; wrong-key, stale-epoch, or
unverifiable replies keep the operation pending or yield a typed terminal
refusal. An already-dispatched envelope is not rewritten for a replacement
epoch, and this rule does not authorize transfer of an accepted message.

`accepted_ephemeral` means the message is owned by the named live mailbox
epoch. If that epoch terminates, the signed epoch-terminal observation closes
the volatile queue; senders that need recovery use stable IDs and retry into a
newly authorized epoch. A partitioned observer may remain uncertain until
reconciliation; the protocol does not invent a terminal fact it cannot observe.

### 7. Durability, retry, poison messages, and dead letters

Durable mailboxes use an encrypted append-only journal and independently
recoverable delivery state. Accepted history is not rewritten. A record binds
the tenant, mailbox, message ID, execution epoch, ciphertext commitment,
previous-record commitment, receipt state, and key version.

Retry work is bounded by the capability and mailbox policy. The initial
default is eight delivery attempts, with monotonic backoff timers and explicit
cancellation. A handler NACK identifies a typed retryable or terminal reason;
it never includes payload-derived text. Exhausted, malformed-after-decryption,
unsupported-content, and policy-terminal messages move to an encrypted
dead-letter journal in the same recipient authorization domain and receive a
terminal receipt.

Retention bounds journal bytes, message count, deduplication entries, attempts,
dead letters, and tombstones per mailbox and tenant. Disk full, rollback,
corruption, wrong key, and quota exhaustion fail closed. Crash recovery is an
idempotent reconciliation of durable state, not a sleep-polled foreground
path.

For the standalone local tier, a signed plan must declare a finite retention
window before admission; an absent policy does not imply an infinite default.
The versioned optional `MailboxGrant.retention` preserves old signed-plan
bytes when absent; a present duration is an explicit request bounded by host
policy, and expiry-plus-retention arithmetic fails closed on overflow.
The workload configures the requested window before the plan is signed; the
host operator independently configures a maximum. Neither has a permissive
default: without both, local-durable admission refuses, and a request above
the host maximum refuses rather than being silently clamped. Changing the
maximum affects new acceptance, not the recovery or retention deadline of
messages already accepted under a verified signed plan and custody binding.
Compaction first durably publishes an encrypted, destination-authenticated
snapshot of still-live delivery state and dedup tombstones through each
message's expiry plus that window, then advances the local chain head, and
only then prunes superseded records. Recovery verifies the appropriate old
prefix or committed snapshot after interruption; it never guesses a new
genesis from a gap. If the snapshot or retained tombstones cannot fit the
finite quota, new acceptance refuses rather than discarding replay evidence.
This host-local sequence does not detect rollback of the entire host.

The checkpoint is an immutable journal generation, not a second acceptance
authority. It binds the previous committed tip, the next monotonic cursor,
the history-key version, the exact signed retention window, and a content
commitment over the retained ciphertext, receipt bodies, leases, signed guest
ACKs, terminal dispositions, and dedup state. The destination signs this
commitment before encrypting and fsyncing the checkpoint. The local anchor
then advances to the checkpoint tip before any earlier record is removed.
Only terminal messages strictly past expiry plus their signed retention
window, and challenges owned by those messages, may leave that snapshot;
pending messages and their replay evidence remain until terminal settlement.
Recovery of a pre-anchor interruption requires the complete old prefix;
recovery of a post-anchor interruption requires the checkpoint and its
matching tip even when old files are still present or partly pruned. A
missing, divergent, oversized, or unverifiable checkpoint refuses rather
than falling back to a shorter history. Snapshotting cannot turn a leased
message into an unsigned host ACK or reset the original signed acceptance
time. The same bounded writer lock excludes concurrent admission, lease,
ACK, and compaction while this transition is in flight.

### 8. Selective receive is bounded and fair

Selective receive may match only authenticated inner-header fields declared by
the receiver API: message kind, sender principal, content type, correlation,
and ordering scope. The host-blind router does not evaluate these selectors.

The receiver maintains bounded indexes and a policy-capped candidate window.
One receive operation examines at most 256 candidates and returns a typed
`scan_bound_reached` result rather than scanning the whole mailbox. Aging gives
older eligible messages priority within a selector, and each selector has a
bounded consecutive-match budget so a hot pattern cannot starve other ready
messages. Unsupported selectors are refused; arbitrary predicates and payload
search are not protocol features.

### 9. Links, monitors, supervision, and failure observations

Monitoring is a capability-bound operation. A monitor lease binds observer,
target principal, mailbox, target execution epoch, policy epoch, expiry, and a
fresh monitor ID. An unauthorized observer learns neither existence nor
failure state.

Failure events are signed observations with a source and evidence class:

```text
terminal_exit
epoch_replaced
lease_expired
destination_refused
transport_unreachable
observation_uncertain
```

Only the first three are terminal for the named epoch. A timeout, partition,
or transport failure produces `observation_uncertain`, never a fabricated
death claim. Delayed events for an older epoch cannot affect a current owner.

A link is two accepted monitor leases plus a declared propagation policy; it
is not an implicit bidirectional capability. A supervisor acts only on a
verified event for the expected epoch and follows a signed, bounded restart
policy with maximum attempts, backoff, and escalation destination. A DOWN-style
event may trigger a compensating message or restart, but it never grants new
authority and is not a perfect distributed failure detector.

### 10. Restart, partition, reconnect, and movement

During a partition, each side preserves accepted durable state and bounded
retry state. Reconnect reauthenticates the transport binding, exchanges
high-water marks, retransmits stable message IDs, and deduplicates at the
destination. Expired messages receive a terminal receipt instead of delivery.

Movement uses a monotonically increasing `ExecutionEpoch`. Source fencing is
durable before destination activation. Mailbox, credential, egress, and effect
brokers refuse a stale epoch. A duplicate or interrupted handoff reconciles by
stable mailbox identity and epoch; no route hint can activate two owners.

These movement rules define the contract consumed by #4631. They do not claim
that migration is implemented.

### 11. Plaintext and host-blindness are tiered claims

| Assurance tier | Where plaintext and keys may exist | Defensible claim |
| --- | --- | --- |
| Development / trusted host | Sender and recipient processes; the host or debugger may inspect guest memory. | Authenticated encrypted protocol, not host-blindness. |
| Isolated production on ordinary virtualization | Sender and recipient guests; transport and stores hold ciphertext, but the hypervisor owner can inspect guest memory. | Relay- and service-process-blind payloads, not malicious-host confidentiality. |
| Host-blind sealed execution | Only measured sender/recipient confidential guests after attestation-bound key release; ordinary host and `mvmd` processes never receive decryption material. | Host-blind payload confidentiality after hardware, attestation, rollback, and key-release witnesses pass. |

The trusted-host local-durable receipt is an acceptance class, not an assurance
tier upgrade: the same host remains trusted for key custody and rollback. A
missing or rotated history/payload key must refuse recovery rather than mint a
replacement. Standalone MVM may keep versioned, purpose-separated keys in its
existing protected host key directory; an independently operated checkpoint
and optional confidential hardware remain upgrades, never implicit dependencies
of a local mailbox launch.

Encryption at rest, TLS, a microVM boundary, Keychain, TPM storage, or an
honest host does not by itself establish host-blind execution. A platform
without confidential-computing memory protection must refuse a requested
host-blind mailbox profile rather than silently relabel the ordinary tier.

#### Local key custody at fleet density (#5292)

One resident scheduler per host routes, queues, journals, and schedules wakes
for **sealed messages only**. It holds no mailbox key and cannot open or forge
a mailbox message. Seal/open and mailbox authorization belong to a VM-scoped
key holder, not the scheduler or the network endpoint. A host-wide key holder
would hold every mailbox key on a single-tenant host; putting those keys in a
daemon that parses guest input makes one parser compromise an all-mailboxes
compromise. A per-tenant key-holding daemon is therefore not the chosen
density tradeoff.

An existing per-VM supervisor is a candidate holder on HVF and libkrun,
subject to a witness for its guest-input boundary, key lifecycle, and
fail-closed admission. Firecracker has no separate per-VM supervisor today:
its VMM is not a substitute key holder, so it needs a VM-scoped helper or a
separately reviewed supervisor. Holders should wake on owned socket/process
events and may exit after an idle deadline; crash recovery reconciles the
durable journal and VM ownership without making a periodic idle poll the
delivery path. Acceptance requires measurement of recovery, first-message
latency, warm claims, and idle wakeups at fleet scale.

This is a **design decision, not a shipped guarantee**. Compromise of a
key holder exposes its own VM's mailbox. The scheduler sees message metadata
(including routing, size, timing, and queue activity) even though it cannot
read or forge payloads. A compromised host remains outside this isolation
claim; the host-blind tier above still needs its own hardware witnesses.

### 12. Dedicated service and resource isolation

Mailboxes receive a separately registered `GuestService` and dedicated vsock
port. They do not share machine-control, telemetry, broker, network-flow, or
workload-exit framing, queues, credits, listeners, or worker budgets.

Admission bounds exist per payload, sender, mailbox, tenant, and host for
queued bytes, queue depth, outstanding calls, selectors, delivery attempts,
connections, streams, timers, and journal work. Saturation returns a typed
mailbox result and cannot borrow another service's reserved capacity. The
implementation uses the smallest event primitive matching existing ownership;
this decision adds no repository-wide async runtime.

### 13. Overlay, transport, and orchestration remain replaceable

Mailbox protocol code depends on two MVM-owned interfaces:

```text
PeerOverlay: stable principal or mailbox -> authorized route candidates
PeerTransport: authenticated bounded byte channel -> path outcome
```

Overlay resolution conveys no send authority. Transport authentication conveys
no mailbox authority. The encoded canonical envelope crosses the byte
transport unchanged.

`mvm` defines the mailbox contract, authorization gates, and transport-neutral
interfaces; it does not implement a cross-host network. `mvmd` owns concrete
cross-host transport and orchestration, including the planned Iroh adapter
behind `PeerTransport`. Direct and customer-configured relay paths are the
default; public relay use requires explicit configuration and cannot be a
silent fallback. HeatNet/UOR and a future virtual NIC are evaluated separately
and cannot smuggle packet forwarding into mailbox authority.

`mvmd` may enroll principals, place workloads, distribute signed route hints,
and store or forward opaque ciphertext. It cannot define a second envelope,
signature domain, receipt, ACK format, or payload schema; decrypt payloads in
an ordinary coordinator; or become required for local delivery.

The MVM interfaces reuse operational lessons from the earlier `mvmd`
`AgentTransport` work without importing an `mvmd` crate or runtime dependency.
`mvmd` implements cross-host adapters for the interfaces and may adapt its
coordinator metadata into authorized route hints; it cannot edit, decrypt, or
re-sign the canonical envelope. Local mailbox delivery remains usable without
`mvmd`.

### 14. Prototype `mvmd` type migration

The existing prototype types are migration inputs, not protocol authority:

| Existing prototype | Canonical disposition |
| --- | --- |
| `mvmd_types::MailboxAddress` | Adapter to canonical `MailboxAddress`; fleet placement remains in an outer `mvmd` wrapper. |
| `MailboxAssignment` | `mvmd` placement wrapper only; no canonical equivalent and no signed-envelope authority. |
| `EncryptedMailboxEnvelope` | Decode through an explicitly versioned compatibility adapter, then re-encode as canonical `MailboxEnvelope`; never reinterpret bytes in place. |
| `DeliveryLease` | MVM runtime delivery state bound to message, mailbox, epoch, and delivery token. |
| `LeasedMessage` | Runtime API projection, not a wire-contract type. |
| `AckDelivery` / `NackDelivery` | Map to canonical destination outcomes after destination verification; coordinator acknowledgements are not destination receipts. |

The `mvmd.mailbox.v1` signature domain is never accepted as the MVM canonical
domain. `mvmd` may carry a bounded compatibility adapter for one declared
release window if inventory finds persisted rows or supported API clients.
The adapter is isolated from canonical verification, rejects unknown fields,
has fixture tests, and emits an explicit legacy-version result.

Declaring the prototype format disposable requires all of this evidence:

1. a production and staging inventory reports zero persisted V1 mailbox rows;
2. supported-client telemetry or a client registry reports zero V1 producers;
3. backup restore plus migration rehearsal finds no retained record needing V1;
4. release notes announce rejection before the decoder is removed;
5. the owner records the evidence on tinylabscom/mvmd#254.

Without that evidence, the bounded adapter is mandatory. Silent reinterpretation
and unbounded dual-format support are both rejected.

### 15. Performance contract

For bounded messages, online endpoints, a warm direct connection, and the
declared same-region topology, send-to-destination-acceptance p95 is below
300 ms. The hot path requires no global consensus, synchronous all-peer
replication, or fresh DHT lookup.

Ephemeral acceptance, durable acceptance, call response, local delivery,
same-host delivery, direct same-region delivery, customer relay, public relay,
offline delivery, and partition recovery are measured and reported separately.
Security never downgrades to satisfy latency.

## Proposed amendment: Call, Cast and Reply service decisions

**Status:** Proposed. Nothing in this section is accepted, wire-visible, or
implementable as a decision until a maintainer accepts it here, one item at a
time. It adds no claim to ADR-001 and promotes nothing. Sections 1-15 above
stay authoritative where they speak; D7 only restates them.

**Tracks:** [#4629](https://github.com/tinylabscom/mvm/issues/4629) and
[#4622](https://github.com/tinylabscom/mvm/issues/4622); also bears on
[#4630](https://github.com/tinylabscom/mvm/issues/4630),
[#5126](https://github.com/tinylabscom/mvm/issues/5126),
[#5255](https://github.com/tinylabscom/mvm/issues/5255),
[#5292](https://github.com/tinylabscom/mvm/issues/5292), and
[#4633](https://github.com/tinylabscom/mvm/issues/4633).

Section 5 fixes what Call, Cast and Reply mean. It does not say how they are
carried, who admits them, what a caller sees when they are refused, or what
happens to an unanswered Call when the callee's epoch ends. The questions below
are the open ones. Each gives the options, a recommendation, and what the
choice blocks. D7 is the exception: it is recorded as decided.

### D1. Envelope: build on V1 now, or wait for V3

Question: does the Call/Cast/Reply service ship on the current V1 envelope, or
wait for the V3 profile that adds endpoint encryption?

Constraints already stated by the maintainer in the V3 design session:

- No approval was given to use the legacy plaintext or host-sealing path for V3.
- V3 retry equality is authenticated-body identity, not signature-byte
  identity. A retry compares the authenticated body; the original proof bytes
  are retained and not regenerated.
- Receive or Reply authority never implies general reverse Send authority.

Options:

1. Build the whole service on V1 now, including the guest send path.
2. Wait for V3 before writing anything.
3. Define conversation semantics (correlation, deadlines, late-reply handling,
   refusals, admission) independent of the envelope, and hold the guest send
   path until V3's field table exists.

Recommendation: option 3. The semantics do not depend on how a body is sealed,
and writing them once avoids a second rewrite. Do not extend the V1
host-sealing send path: it puts sealing in the host, which is what V3 is meant
to avoid, and any retry-equality rule built on it would have to be unpicked.
The guest send-path slice waits for the V3 field table.

Blocks: the kind-and-correlation send path and the guest-to-host slice wait on
this. The conversation core and the quota ledger do not.

### D2. Guest wire: sibling request or extended outbox frame

Question: how does a guest ask for a Call, Cast or Reply?

Options:

1. Extend the existing outbox frame with kind and correlation fields.
2. Add a sibling, separately versioned request next to the outbox frame.

Recommendation: option 2, defined independent of the envelope. The outbox
frame is the sender-owned pending-work record of section 6; giving it a second
meaning (conversation state) couples its retry rules to deadlines and replies.
A sibling request can be versioned and refused on its own, and an older guest
that knows only the outbox frame fails closed instead of misreading new fields.

Blocks: the guest-to-host and host-to-guest slices.

### D3. Refusal names and the advisory rule

Question: what refusals does a caller see, and what may it conclude from a
timeout?

Proposed names and meanings. These are proposals only; none is wire-visible
until accepted.

| Name | Meaning |
| --- | --- |
| RateLimited | A rate or outstanding-call limit was exceeded for this sender. Retrying later may succeed. |
| ShuttingDown | The destination mailbox is closing and takes no new work. |
| Expired | The message's signed expiry had passed when it was presented. |
| Unavailable | The destination is not reachable or not live in an authorized epoch. |

Each is synchronous: the refusal is returned before acceptance. Each is a
refusal and never consumes a dedup identity, so the same message ID may be
retried once the condition clears. This matches section 5 (a full, expired,
rate-limited or shutting-down mailbox refuses before acceptance) and the
existing rule that a refused message does not consume its identity. The
existing full and unauthorized outcomes are not redefined here.

Rule recorded by the maintainer: MVE1 is advisory only. It is not
authoritative termination, not evidence of non-execution, not a budget
release, and not permission to send a fresh message ID. Consequently a
TimedOut or Cancelled outcome means only that the caller stopped waiting. It is
never evidence that the callee did not execute, and never permission to reuse a
message ID or to treat the call's budget as returned. This restates section 5
(a timeout does not assert non-execution) for the two outcome names.

Recommendation: accept the four names and the advisory rule together. Splitting
them risks a caller reading Unavailable or TimedOut as "safe to resend as a new
message".

Blocks: the conversation core's outcome type can carry the advisory rule now as
documentation. The wire names block the send path and both directions' slices.

### D4. Unreplied Calls at epoch end or restart

Question: what happens to a Call that has no Reply when the callee's epoch ends
or the host restarts?

Options:

1. Resolve as Unavailable, always.
2. Carry the Call into the durable journal automatically when the destination
   is durable.
3. Resolve as Unavailable by default; carry into the journal only by explicit
   opt-in in both the conversation and the signed workload plan.

Recommendation: option 3, which is the preference the maintainer recorded on
#5126. Durability alone is not sufficient reason to transfer: a durable
mailbox says the message survives, not that its sender agreed to have a
pending wait outlive the epoch. Requiring both the conversation and the signed
plan keeps the decision in signed authority. A pending Call is never revived
as a wait by transfer (ADR-062 keeps this separate from recovering a committed
outcome). Until accepted, the behavior is option 1.

Blocks: the epoch-end handling in the conversation core, and #5126's transfer
work. The default (Unavailable) needs no new storage and can proceed.

### D5. Quotas and admission

Question: where are max_outstanding_calls, max_messages_per_minute and
max_queue_contribution_bytes enforced?

Constraints:

- The scheduler (the mailbox scheduler inside the existing host daemon, no new
  crate, shared within one unprivileged OS user and canonical runtime instance)
  is keyless. Signing and MAC secrets are excluded from it.
- A counter or a mutex is never authority. Acceptance, receive and ACK need an
  authoritative compare-and-commit against the current generation.
- Accounting uses the actual encoded objects and retained evidence. Admission
  must reserve the worst-case completion evidence the message may later need,
  or refuse.

Options:

1. Enforce in the scheduler.
2. Enforce in the per-VM service, which holds the key and sees each message.
3. A ledger interface implemented in the per-VM service, shaped so a scheduler
   can later call it, with no quota state that outlives the authority that
   granted it.

Recommendation: option 3. The scheduler cannot be the authority because it is
keyless and a counter held there is not authority; the per-VM service can commit
and compare against the current generation. Defining the ledger as an
interface keeps fleet-density scheduling (#5292) possible without moving
authority. A quota that survives its grant's epoch would let a stale holder
spend a fresh one's budget, so ledger state is dropped with the authority.

Blocks: the quota ledger slice, and every send path, since admission precedes
acceptance. The limit values themselves are not decided here.

### D6. Audit entries

Undecided. This records the questions and the minimum, not an answer.

Open questions:

- Which of Call, Cast, Reply, each refusal, and a late Reply emit an entry?
- Is a refusal an entry per attempt, or aggregated, given that refusals are
  synchronous and unbounded in number?
- Do entries carry the message ID, correlation ID and kind, and never payload
  bytes, as the stream plane's audit entries do?
- Is a late Reply recorded against the original Call or as its own event?

Minimum needed for chain coverage of the kind claim 8 gives plan admission:
every accepted Call, Cast and Reply, and every terminal disposition of a Call
(replied, late, expired, unavailable), is represented by a chain-signed entry,
and a refusal that consumed no identity is either recorded or explicitly
exempted by the accepted rule. This proposes no new numbered claim; any claim
language is a separate maintainer decision.

Blocks: audit wiring in every send path. Not the conversation core.

### D7. Transport ownership (decided)

Recorded as decided by the maintainer on 2026-11-16, consistent with sections
1 and 13. `mvm` has no network and implements no cross-host transport. `mvmd`
owns the Iroh adapter behind the peer transport interface. `mvm` keeps the
transport-neutral contract. Text in #4622 and #4633 saying that `mvm` owns the
adapter is stale and is superseded by this paragraph.

### What each decision unblocks

| Slice | D1 | D2 | D3 | D4 | D5 | D6 |
| --- | --- | --- | --- | --- | --- | --- |
| Conversation core (open as a PR) | no | no | outcome docs only | default only | no | no |
| Quota ledger | no | no | names | no | yes | no |
| Kind-and-correlation send path | yes | yes | yes | no | yes | yes |
| Guest to host | yes | yes | yes | yes | yes | yes |
| Host to guest | yes | yes | yes | yes | yes | yes |
| Boundary tests | per slice | per slice | yes | yes | yes | yes |

"Yes" means the slice cannot be built as final until the decision is accepted.
D7 blocks nothing; it is settled.

## Threat model

### In scope

- malicious or compromised senders and recipients;
- forged, tampered, replayed, delayed, duplicated, reordered, oversized, deeply
  nested, or high-rate frames;
- capability substitution, confused-deputy delegation, stale epochs, stale
  route hints, stale transport bindings, and revoked policy;
- malicious ordinary host services, `mvmd` coordinators, transports, and relays
  in the host-blind profile;
- queue, disk, memory, CPU, descriptor, timer, retry, selector, connection, and
  audit amplification;
- crash, truncation, rollback, partial write, partition, reconnect, duplicate
  handoff, and delayed failure observations;
- payload or error content reaching logs, metrics, audit, or routing metadata.

### Outside a claim unless the tier names a mechanism

- confidentiality from a malicious hypervisor on ordinary virtualization;
- availability against a host that destroys all local durable state and every
  configured replica;
- a perfect distributed failure detector;
- general exactly-once handler execution or external effects;
- global total ordering;
- traffic-analysis resistance beyond declared padding and metadata bounds.

## Alternatives rejected

### Keep ADR-046's conversation-shard protocol as the mailbox authority

Rejected. It makes local delivery vocabulary depend on data groups and
committed positions owned by optional fleet consensus. Mailbox identity and
delivery work without `mvmd`; fleet replication adapts around them.

### Copy the `mvmd` prototype into `mvm-contract`

Rejected. The prototype lacks the complete identity, epoch, capability,
receipt, and algorithm-version contract and embeds the wrong ownership
direction.

### Treat an address, TLS session, or route as authority

Rejected. Each is discoverability or transport state, not permission to send,
receive, reply, monitor, or administer.

### Promise exactly-once delivery

Rejected. At-least-once delivery, stable IDs, receiver deduplication, and
idempotency receipts are implementable. External effects require their own
idempotency keys and durable receipts.

### Use telemetry, FlowMux, stdin, or machine control for mailbox messages

Rejected. Sharing authority or capacity lets one service widen or starve
another and makes payload data executable by accident.

## Consequences

Positive:

- one canonical protocol serves standalone and fleet operation;
- identity, authority, routing, transport, and placement cannot be substituted;
- accepted normal messages have typed, bounded outcomes;
- hosts and relays remain ciphertext-only where the assurance tier supports it;
- local and cross-host implementations can evolve independently behind stable
  interfaces.

Costs:

- at-least-once delivery requires application idempotency;
- durable mailboxes require encrypted journal, deduplication, retention, and
  crash-recovery state;
- monitor and supervisor semantics expose uncertainty instead of simplifying it
  into a false binary liveness claim;
- prototype `mvmd` clients and records require evidence-backed disposal or a
  bounded adapter;
- host-blind claims require confidential-computing and attestation evidence not
  supplied by this ADR.

## Required evidence before implementation issues close

- canonical codec and `no_std + alloc` checks;
- positive, tamper, wrong-key, wrong-identity, wrong-tenant, replay, expiry,
  stale-epoch, version, and boundary-size tests;
- immutable pass-by-value witness;
- dedicated-service queue and credit isolation witness;
- durable journal crash, rollback, corruption, rotation, retention, and
  deletion tests;
- retry, duplicate, late-reply, poison, dead-letter, selective-receive, and
  fairness tests;
- monitor, partition, delayed-event, restart, and stale-epoch tests;
- direct and relayed ciphertext-only transport tests;
- plaintext-location and key-release evidence for every advertised assurance
  tier;
- reproducible p50, p95, and p99 measurements for each declared topology and
  acknowledgement class.

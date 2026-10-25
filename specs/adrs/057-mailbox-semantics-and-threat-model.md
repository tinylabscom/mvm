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
**Reconciles:** ADR-051. The workload actor model remains, but its inbox uses
the contract and identities defined here.
**Complements:** ADR-001, ADR-014, ADR-020, ADR-031, ADR-042, ADR-045,
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
- ADR-051 selected ADR-046's `mvm_contract::fabric` vocabulary and one
  `ExclusiveInbox` per workload.
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

`accepted_durable` means the encrypted envelope and deduplication identity are
durably committed before the receipt is signed. `accepted_ephemeral` means the
message is owned by the named live mailbox epoch. If that epoch terminates,
the signed epoch-terminal observation closes the volatile queue; senders that
need recovery use stable IDs and retry into a newly authorized epoch. A
partitioned observer may remain uncertain until reconciliation; the protocol
does not invent a terminal fact it cannot observe.

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

Encryption at rest, TLS, a microVM boundary, Keychain, TPM storage, or an
honest host does not by itself establish host-blind execution. A platform
without confidential-computing memory protection must refuse a requested
host-blind mailbox profile rather than silently relabel the ordinary tier.

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

Iroh is the first planned cross-host transport behind `PeerTransport`. Direct
and customer-configured relay paths are the default; public relay use requires
explicit configuration and cannot be a silent fallback. HeatNet/UOR and a
future virtual NIC are evaluated separately and cannot smuggle packet
forwarding into mailbox authority.

`mvmd` may enroll principals, place workloads, distribute signed route hints,
and store or forward opaque ciphertext. It cannot define a second envelope,
signature domain, receipt, ACK format, or payload schema; decrypt payloads in
an ordinary coordinator; or become required for local delivery.

The MVM interfaces reuse operational lessons from the earlier `mvmd`
`AgentTransport` work without importing an `mvmd` crate or runtime dependency.
Optional coordinator metadata enters through a narrow route-hint adapter that
selects an already authorized path; it cannot edit, decrypt, or re-sign the
canonical envelope.

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

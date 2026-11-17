# ADR-063 — Disconnected host authority, recovery, and observation retention

Backing: preview
Validation: none — architecture decision only; integrated runtime, power-loss,
cross-host and hardware witnesses are required before capability promotion.

**Status:** Proposed for repository adoption; direction approved in the
owning issue's design discussion.
**Date:** 2026-11-17
**Owner:** `mvm` maintainers
**Tracks:** [#5097](https://github.com/tinylabscom/mvm/issues/5097)
**Refines:** [Host interface and distributed execution](../contracts/host-interface-distributed-execution.md).
**Complements:** [ADR-001](001-microvm-security-posture.md) and
[ADR-057](057-mailbox-semantics-and-threat-model.md).
**Related proposals:** [ADR-060](060-mailbox-rebuild-handoff.md) and
[ADR-062](062-workload-actor-lifecycle-and-causal-evidence.md). Neither is
accepted or implemented by this decision.

This document records architectural choices, not implementation progress or
new shipped security claims. GitHub owns remaining work and acceptance.
Existing signed-plan, mailbox and backend contracts remain authoritative;
changes to their wire meanings require separate versioned review.

## Problem and goals

A ship, aircraft and ground vehicle must exchange authorized observations on
a closed mission network, continue bounded work during partitions, and
optionally connect to a control center. The host interface must enforce the
same policy locally in every connectivity condition. Sensitive execution
state should be disposable, while selected observations can survive power
loss under an explicit recovery policy. Small-device resource use and
admission-inclusive launch latency are design constraints, not exemptions
from verification.

## Approaches considered

| Approach | Tradeoff | Decision |
| --- | --- | --- |
| Central authorization for every operation | Immediate central decisions, but disconnected work and predictable local latency are unavailable. | Reject as the mandatory path. |
| Fully replicated authority on every peer | More available issuers, but distributed ownership, capture exposure and consensus costs move onto every device. | Reject as the initial design. |
| Local enforcement under signed, bounded authority | Fast local decisions and offline operation; requires explicit expiry, fencing and reconciliation. | Adopt, with narrowly delegated mission-local renewal. |

Purely volatile storage and universally recoverable storage are also rejected
as global defaults: neither expresses disposable execution together with
selectively retained observations. Retention is a per-data-class decision.

## Decision

### 1. Deployment and connectivity are independent

Local execution remains usable without enrollment, `mvmd`, an external key
service or required TPM/TEE. Managed mission operation is opt-in.

A closed mission network can be air-gapped from the Internet while its nodes
communicate internally. Connected mode adds an authorized control-center
uplink. Physical isolation has no network delivery until an approved transfer
path exists.

Track peer connectivity separately from authority/uplink connectivity and
name the dependencies of each workload. Losing one peer does not imply losing
all peers or require every workload to stop. Preserve primary lifecycle
states `Pending`, `Active`, `Quarantined`, and `Revoked`; disconnected,
degraded and reconnecting remain conditions.

### 2. A local controller owns enforcement; networking is replaceable

Use one shared host controller with bounded per-workload state, rather than
a general networking process or thread per VM. Retain narrowly scoped
per-workload custody helpers where the backend requires them; sharing does
not remove key isolation or lifecycle obligations.

The non-root networking worker is separate from lifecycle authority and
long-lived key custody. It carries authorized ciphertext; it cannot authorize
launch, mint destination acceptance or widen grants. Platform enforcement
continues through existing backend mechanisms. Workload VMs have no NIC or
SSH path.

This worker belongs to the optional `mvmd` deployment, including on a closed
mission network without an Internet uplink. ADR-057's transport ownership
decision remains intact: `mvm` owns the transport-neutral peer contract;
`mvmd` owns the concrete cross-host transport and its Iroh adapter. Neither
offline operation nor SpiralCore integration adds a cross-host network
implementation to standalone `mvm`.

The logical interface composes existing contracts:

| Surface | Local owner and responsibility |
| --- | --- |
| Execution | Canonical policy/admission and backend lifecycle: verify, establish enforcement, launch, quarantine, stop, replace. |
| Mailbox | Canonical MVM capability, envelope, queue, receipt, replay and delivery rules. |
| Coordination | Optional `mvmd`-backed identity, policy/revocation distribution, route hints, heartbeat observations and reconciliation. |
| Object transfer | Authorized endpoint encoding/reconstruction through SpiralCore, inside mailbox authorization. |

The guest-facing contract is transport-independent, but required enforcement
is always local. The managed profile requires authenticated encrypted control
and workload channels across host-to-host and host-to-guest boundaries;
VM-to-VM values remain inside canonical mailbox encryption. Vsock alone is
not encryption. An unavailable required channel guarantee refuses admission
rather than silently falling back to plaintext.

A network-worker crash cannot disable expiry or local policy. Controller
failure must revoke effect paths and stop workloads through a qualified
backend supervisor/watchdog. If this cannot be enforced, the requested
managed profile refuses admission. Cleanup failure retains resource charges
and reports uncertainty; it does not imply successful stop.

### 3. Shared trust, distinct identities and bounded delegation

Provision a signed mission configuration containing trusted issuers, eligible
node public identities, policy floors, authorized packages, communication
relationships, finite lease/restart limits and retention rules. Nodes generate
distinct private identity keys; a fleet-wide shared secret is not identity.
Separate identity, transport, mailbox, storage and policy-signing key purposes.

The authority chain is organization authority, bounded mission delegation,
then node/workload leases. Preissued leases permit operation before contacting
an issuer. One explicitly designated mission issuer may renew them without
the external control center. Its delegation binds eligible subjects,
operations, policy constraints, maximum child-lease duration and an absolute
mission expiry. It cannot widen authority, revive a known-revoked identity,
extend its own expiry or delegate further unless explicitly permitted.
Renewals must bind the current subject and authorization generation and be
replay-protected and auditable.

Do not elect a new issuer merely because the old one is unreachable. Issuer
replication/failover needs separately reviewed quorum and fencing semantics.
Admission, policy publication, revocation and exclusive ownership updates
require coordinated authority; route hints and telemetry may converge
eventually. Neither stale replicas nor route caches grant permissions.

A vehicle isolated from every authorized issuer cannot self-renew. Restart,
retry, clock correction and reconnect attempts cannot extend a lease.
Unseen revocations cannot be enforced during isolation: accepted offline
duration bounds that exposure. Mission durations and organization ceilings
must be explicitly chosen from operating requirements; there is no invented
universal lease duration.

### 4. Time, replay and execution identity have separate roles

Distinguish mission/policy generation, monotonic workload execution epoch,
fresh boot/session identity, message identity/sequence, and clock evidence.
Unrelated nodes do not share one workload-ownership epoch.

Kuramoto-derived replay state is a checkpoint and logical step, not a
security timestamp. Physical synchronization, if added, is a separate
estimate with uncertainty. Neither phase agreement nor logical replay proves
current authorization, global ordering or exclusive ownership.

Within a controller lifetime, use monotonic expiry deadlines derived
conservatively from validated lease time and clock uncertainty. Suspend,
resume and reboot must not reset elapsed lease time. If time validity cannot
be established, refuse lease-dependent operations and reauthorize. A local
ledger supports ordinary crash recovery, not malicious whole-host rollback;
stronger rollback/time claims require qualified hardware or independent
authority evidence.

### 5. Local restart is distinct from relocation

Local restart on the disconnected vehicle is the first recovery scenario.
Connectivity loss alone does not rebuild a healthy workload. A signed policy
may instead require stop on dependency loss, or explicitly permit replacement
within the still-valid offline lease and finite restart budget.

The local controller fences the old incarnation and all effect holders,
confirms termination, advances the epoch, verifies the same signed package
digest, and admits a clean replacement with fresh boot/session keys. Package
verification is not admission or readiness. Ordinary workloads stop at lease
expiry; explicitly authorized isolated computation requires its own finite
authority and cannot retain external effects. The recovery controller remains
available to authenticate and re-admit.

Do not restore suspect VM memory. Only explicitly authorized retained inputs
may feed the replacement. Old-epoch messages, capabilities and uncertain
effects are not silently retargeted or replayed. A controller that cannot
prove old-owner retirement refuses activation of a replacement.

Cross-host relocation is a separate operation: the destination verifies its
own backend/capacity/data availability and cannot become an effectful owner
until source fencing is proven. Timeout alone is insufficient. Lease-based
takeover would require validated clock/expiry assumptions and enforcement at
every relevant effect boundary. Without that evidence, relocation refuses.
A new epoch number cannot remotely stop an unreachable device.

### 6. Connectivity observations and reconciliation

Heartbeats are small authenticated, encrypted observations with session and
sequence freshness, not proof that a workload is healthy or dead. Piggyback
when practical. Retry uses exponential backoff with jitter, finite attempts,
attempt deadlines and cancellation. Retry exhaustion reports unreachable or
uncertain; it is not a fleet-wide terminal fact.

| Trigger | Transition owner and required action |
| --- | --- |
| Missed heartbeat | Local connection manager marks the link suspect and schedules bounded retries. |
| Retry exhaustion | Controller applies the signed dependency policy; remaining valid authority is unchanged. |
| Lease expiry or required enforcement loss | Controller closes affected capabilities and stops the workload by default. |
| Authorized local restart | Controller records fencing/retirement and new epoch before replacement authority becomes active. |
| Controller/host restart | Recover verified epoch, policy, replay and deadline evidence, or require external reauthorization. |
| Link returns | Establish a fresh authenticated session; reconcile revocation, policy, epoch, required assurance, queue state and receipts before restoring effects. |
| Cleanup or dispatched-result uncertainty | Preserve the uncertain outcome; do not invent completion or automatically repeat effects. |

Low-rate recovery rounds or link-change events may reconnect after the initial
retry budget, without prolonging a lease. Security reconciliation precedes
bulk data synchronization. Retransmission uses original immutable message
identity while its authority remains valid. Expired/stale-epoch items receive
the canonical refusal or terminal/unknown outcome, not rewritten envelopes.
Cancellation and deadlines do not roll back accepted external effects.

### 7. Volatile execution and independently retained observations

| Data class | Retention and recovery decision |
| --- | --- |
| VM working state, active plaintext, session keys | Volatile by default; no intentional swap, dump, snapshot or temporary-file persistence. |
| Plaintext codec/reconstruction caches | Volatile by default; included in memory, cleanup and disclosure limits. |
| Observation records | Configurable discard, archive-only recovery, or explicit local recovery. |
| Epoch, replay, policy floor and lease/restart bookkeeping | Minimal protected ledger, or external reauthorization after loss. Never recreate authority from an empty store. |
| Audit evidence | Independently bounded encrypted retention, priority for security events and explicit gaps; no payload/secret logging. |
| Signed packages and trust configuration | Verifiable provisioning artifacts, not disposable runtime state. They do not alone authorize reboot. |

The capture-sensitive profile defaults retained observations to **archive-only
recovery**. Encrypt each retained object under a purpose-scoped data key and
wrap that key to an authorized recovery recipient. The vehicle may encrypt
offline using a preloaded recipient public key, but retains no local
recoverable copy of the corresponding archive decryption key. Drop transient
data keys and plaintext after the required operation. The recovery recipient
can be mission-local; this does not require a cloud service.

Record provenance, event identity, schema, recipient/key version and integrity
bindings under the archive policy. A committed archive receipt requires the
ciphertext and wrapped key to reach the configured durable storage boundary.
Data not yet committed can be lost on power failure. Recovery verifies the
original authenticated record before exposing it; it does not reenact old
workload authority or complete an old Call.

Local-recovery mode explicitly retains recoverable keys through an admitted
provider and therefore has a different capture-risk claim. Discard mode
retains neither the observation nor a durable receipt for its payload.
Unsupported custody or durability requirements refuse rather than downgrade.
Durable archive storage does not make the mailbox durable: mailbox acceptance,
object publication, delivery ACK and application completion remain separate.

A fully volatile host cannot reconstruct monotonic ownership and replay state
after power loss. It must obtain a fresh authorized activation from an issuer
with the required history before managed execution resumes. Observations may
survive as ciphertext even when that execution cannot resume offline.

### 8. UOR-ADDR and SpiralCore optimize the canonical path

Reuse SpiralCore's shared object core and authorized transport integration
before selecting another QUIC/TLS implementation. Concrete cross-host
integration is owned by `mvmd` behind the existing peer contract; this ADR
does not replace its decided Iroh adapter. Any alternative carrier requires
review in that owner. Do not introduce a new mailbox broker, guest network
path, custom cryptography or policy authority. Encoding happens at an
authorized plaintext endpoint before canonical mailbox encryption; relays
forward sealed envelopes; receivers authenticate, decrypt, reconstruct and
verify before publication.

UOR-ADDR supplies typed canonical identity, not compression or access rights.
Bind realization/canonicalization version and algorithm alongside the label.
When original bytes matter, also bind exact-byte digest and length: equivalent
canonical values can have different original representations. Event identity
is separate from content identity; identical sensor values can be distinct
observations.

Reuse only verified receiver state in the same authorized scope. On cache
loss, reauthenticate and establish available state before choosing a recipe;
use an authorized cold representation or refuse. Never infer possession from
a stale cache advertisement. Keep content labels/inventories protected and
deduplication scoped; cross-domain equality can leak information.

Profiles cap addressing input, parser depth, manifest size, reconstruction
steps, decompressed bytes, CPU, cache memory and in-flight work even when an
upstream library accepts unbounded inputs. Do not compress secrets together
with attacker-controlled input in a shared context. Raw or conventional
compression can win on cost; no codec saving is assumed.

One aggregate host budget accounts for workers, tenant/workload state, queues,
indexes, caches and in-flight bytes. Reserve bounded control/receipt capacity
within that budget; bulk transfers cannot starve expiry, revocation or recovery.
Use backpressure and typed refusals at limits, not unbounded buffering or
silent message loss. Avoid blocking controller progress on socket I/O or
unbounded reconstruction work.

### 9. Termination, destruction and assurance remain separate

Stop ends execution; quarantine removes ordinary capabilities; revoke
withdraws authority; destroy-data targets named keys/state. Missing heartbeats
alone never authorize destruction. A destruction request requires explicit
scope, issuer, freshness/replay checks and policy authority.

Close new effects/secret release, fence and stop affected workloads, revoke
sessions, destroy the designated keys, attempt memory cleanup, and record
outcomes without claiming success for unknown holders. The host controller
must not exit before required cleanup merely to simulate destruction.

Destroying every recoverable copy of a key can render its retained ciphertext
undecryptable; it cannot undo plaintext exposure or prove physical erasure.
Local destruction does not erase an archive whose recipient retains recovery
keys. Hardware attestation alone does not make the active host blind to
plaintext. ADR-001's trusted-host boundary and backend-specific evidence apply;
an unsupported stronger profile refuses.

## Missing pieces and qualification

Existing host-interface, lease and mailbox primitives are integration inputs,
not evidence that this complete architecture runs. Implementation needs
reviewed delegation/renewal and archive-custody contracts, controller restart
and enforcement-loss handling, cross-host key delivery, canonical queue
reconciliation and explicit resource profiles. Any public schema or signed
wire changes need versioned compatibility review.

Before promotion, run these focused experiments on pinned combined sources:

| Question | Smallest useful witness | Decision rule |
| --- | --- | --- |
| Can local recovery preserve authority bounds? | Three nodes with asymmetric partitions, lease expiry, VM restart, controller crash, suspend and clock rollback. | No widened authority, reset deadline/budget, duplicate effectful owner or stale-epoch acceptance; otherwise refuse that recovery profile. |
| Can observations outlive disposable execution? | Interrupt archive writes and power-cycle the sender; independently recover with the recipient key, including wrong-key and missing-key controls. | Only committed valid records recover; the sender has no retained archive decryption path in archive-only mode. This is not a physical-erasure witness. |
| Does SpiralCore help this deployment? | Matched raw, conventional compression and SpiralCore transfers across actual hosts, with cold/warm caches, receipt loss and cache reset. | Compare total link bytes, endpoint CPU, memory and completion percentiles including preparation and receipts; select only within the admitted resource profile. |
| Is the resident controller bounded? | Idle and saturated workload populations with concurrent transfers, full queues and stalled peers. | Control/expiry remains responsive, total resources stay bounded, and cold <300 ms / warm <50 ms launch budgets include admission. Report safe replacement separately. |

Security witnesses include issuer compromise scope, wrong tenant/key,
expired delegation, policy rollback, replay, revocation reconciliation,
decompression/queue pressure, audit pressure, cleanup failure and immutable
retry identity. Label simulation separately from native/backend evidence.

## Open decisions

Implementation review must set finite mission/lease/restart and resource
limits from operating requirements, choose supported archive algorithms and
recipient rotation/recovery custody, qualify per-backend memory/watchdog
controls, and define the combined SpiralCore/UOR dependency pins. No new
library dependency or installed wire format is selected by this ADR.
Mission-issuer replication, physical clock synchronization and cross-host
relocation qualification remain separate decisions; the default does not
depend on them.

## External reference baseline

These references inform the design, not MVM security or performance claims:

- [Kuramoto model](https://en.wikipedia.org/wiki/Kuramoto_model): coupled
  oscillator synchronization, not a secure timestamp or ownership protocol.
- [UOR-ADDR conformance](https://github.com/uor-Foundation/uor-addr/blob/69f6b3afa6a103b55d1ff1a46e7ed790d5fd4572/CONFORMANCE.md):
  typed canonical content identity; MVM must impose its own resource bounds.
- [SpiralCore architecture](https://github.com/R4-Laboratories/SpiralCore/blob/6b0edd8c9106c0f9380748de9ad7e3cf7ab199ae/README.md):
  endpoint optimization, canonical mailbox boundary and separately qualified
  transport paths.
- [SpiralCore MVM adapter](https://github.com/R4-Laboratories/SpiralCore/blob/6b0edd8c9106c0f9380748de9ad7e3cf7ab199ae/crates/spiralcore-mvm-adapter/README.md):
  bounded admission, receipt and object-publication distinctions. Upstream
  component reports are not independently reproduced here and do not qualify
  this three-node architecture or every MVM backend.

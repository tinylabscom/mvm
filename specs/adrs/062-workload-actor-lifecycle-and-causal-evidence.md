# ADR-062 — Workload actors: recipe identity, residency, supervision, and causal evidence

Backing: preview
Validation: none — this is a proposed design; no code implements it and no
test exercises it.

**Status:** Proposed
**Date:** 2026-11-14
**Owner:** `mvm` maintainers
**Extends, if accepted:** ADR-051 (the workload actor model). It fixes what
ADR-051 left open: identity across VMs, residency, supervision policy,
evidence that spans actors, trace storage, and the density budget.
**Complements:** ADR-001, ADR-014, ADR-025, ADR-035, ADR-045, ADR-057,
ADR-060, and ADR-110.
**Related issues:** #5097 (distributed host interface), #5292 (shared mailbox
daemon and its key-custody decision D1), #5510 (density), #5121 and the
factory-edge presentation merged in #5396.
**Tracked in:** #5544 (design, decisions and phases); first issues #5538,
#5539, #5540, #5541, #5542 and #5543. Nothing here may be described as shipped,
and no ADR-001 claim changes, until the evidence listed at the end exists.

## Context

MVM microVMs are used as functions, not only as isolated sandboxes: a workload
receives a message, does bounded work, replies, and waits. ADR-051 named this
the workload actor model and rejected an in-process actor framework. ADR-057
gave the mailbox Erlang-style semantics: `call`, `cast`, `reply`, monitors,
links, signed restart policy and `ExecutionEpoch` fencing.

What remains undecided is the lifecycle around those messages:

- **Identity across VMs.** An actor outlives any one VM: it is restarted,
  rebuilt, parked and moved. Today evidence is keyed by run, and
  `mvmctl explain <name>` is ambiguous when a name is reused.
- **Residency.** An actor blocked in receive does not need a running VM. The
  density target (500 to 1,000 resident microVMs per host, #5510) depends on
  waiting actors costing a mailbox and saved state, not a running process.
- **Failure.** "Let it crash" must mean rebuild from signed inputs, never
  patch or resume a crashed guest.
- **Evidence across actors.** The audit chain, `session.sealed` RFC 6962
  roots, the stream plane's sealed roots (ADR-035) and the evidence archive
  (ADR-110) are each per run. Nothing links a message in one actor to its
  effect in another.
- **Application tracing.** Developers already use tracing and expect
  OpenTelemetry. That data must survive a VM failure without being mistaken
  for evidence.

## Decision

### 1. Identity: workload, epoch, recipe

Three identifiers, each with one job:

| Identifier | Meaning | Stable across |
| --- | --- | --- |
| Workload ID | The logical actor; the name a mailbox address resolves to. | Restart, rebuild, park, wake, move |
| Execution epoch | One VM lifetime of that workload (`ExecutionEpoch`). | Nothing: every boot, restore or wake is a new epoch |
| Recipe hash | Digest over the measured inputs of the signed plan: image, kernel, verity roots, asset identities (claim 19) and policy. | Identical inputs only |

At admission the host signs one binding per epoch: workload ID, epoch, recipe
hash, plan digest and policy version. The workload ID is a name; the recipe
hash is the proof of what ran. A rebuild that changes inputs keeps the workload
ID and records a new recipe hash under a new epoch, so a recipe cannot change
silently behind a name.

Evidence and traces have three views:

- **Per epoch** (the default): everything one VM did. A replacement epoch
  carries none of its predecessor's records.
- **Per workload**: the history of every epoch of one actor, requested
  explicitly.
- **Per recipe**: every epoch, under any workload ID, that ran the same inputs.

Locally the host issues workload IDs; in managed mode `mvmd` does. Neither may
mint an identity that the signed plan does not name.

### 2. State classes

A workload declares how its state survives, in the plan; host and organization
ceilings may only narrow it.

| Class | What survives an epoch | Attested by | Movable between hosts |
| --- | --- | --- | --- |
| Stateless | Recipe only | Construction | Anywhere the recipe is admitted |
| Restart-safe | Recipe, admitted volumes and the mailbox journal | Construction plus the journal | Wherever its volumes may go |
| Memory | Recipe plus an encrypted memory snapshot | Custody: the capturing host's signature for that epoch | Same VMM and architecture only |

A snapshot is attested by custody, not by derivation: nothing can recompute its
bytes from the recipe. Replaying a journal against a recipe re-executes work; it
does not reconstruct state, because untrusted code is not deterministic. Only
stateless and restart-safe workloads may be rebuilt on a different host from
their recipe. Shipping a memory snapshot between hosts is an optimization that
needs its own decision.

### 3. Residency is a condition, not a lifecycle state

Residency is independent of the authority states in #5097 (`Pending`, `Active`,
`Quarantined`, `Revoked`). A parked actor is still `Active`; it has no VM.

| Residency | Host cost | Entered when |
| --- | --- | --- |
| Running | Working set plus VMM | Delivery, timer, launch |
| Idle | Working set after free-page reporting | The workload blocks |
| Parked | No RAM or CPU; recipe, or recipe plus snapshot, on disk | Blocked in receive with no pending timer, past a grace period |

Rules:

1. **Receive is the park point; a message is the wake.** Timers move to the
   host while parked.
2. **A wake is a launch.** It runs the #5097 preflight. A scoped preflight
   cache may make it cheap, but a cache hit never bypasses revocation, policy
   version, or live capacity. A wake refused by revocation gives the waiting
   message a terminal receipt.
3. **Every wake is a new epoch.** Restoring the same snapshot twice therefore
   yields one current owner and one stale epoch that every broker refuses.
4. **Snapshots are node-local** and encrypted under a per-epoch key. If a
   managed node's lease expires while an actor is parked, stopping it means
   destroying that key.
5. **Residency is reported** through the host interface, so placement counts a
   parked standard-class actor as holding a slot but no memory.

This ADR does not change the warm-start requirement; it puts it on the message
path. Wake latency is the warm budget (under 50 ms, admission included).

### 4. Supervision: let it crash, rebuild from the recipe

- A crash is a `terminal_exit` observation (ADR-057 §9) for its epoch.
- The **host** applies the restart policy from the signed plan: strategy
  (one-for-one, one-for-all, rest-for-one), maximum restarts within a period,
  backoff, and an escalation mailbox. Guest code does not enforce supervision.
- A restart rebuilds from the recipe at the next epoch. It never resumes the
  crashed guest's memory.
- Exceeding the restart limit moves the workload to `Quarantined`.
- Restarts, give-ups and escalations are host-witnessed events (section 5).

### 5. Evidence and tracing

#### 5.1 Two tiers

- **Host-witnessed events are evidence.** Admission, the epoch binding, spawn
  and release, mailbox send and acceptance, egress allowed and denied,
  host-service calls, park, wake, exit, restart and quarantine. The host
  observes these itself; they are chain-signed and Merkle-committed.
- **Workload-asserted spans are telemetry.** Application (L7) spans the guest
  reports. The host records them with integrity from the moment it receives
  them, and labels them as asserted: the host can attest that the guest said
  something at a time, not that it was true (the checked/asserted distinction
  of ADR-110).

#### 5.2 Loss rules

- **Record, then respond.** A host-witnessed decision is appended to the audit
  journal before its result is returned to the guest or caller. It never passes
  through a buffer that may drop. A decision whose record cannot be written is
  refused, as an unauditable wall-clock kill already is.
- **Asserted spans stream as they happen** over the existing telemetry
  channel (`GuestService::Telemetry`), separate from mailbox, broker and
  network-flow framing (ADR-057 §12), into a small fixed host buffer. Dropped
  spans are counted, never silent.

#### 5.3 The host seals every epoch

On every exit, including a crash or kill, the host seals the epoch: a signed
record holding its RFC 6962 root and a completeness label:

- `complete`;
- guest stream truncated, with the number of spans dropped;
- host record incomplete, with the reason.

A sealed epoch is never silently partial.

#### 5.4 Causal links across actors

1. **Messages carry the sender's leaf hash.** The encrypted inner header of
   each mailbox envelope carries the hash of the sender's send entry. The
   receiver records it in its acceptance entry. Logs on different actors become
   hash-linked, so an auditor can prove that a message caused a spawn that
   caused an egress. It is never placed in the routing frame.
2. **Parents commit to children.** When a child is released, the parent's log
   records the child's final sealed root. The supervision tree becomes a tree of
   Merkle trees with one root per workflow run, verifiable with inclusion
   proofs.

#### 5.5 OpenTelemetry

- Guests use standard OpenTelemetry SDKs and export OTLP over vsock to one host
  collector per host. No guest NIC is added.
- The host overwrites identity resource attributes (tenant, workload ID,
  epoch, recipe hash). A guest cannot set them.
- Trace context travels in the encrypted inner header of mailbox envelopes, so
  a trace follows a message between VMs.
- Spans for host-witnessed events carry their leaf hash, linking telemetry to
  evidence without merging them.
- The OTLP parser is bounded and fuzzed like other host-guest framing (claim 5).

#### 5.6 Readback

All readback goes through `mvm-client`, extending
`mvm_client::explain::explain_local_run` rather than adding a path. Studio and
other embedders add no verifier, recorder or storage reader of their own.

### 6. Storage and encryption

**Keys.** Records are encrypted with a 256-bit AEAD under a per-workload key
derived from the tenant key, with a per-epoch subkey. Destroying a key erases
that workload or epoch cryptographically. Traces, mailbox journals and
snapshots share one custody decision, #5292 D1, decided by the owner on
2026-11-14 (see Owner decisions).

**Who can read.** By default the host can read stored traces (trusted-host
tier), so local search, `explain` and export work. A host-blind tier, in which
the guest encrypts to the tenant's key and the host stores ciphertext only, is
selectable by policy where confidential-computing hardware exists, under the
tiers of ADR-057 §11. In both tiers the Merkle tree commits to the stored
records as stored, so completeness can be checked without decrypting.

**In flight.**

| Hop | Protection | Reason |
| --- | --- | --- |
| Guest to host over vsock | Authenticated, bounded framing; the stream is bound to the VM through the socket the VMM was handed, never through a guest claim | No network is involved, and the only parties able to read it (the host user, root) can already read guest memory |
| Host to host, mailbox | End-to-end per ADR-057 | Leaves the host |
| Cross-host transport, export | Encrypted transport | Leaves the host |

The host-blind tier is the exception: there the guest encrypts before data
leaves the VM.

**Residual.** Plaintext exists briefly in host process memory before it is
encrypted at rest. Unencrypted Linux swap could write it to disk. Either lock
those buffers in memory or state the limit.

**Retention.** Set in the signed plan and capped by host and organization
ceilings; the smallest wins. Recovery after a failure exports a sealed epoch as
an evidence archive (ADR-110).

### 7. Cryptographic agility and post-quantum readiness

- Every signed or encrypted record names its algorithms, as the mailbox
  envelope's `EncryptionContext` and signature fields already do. Plans, audit
  records, checkpoint metadata and trace records gain the same fields, so an old
  record verifies under the algorithm it was written with.
- **First:** hybrid X25519 + ML-KEM-768 for mailbox key agreement and cross-host
  transport, because recorded traffic can be decrypted later.
- **Second:** hybrid Ed25519 + ML-DSA-65 for long-lived artifacts: audit and
  epoch seals, evidence archives, packs and plans.
- **Deferred:** post-quantum signatures on each message. About 3.3 KB per
  signature costs density and mailbox bounds before the threat requires it.
- Symmetric keys are 256-bit everywhere; hashes are unchanged.
- Release signing follows Sigstore's support and is tracked outside mvm.
- Zero-knowledge proofs are not used on any launch, wake or message path. They
  may be considered later for offline proofs over sealed epochs.

### 8. Pools: a resolver, not a shared mailbox

N instances of one function are N ordinary admitted actors, each with its own
exclusive mailbox. A **resolver** maps a function address to one worker:

- It returns one worker's address and key, narrowed from the capability the
  caller already holds. It mints no authority and admits nothing.
- The caller encrypts to that worker. The resolver never sees plaintext.
- When ordering matters, the ordering scope is hashed to a worker so a key stays
  on one worker.
- The resolver emits demand: the local standby pool or `mvmd` adds or parks
  workers. Scale-to-zero means every worker is parked.
- The contract lives in `mvm`, so local use needs no `mvmd`; `mvmd` provides the
  cross-host resolver.

### 9. Density budget

Everything above must fit one per-resident-VM host budget covering the VMM,
mailbox, trace collection, keys and buffers. The figures are set from the
#5510 baseline wave and pinned in the perf budget registry; the proposal to
test is 10 MiB host memory and 0.05% of a core idle per resident VM. Specific
rules:

- One trace collector and one mailbox service per host, not per VM (#5292).
- Trace buffers are small and fixed. Asserted spans are opt-in and sampled;
  host-witnessed events are always on and cost the guest nothing.
- Wake admission has its own budget, because every wake is an admission.
- Per-epoch seals and indexes let `explain` and audit verification cost scale
  with the epoch read, not with the whole chain.
- The recipe hash is the sharing key for read-only base pages, fork families
  and standby pools, within a tenant (ADR-025).

### 10. No actor framework

ADR-051 §4 stands and now also covers ractor and tellus: their actors are tasks
in one process, their references act as addresses rather than capabilities, and
their restarts keep the same address and mailbox where MVM requires a new
epoch.

## Compatibility with the factory-edge presentation (#5396)

The presentation needs none of this ADR. It uses explicit stop and fresh
launch, one host and the existing client path, and it claims no hot
replacement, message handoff, parking or cross-host delivery. This ADR must not
widen those claims, and must keep each beat working:

| Beat | What this ADR adds | Constraint it must keep |
| --- | --- | --- |
| 1–2, useful work and declared boundaries | Each workload has a workload ID and a recipe hash to display | Shown only through `mvm-client`; policy cards show only enforced permissions |
| 3–4, denial while other work continues | The denial is a host-witnessed event, recorded before the refusal is returned | Unrelated workloads show no denial; readback stays a preview in Studio until witnessed |
| 5, stop and fresh launch | A replacement is a new epoch, or a new workload ID if launched under a new name | The default per-epoch view shows the replacement with none of the old refusals; the old epoch's refusal stays on record |
| 6, evidence | Sealed epochs with completeness labels; per-epoch verification | Still evidence of admitted execution and host-mediated effects, not of internal computation or output correctness |

Requirements the presentation makes visible:

1. **Record-then-respond (5.2).** In repeated HVF runs, 11 of 12 denied runs
   wrote the expected audit entry; the cause of the miss is unknown. Under this
   ADR a missing denial is either impossible (the refusal is not returned
   without its record) or shows as an incomplete seal. It is never silent.
2. **One denial event shape.** The same scripted request was recorded as a
   refused DNS lookup in one run and a refused connection in another. The
   canonical event carries one type with a kind (lookup or connect).
3. **Explain by workload and epoch.** `explain` accepts a name but resolves it
   to a workload ID and epoch, removing the name-reuse ambiguity the runbook
   works around.
4. **Per-epoch default view (section 1).** Keeps the demo's assertion that a
   replacement carries none of the refusals.
5. **Chain growth.** The runbook notes that every lookup is a signed entry, so
   `explain` and `trust audit verify` slow the longer workloads run. Per-epoch
   seals and indexes (section 9) bound that cost.

## Consequences

- ADR-051 gains identity, residency, supervision and evidence rules. ADR-057's
  wire contract gains two fields in the encrypted inner header (sender leaf
  hash, trace context), which needs a protocol version step.
- #5097's host interface gains a residency report and a wake preflight.
- The audit pipeline gains a rule that decisions are recorded before results
  are returned, and per-epoch seals with completeness labels.
- Traces, mailboxes and snapshots wait on #5292 D1.
- The warm budget becomes a messaging budget. The HVF warm gap, and warm claims
  for mailbox-granted launches (#5292), move onto the critical path.

## Alternatives rejected

- **Recipe hash as the only identity.** Every rebuild would look like a new
  workload and break the thread of evidence.
- **Parked as a fifth lifecycle state.** It would mix residency with authority
  and duplicate #5097's state machine.
- **Guest-buffered traces flushed at exit.** A crash loses the tail, which is
  the part an investigation needs.
- **Application spans as evidence.** A compromised guest controls its spans.
- **Encrypting the guest-to-host hop by default.** It adds cost and protects
  against no party that cannot already read guest memory.
- **Several consumers on one mailbox.** Every worker would hold the mailbox's
  decryption key, and per-scope ordering would break.
- **A Rust actor framework.** See section 10.

## Owner decisions (2026-11-14)

1. One durable execution epoch per workload, shared by the plan, the host
   interface and the mailbox. Today's node-wide host-interface epoch becomes
   per workload. Locally the host issues it; in managed mode `mvmd` does, and an
   offline lease delegates a range. The policy epoch, node boot ID, telemetry
   producer epoch and placement generation stay separate.
2. Under `--prod`, three consecutive audit-write failures stop the workload. In
   development the workload keeps running and its epoch is sealed as host
   record incomplete. The threshold is revisited once measured.
3. #5292 D1: one mailbox daemon per tenant may hold that tenant's derived keys.
   It never serves two tenants; keys are derived on demand and zeroized.
4. A per-workload mailbox storage key survives a wake; the per-epoch authority
   keys rotate. A compromise replace destroys both.
5. The guest agent may accept OTLP on a Unix socket inside the guest. This needs
   an explicit carve-out in `check-single-network-path` and the PRD's
   no-listening-socket rule before it ships.
6. Large resource grants come from a separate burst share of 25% of the host
   budget, revisited after the #5510 baseline.
7. A retired workload ID is never reissued in managed mode.
8. The production requirement is #5097: every actor operation runs through its
   fail-closed preflight, local production comes before managed production, and
   finishing and measuring preflight on the launch path gates the rest.

Still open: the per-VM density budget values, set from the #5510 baseline, and
whether cross-tenant base-page sharing is ever allowed.

## Evidence before acceptance

Each item needs a test or CI lane named in the implementing issue:

- A crash mid-stream produces a sealed epoch labelled with its dropped-span
  count, and every host-witnessed event before the crash is present.
- A denied egress is never returned to the guest without its audit record,
  including under induced journal failure, which refuses instead.
- A wake under revoked policy is refused and the queued message receives a
  terminal receipt.
- Restoring the same snapshot twice leaves exactly one epoch that brokers
  accept.
- A guest-set identity attribute in OTLP is overwritten by the host.
- A message's causal link verifies across two actors from their sealed roots.
- The resolver never handles plaintext and cannot widen a caller's capability.
- A replacement epoch's default `explain` view shows no predecessor records.
- The density budget holds at the #5510 baseline counts with tracing enabled.

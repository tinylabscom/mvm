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
**Continuation design:** [#5126](https://github.com/tinylabscom/mvm/issues/5126)
and proposed [ADR-060](060-mailbox-rebuild-handoff.md). Neither accepts a
mailbox protocol amendment or qualifies cross-epoch Call completion.

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

## Function-model overview

The interface is function-like; the logical lifetime is actor-like. A workload
receives immutable signed inputs, performs capability-bounded work, and emits
an explicit result or reply. These are not mathematically pure functions:
identical inputs need not produce identical output or effects. ADR-051 names
one VM incarnation with its mailbox, lifecycle handle, authority and evidence;
this proposal extends logical identity across incarnations, not across
multiple workloads inside one guest.

Read the model through [identity](#1-identity-workload-epoch-recipe),
[state classes](#2-state-classes), [residency](#3-residency-is-a-condition-not-a-lifecycle-state),
[continuation](#41-explicit-continuation-across-incarnations),
[evidence](#5-evidence-and-tracing) and [custody](#6-storage-and-encryption).
ADR-057 remains the mailbox authority, not ADR-046's superseded messaging
contract. No new actor framework, public invocation schema or SDK API is
defined here.

Every incarnation uses the existing signed-plan admission and isolation path.
Required checks precede applicable readiness, disclosure and effects; child
authority only attenuates under every parent and policy ceiling. No guest NIC,
SSH or generic privileged machine-exec/control path bypasses the admitted
application interface. A sandboxed code-runner may process declared code/script
inputs under its capabilities; callers gain no arbitrary platform-control
authority. External API credentials stay in ADR-023's host-service boundary;
narrowly scoped internal decryption keys are different and do not themselves
authorize effects.

MVM owns local execution, mailbox and context contracts without MVMD, an
external account or external key service. Optional MVMD adds fleet routing
and orchestration, not plaintext access or a second local authority. Packaged
MVM background components are not external-service dependencies; their presence
does not qualify an unattended OS-manager deployment profile.

## Decision

### 1. Identity: workload, epoch, recipe

Three identifiers, each with one job:

| Identifier | Meaning | Stable across |
| --- | --- | --- |
| Workload ID | The logical actor; the name a mailbox address resolves to. | Restart, rebuild, park, wake, move |
| Execution epoch | One VM lifetime of that workload (`ExecutionEpoch`). | Nothing: every boot, restore or wake is a new epoch |
| Recipe hash | Digest over the measured inputs of the signed plan: image, kernel, verity roots, asset identities (claim 19) and policy. | Identical inputs only |

The definition/recipe is not the logical workload or a particular invocation.
A message is one immutable value; a Call requests an application Reply, while
a conversation relates messages and explicit task progress. One incarnation
may handle many Calls, and a task may span incarnations. These are conceptual
distinctions, not a new `InvocationId` or wire schema. The policy epoch tracks
authorization policy separately from the execution epoch and boot identity.

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

The mailbox surface remains ADR-057's: one public capability-bound mailbox
identity per actor, with a bounded inbox and pending-send outbox internally.
The outbox is not a second address, service or per-actor process. Hosts and
workloads can independently initiate authorized `call` and `cast` operations
and issue scoped `reply` messages. Delivery acceptance is not an application
reply; Receive or Reply authority never implies general reverse Send authority.
Outbox durability follows the requested admission class.

Sender queuing, destination acceptance, delivery ACK, application Reply/result
and VM exit are separate observations. Stdout/stderr remain diagnostics.
A Cast requests no application Reply, not silent loss. Delivery is at least
once within finite expiry/retry bounds; application effects need their own
idempotency. Call waiting deadlines are separate from message expiry: timeout
does not prove non-execution, cancellation is not rollback, and a late Reply
cannot complete a different Call. Unreconciled effects remain `Unknown`.
ADR-057 owns acceptance classes, scoped ordering, deduplication and bounded
queues/credits; mailbox saturation cannot borrow another service's capacity.

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
| Parked | No guest RAM or vCPU; retained recipe/state and bounded host bookkeeping | Blocked in receive with no pending timer, past a grace period |

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
path. Cold <300 ms, warm/wake <50 ms (admission included) and 1,000-workload
density are unverified acceptance targets, not current performance claims.
Snapshot and warm mechanisms require their own backend and fencing evidence.

### 4. Supervision: let it crash, rebuild from the recipe

- A crash is a `terminal_exit` observation (ADR-057 §9) for its epoch.
- The **host** applies the restart policy from the signed plan: strategy
  (one-for-one, one-for-all, rest-for-one), maximum restarts within a period,
  backoff, and an escalation mailbox. Guest code does not enforce supervision.
- A restart rebuilds from the recipe at the next epoch. It never resumes the
  crashed guest's memory.
- Exceeding the restart limit moves the workload to `Quarantined`.
- Restarts, give-ups and escalations are host-witnessed events (section 5).

### 4.1 Explicit continuation across incarnations

The workload deliberately persists bounded task progress and pending
conversation bindings, then explicitly reloads them under a new admission.
This is application continuation, not suspended-call-stack restoration,
deterministic journal replay or automatic repetition of uncertain effects.
Retained context supplies data, never the predecessor's grants.

#### Pending Calls and committed outcomes

[#5126's opt-in decision](https://github.com/tinylabscom/mvm/issues/5126#issuecomment-6669316870)
and its [rebuild confirmation](https://github.com/tinylabscom/mvm/issues/5126#issuecomment-6780490193)
record a product preference: transfer requires explicit opt-in in both the
conversation and signed workload plan. Durability alone is insufficient.
The signed representation and current-authority transfer mechanism remain
unqualified; ADR-057's epoch fencing remains authoritative.

A still-pending Call is not an already committed Reply/outcome. Authorized
recovery of a committed outcome reads history; it does not complete a new
Call or revive a superseded wait. The proposed V3 strict caller-epoch
completion rule does not automatically transfer a pending Call to a replacement,
even when its task context survives.

Eligible transfer would preserve immutable accepted envelopes and provenance,
prove durable old-owner fencing, and require fresh admission, scoped
Receive/Reply authority and key possession for the specific replacement.
A separate authenticated delivery decision must bind the current consumer
without retargeting the old envelope or making an old grant current.
Invocation-pinned, expired, revoked or unprovable items remain pinned or receive
a truthful terminal/uncertain disposition. A retained key revives no capability;
revocation cannot retract plaintext or keys a previous endpoint already saw.

#### Crash consistency and send intent

An atomic local commit of encrypted continuation plus durable send intent is
a **design target to prove**, not a shipped transaction or cross-owner
atomicity. It must preserve independent authorization, queue/credit admission
and finite storage budgets. Remote acceptance, replies and external effects
are outside that commit. If one safe transaction cannot own the necessary
state, compare a bounded recoverable-intent protocol with explicit outcomes.

Producers retain sealed bytes for retry under a stable immutable
message/content/context binding in the selected canonical version.
Authenticated duplicate recognition follows that version's reviewed rule,
not an invented cross-version raw JSON or signature-byte equality rule.
Lost commit responses require reconciliation, not a new identity.

As proposed in [ADR-060](060-mailbox-rebuild-handoff.md#proposed-boundary), a
never-dispatched intent may be freshly sealed by its authorized sender for an
admitted replacement. Eligibility requires evidence of no prior disclosure at
the actual source handoff boundary: a missing receipt or locally absent
dispatch marker does not prove no disclosure occurred. Partial or lost handoff
is possibly dispatched/`Unknown`, not permission to reseal or retry with a new
message ID.

Still open under #5126: transfer representation and eligibility, cancellation
scope and timeout/expiry races, context revisions/retention and key recovery,
and crash-safe ordering of Reply consumption, continuation update and ACK.
Existing ADR-057 retention and retry rules are not replaced by new defaults.

#### Example: ask a person, replace the VM, continue

This is the intended **qualified workflow**, not current functionality or SDK
syntax. It depends on the transfer and crash-consistency proofs above.

1. An admitted restart-safe workload has narrowly scoped Read and Write
   authority for its private continuation space, plus authority to ask a person
   a question and receive the exact Reply. Read does not confer Write, and a
   stateless declaration gains no persistence. Its plan and conversation
   opt into replacement continuation with finite expiry and waiting bounds.
2. It records "waiting for this answer" and the encrypted question's send
   intent under the proposed local commit. Destination acceptance and a
   person's application Reply are separate later events.
3. The VM goes away while waiting. A planned park retains admitted state; a
   crash causes recipe-based reconstruction, never reuse of crashed memory.
4. The person's authorized endpoint sends the encrypted Reply within its
   allowed window. Pending mailbox state can outlive the VM in the local
   durability domain; a keyless scheduler does not decrypt the answer.
5. A newly admitted incarnation, under a fresh epoch, may receive that Reply
   and explicitly continue only after the pending-conversation transfer proof,
   old-owner fencing, current authorization and scoped key release succeed.
   If the outcome was already committed, authorized history recovery instead
   retrieves it without reviving the old wait.
6. The workload durably records progress and ACKs under the reviewed ordering.
   Crash/lost-ACK duplicates require deduplication and application idempotency;
   external effects are not generally exactly once. Expiry, revocation, lost
   keys or unprovable ownership refuse or report uncertainty, never success.
   A late Reply cannot resurrect a timed-out Call.

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

**Privacy and version boundary.** Initial V3 profile A is designed to encrypt
application payloads while exposing explicitly declared routing/authorization
metadata. All causal/trace-header descriptions in this ADR are proposals whose
placement and protection require their own versioned review. Profile A does not
permit indiscriminate disclosure of additional tracing fields. This ADR does not
amend ADR-057's wire contract or qualify the private-metadata profile B.

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
derived from the tenant key, with a per-epoch subkey. Deleting a derived key
alone does not erase anything that a retained ancestor key can recover.
Cryptographic erasure requires destroying all recoverable key material,
including derivation and backup paths and retained copies. Rotation is not
erasure; neither can undo prior plaintext exposure or prove physical erasure.
A missing history key refuses recovery rather than minting a replacement or
reporting empty history. Selective workload/epoch erasure cannot be claimed
until the key hierarchy and retention mechanism satisfy these conditions.

**Mailbox custody.** ADR-057 §11 and #5292 govern mailbox keys: the shared
scheduler routes and stores sealed messages and holds no mailbox keys.
Signing and MAC secrets are also excluded from the shared scheduler.
Mailbox seal/open and authorization remain with VM-scoped holders; an
authorized host endpoint needs its own explicitly scoped custody, not ambient
access to other actors. Shared trace or snapshot infrastructure acquires no
mailbox-key authority from handling related records.

**Private context.** #5126 starts with a minimal encrypted task/workload space,
not a boot-scoped memory image or an agent-only API. It carries attributable
untrusted data, not authority, following proposed [ADR-047](047-agent-memory-plane.md#3-memory-carries-facts-it-never-carries-authority).
Future sharing needs explicit content capabilities and administrative RBAC;
fleet membership grants no ambient access, and read/write rights do not grant
policy administration. A plaintext-blind store cannot provide plaintext
server search or semantic scans. Context revision, provenance and retention
must be reconciled with ADR-047 rather than silently replacing its rules.
Mailboxes remain usable without a shared context pool.

**Local durability.** Continuation survives guest replacement only with its
backing storage, verifiable history, usable keys and current authorization
intact. It does not survive permanent host/disk/key loss by default or prove
whole-host rollback protection. Optional replication is a separate tier;
neither P2P transport nor OS service restart provides it.

**Who can read.** By default the host can read stored traces (trusted-host
tier), so local search, `explain` and export work. A host-blind tier, in which
the guest encrypts to the tenant's key and the host stores ciphertext only, is
selectable by policy where confidential-computing hardware exists, under the
tiers of ADR-057 §11. In both tiers the Merkle tree commits to the stored
records as stored, so completeness can be checked without decrypting.

**In flight.**

| Hop | Protection | Reason |
| --- | --- | --- |
| Mailbox endpoint to endpoint, including same-host vsock | End-to-end authenticated encryption per ADR-057 before entering scheduling, relay, retry or storage infrastructure | A shared service compromise must not disclose payloads or endpoint keys |
| Guest telemetry to its authorized host collector, trusted-host tier | Authenticated, bounded framing; the stream is bound to the VM through the socket the VMM was handed, never through a guest claim | The collector is an authorized telemetry recipient; this is not a plaintext exception for mailbox traffic |
| Cross-host transport, export | Encrypted transport | Leaves the host |

Inbox, outbox and dead-letter stores retain sealed payloads, including in
standalone local operation. Plaintext processing stays inside the declared
endpoint/custody boundary. Routing, size and timing metadata remain visible;
encryption does not conceal traffic patterns. An authorized host application
may read messages addressed to it, but a routing service is not therefore an
authorized endpoint.

The host-blind tier additionally requires confidential-computing memory
protection, attestation-bound key release and rollback witnesses under
ADR-057 §11, or refusal. Encrypting mailbox traffic does not hide guest
plaintext from a compromised ordinary hypervisor host.

**Residual.** Plaintext can exist in authorized endpoint/holder memory and in
host collector memory for trusted-host telemetry. Swap or crash dumps can
retain it unless the selected profile prevents that; state those limits.
This does not authorize plaintext mailbox buffers in shared intermediaries.

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

- One trace collector per host, not per VM.
- One keyless mailbox scheduler is shared across tenants within a single
  unprivileged OS user and canonical MVM runtime instance, not per VM
  ([scope decision](https://github.com/tinylabscom/mvm/issues/5544#issuecomment-6929453494)).
  Separate OS users and runtime homes are not implicitly merged. Deployment
  profiles and authority/fencing qualification remain separate; shared
  scheduling does not combine mailbox-key custody.
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
- Mailbox scheduling and custody follow ADR-057 §11 and #5292. Shared tracing
  and snapshot infrastructure must not widen that custody boundary.
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
- **Treating a local hop as mailbox confidentiality.** A shared service can be
  compromised without control of the hypervisor. Local vsock traffic therefore
  keeps mailbox payloads encrypted; the trusted-host telemetry exception does
  not apply to it.
- **Several consumers on one mailbox.** Every worker would hold the mailbox's
  decryption key, and per-scope ordering would break.
- **A Rust actor framework.** See section 10.

## Owner decisions

The initial decisions were recorded on 2026-11-14. Mailbox custody follows
the subsequent ADR-057 §11 amendment and #5292; the inbox/outbox API model
was clarified on 2026-11-16.

1. One durable execution epoch per workload, shared by the plan, the host
   interface and the mailbox. Today's node-wide host-interface epoch becomes
   per workload. Locally the host issues it; in managed mode `mvmd` does, and an
   offline lease delegates a range. The policy epoch, node boot ID, telemetry
   producer epoch and placement generation stay separate.
2. Under `--prod`, three consecutive audit-write failures stop the workload. In
   development the workload keeps running and its epoch is sealed as host
   record incomplete. The threshold is revisited once measured.
3. #5292 D1 follows ADR-057 §11: a keyless shared scheduler handles sealed
   messages; mailbox seal/open and authorization remain VM-scoped. This
   supersedes the earlier per-tenant key-holding-daemon wording. Authorized
   host endpoints require independently scoped custody as described in §6.
4. A per-workload mailbox storage key survives a wake; the per-epoch authority
   keys rotate. A compromise replace destroys both; any erasure claim must
   also satisfy the recoverable-key-material conditions in §6.
5. The guest agent may accept OTLP on a Unix socket inside the guest. This needs
   an explicit carve-out in `check-single-network-path` and the PRD's
   no-listening-socket rule before it ships.
6. Large resource grants come from a separate burst share of 25% of the host
   budget, revisited after the #5510 baseline.
7. A retired workload ID is never reissued in managed mode.
8. The production requirement is #5097: every actor operation runs through its
   fail-closed preflight, local production comes before managed production, and
   finishing and measuring preflight on the launch path gates the rest.
9. One public mailbox identity per actor, with bounded inbox/outbox state
   internally, supports independent bidirectional `call`, `cast` and `reply`.
   A Cast-only implementation or delivery ACK is not full Call/Reply support.

Still open: the per-VM density budget values, set from the #5510 baseline, and
whether cross-tenant base-page sharing is ever allowed.

## Evidence before acceptance

Each item needs a test or CI lane named in the implementing issue:

- A crash mid-stream produces a sealed epoch labelled with its dropped-span
  count, and every host-witnessed event before the crash is present.
- A denied egress is never returned to the guest without its audit record,
  including under induced journal failure, which refuses instead.
- Host and workload endpoints each initiate authorized messages in both
  directions. Application replies bind the exact original call and authorized
  responder; delivery ACKs, duplicate replies and late replies cannot complete
  another call.
- Shared scheduling, retry, journal and dead-letter paths expose neither
  plaintext payloads nor endpoint keys, including for same-host traffic.
- A wake preserves immutable sender provenance and historical acceptance while
  requiring fresh destination admission and Receive authority. Retaining a
  storage key cannot revive an expired or revoked capability or retarget the
  original envelope.
- Pending-Call transfer is qualified separately from committed-outcome
  recovery; neither retained context nor a late Reply revives a superseded wait.
- Crash injection at continuation commit, source handoff, receipt, Reply and
  ACK boundaries preserves authorization and budgets. Possibly disclosed work
  is never misclassified as never dispatched or automatically resealed.
- A wake under revoked policy is refused and the queued message receives a
  terminal receipt.
- Restoring the same snapshot twice leaves exactly one epoch that brokers
  accept.
- A guest-set identity attribute in OTLP is overwritten by the host.
- A message's causal link verifies across two actors from their sealed roots.
- The resolver never handles plaintext and cannot widen a caller's capability.
- A replacement epoch's default `explain` view shows no predecessor records.
- The density budget holds at the #5510 baseline counts with tracing enabled.

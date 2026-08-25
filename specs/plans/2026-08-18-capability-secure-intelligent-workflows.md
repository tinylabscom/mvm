# Capability-secure intelligent microVM workflows

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

**Status:** PROPOSED — no implementation has begun.  
**Issue:** not yet assigned.  
**Governing ADR:**
`specs/adrs/045-capability-secure-intelligent-workflow-controllers.md`.  
**Research:**
`specs/research/intelligent-capability-secure-microvm-workflows.md`.

## Goal

Extend `mvm`'s one-workload-per-microVM runtime with an opt-in workflow layer in
which an admitted controller microVM can:

- use a deterministic or AI planner;
- reason over a finite signed ontological action catalog;
- launch exact admitted worker templates;
- communicate through structured mailbox, stream, and artifact bindings;
- manage clean capacity across cold, parked, resident-warm, claimed, and
  running states;
- operate locally on one `mvm` host or under `mvmd`-rooted fleet authority;
- remain unable to widen its own capabilities, resource envelope, delegation,
  data reach, or host/hypervisor authority.

Direct single-microVM execution remains a separate first-class path and incurs
no workflow runtime, storage, semantic, mailbox, or AT Protocol dependency.

## Why this plan exists

The repository already has reviewed pieces of the mechanism:

- signed and audited `ExecutionPlan` admission;
- exact host-service bindings and parser/key-holder separation;
- workload streams, input grants, stream edges, and DAG validation;
- workload grants and independent ceilings;
- warm compatibility keys, resident/saved capacity, claim leases, and explicit
  cold/optional/required launch modes;
- local node verification seams intended for `mvmd`-issued grants.

What does not exist is a single authorization and lifecycle model connecting
those pieces safely for an AI-controlled workflow. Adding only a `launch_child`
verb would be unsafe: a controller could exhaust live VMs, warm parents,
snapshots, memory, CPU, disk, descriptors, sockets, mailbox storage, audit
capacity, or external-provider cost.

This plan therefore builds the resource partition, process boundaries,
transaction model, and negative witnesses before it adds broad planner
functionality.

## Global constraints

These are release blockers, not preferences.

1. **One guest remains one workload.** No multi-workload controller guest and
   no nested virtualization.
2. **Direct execution remains separate.** A direct plan creates no workflow
   state, process, mailbox, graph, reservation, semantic, or AT dependency.
3. **Every child is an ordinary admitted workload.** Child launch reuses the
   same plan synthesis, signature, admission, backend, stream, secret, network,
   and audit path as a direct workload.
4. **The controller never supplies host configuration.** It selects exact
   plan-local template/action bindings only.
5. **Authority only attenuates.** Child capabilities, egress, secrets,
   filesystem, tools, resources, and delegation are subsets of every
   applicable root, parent, workflow, tenant, template, and host ceiling.
6. **Budget reservation is transactional.** No check-then-start race and no
   partial reservation.
7. **Host safety is independent.** A valid workflow cannot consume the host's
   final safety reserve.
8. **Attempts are bounded.** Live count alone is insufficient; total attempts,
   launch rate, concurrent launches, warm capacity, snapshots, storage,
   descriptors, channels, network, and cost are explicitly bounded.
9. **Used children are destroyed.** They never return to a shared warm pool.
10. **Semantic state is advisory until compiled.** AI output, AppViews,
    ontology edges, labels, embeddings, CIDs, and AT records cannot directly
    authorize a launch.
11. **Natural language is not the control protocol.** Privileged operations use
    typed exact bindings.
12. **Guest-facing parsers hold no signer or backend authority.** Admission and
    lifecycle execution are separate roles.
13. **Mutating commands are idempotent and fenced.** Stale controller
    generations cannot act.
14. **Mailboxes are private and bounded.** Raw prompts, messages, output,
    secrets, and tenant topology are not published through AT Protocol.
15. **No new network stack.** Workflow communication uses the existing
    host-mediated seams.
16. **No unverified downgrade.** Production workflows refuse resource limits
    that the selected backend cannot actually enforce.
17. **No critical-path semantic dependency.** PDS, relay, AppView, DID, OAuth,
    model inference, and external repository operations are excluded from boot
    and child-start critical paths.
18. **Performance is gated.** Direct launch must not regress. The authoritative
    200 ms versus current sub-300 ms warm-launch SLO must be resolved in WS0.
19. **Plans and claims stay honest.** Controls with no production caller remain
    declared dormant or preview; they do not become numbered claims early.
20. **Tests precede completion.** Checkboxes are marked only after the listed
    tests and repository gates pass.

## Out of scope for the first implementation

- Recursive child-controller delegation.
- Threshold controller consensus.
- General cross-node guest L3 networking.
- Raw/unredacted stream edges.
- Arbitrary AI-generated source launched directly as a workload.
- Full AT repository/PDS/relay implementation.
- Public raw workflow transcripts or mailbox payloads.
- Confidential-computing protection against a malicious host.
- Exactly-once distributed execution.

## First vertical slice

The first end-to-end proof is deliberately small:

```text
single local host
one controller generation
one sealed controller
maximum depth = 1
maximum controllers = 1
maximum live workers = 2
maximum resident VMM slots = 3
maximum total attempts = 4
maximum concurrent launches = 1
launch rate = 2/minute
maximum resident-warm parents = 1
maximum parked parents = 1
two exact worker templates
no worker delegation
no worker network
no worker secrets
no writable host shares
fixed memory and enforced CPU/wall-clock bounds
structured mailbox
redacted streams
content-addressed artifacts
```

Positive flow:

```text
controller
├── launches researcher-a
├── launches researcher-b
├── receives structured results
├── releases capacity as required
├── launches verifier from exact artifact refs
└── seals the workflow receipt
```

## Dependency graph

```text
WS0 decisions/claim freeze
  ├── WS1 contract and direct-path compatibility
  │     ├── WS2 formal authority/budget reference semantics
  │     └── WS3 transactional constraints and reservations
  │           ├── WS4 encrypted workflow session
  │           └── WS5 process-separated lifecycle service
  │                 └── WS6 local vertical slice
  │                       ├── WS7 mailbox/artifact integration
  │                       ├── WS8 warm/parked/cold reconciliation
  │                       └── WS9 graph epochs and supervision
  │                             └── WS10 AI planning snapshot and SDK
  │                                   └── WS11 recursive delegation/groups
  └── WS12 mvmd issuer, placement, and distributed routing
        └── WS13 AT-shaped semantic plane
              └── WS14 optional AT Protocol bridge

WS15 observability/docs and WS16 evidence/claim promotion span all workstreams.
```

## Likely landing points

```text
crates/mvm-contract/src/workflow/
crates/mvm-contract/src/mailbox/
crates/mvm-core/src/plan/
crates/mvm-hostd/src/workflow/
crates/mvm-hostd/src/mailbox/
crates/mvm-runtime/src/warm_service.rs
crates/mvm-runtime/src/vm/lease.rs
crates/mvm-client/src/workflow/
crates/mvm-sdk/src/workflow/
crates/mvm-cli/src/commands/workflow/
crates/mvm-conformance/
xtask/src/
specs/formal/workflow/
specs/adrs/
specs/research/
specs/plans/
specs/SPRINT.md
specs/REFACTOR-STATUS.md
```

Recommended `mvmd` landing points must be remapped after its actual source tree
is available.

---

## WS0 — Freeze decisions, SLO, and claim boundaries

**Purpose:** Prevent implementation from silently choosing unresolved trust,
performance, or storage semantics.

### Decisions

- [ ] Confirm ADR-045 status and merge it before guest-reachable lifecycle code.
- [ ] Amend ADR-001 with the controller, AI, workflow, mailbox, semantic,
      resource-amplification, and distributed threat model.
- [ ] Decide whether ADR-037 is amended or superseded by the rule that every
      production child launch is rooted in a narrow `mvmd` delegation.
- [ ] Write the encrypted guest-host workflow-session ADR or explicitly split it
      into a prerequisite plan.
- [ ] Locate and reconcile the current `mvm-mailbox` ADR/research/implementation.
- [ ] Inspect the actual `mvmd` repository and replace all speculative module
      names in this plan with verified seams.
- [ ] Pin the authoritative launch SLO and measurement boundaries:
      - direct cold start;
      - pre-admitted cold workflow child;
      - resident-warm claim;
      - parked restore;
      - planner time excluded from launch window.
- [ ] Decide the standalone workflow journal store and crash-consistency model.
- [ ] Decide whether host pressure may always evict clean warm capacity or
      whether explicit guaranteed reservations exist.
- [ ] Decide the initial classification lattice and whether declassification is
      in or out of the first release.
- [ ] Pin the initial protocol versions, maximum frame sizes, bounded collection
      lengths, and signature domain separators.

### Claim posture

- [ ] Add preview claim entries only after real code paths exist.
- [ ] Declare any pure functions with no production caller as dormant in the
      repository's dormant-control registry.
- [ ] Define planted defects for every proposed security gate before promotion.
- [ ] Record which claims remain qualified limits rather than aspirational
      absolute statements.

### Acceptance

- [ ] No open question remains about who signs, who verifies, who owns workflow
      truth, who owns reservation truth, who may increase ceilings, or when a
      reservation is released.
- [ ] Direct and workflow SLOs have one authoritative documented number.
- [ ] The `mvmd` boundary is grounded in the actual repository.

---

## WS1 — Contract types and direct-path compatibility

**Purpose:** Define portable, bounded, fail-closed types without introducing
runtime behavior.

### Files

- Create `crates/mvm-contract/src/workflow/mod.rs`.
- Create workflow modules for IDs, membership, templates, actions,
  constraints, budgets, delegation, lifecycle, graph, planning, and receipts.
- Create `crates/mvm-contract/src/mailbox/mod.rs` plus envelope, cursor, limits,
  and archive DTO modules.
- Modify the signed plan type with omitted-when-absent workflow fields only
  after frozen-vector impact is measured.
- Extend schema generation and cross-language parity fixtures.

### Types

- [ ] `WorkflowId`, `WorkflowNodeId`, `AttemptId`, `BootId`, `GraphRevision`,
      `ControllerGeneration`, `TemplateBinding`, `ActionBinding`, `BindingId`,
      `ReservationId`, `MessageId`, and `IdempotencyKey` validated newtypes.
- [ ] `WorkflowMembership` with workflow, logical node, attempt, parent,
      role, revision, and snapshot digests.
- [ ] `WorkflowRole::{Worker, Controller}`.
- [ ] `LifecycleAction` closed enum.
- [ ] `WorkflowLifecycleGrant`.
- [ ] `TemplateLaunchCeiling` and immutable `WorkloadTemplateRef`.
- [ ] `WorkflowBudget` and `RemainingBudgetSummary` using integer units.
- [ ] `WorkflowConstraintSnapshot` and signed envelope.
- [ ] `ActionTarget`, `ActionDescriptor`, `CapabilityDescriptor`, and
      `ActionAvailability`.
- [ ] `ControllerPlanningSnapshot` and signed envelope.
- [ ] `AiPlannerConfig`, `PlannerDecision`, and `PlannedAction` without any
      model-runtime dependency.
- [ ] `GraphPatch`, `ResolvedWorkflowEdge`, and typed edge classes.
- [ ] `LaunchChildRequest`, `LaunchReceipt`, `ActorHandle`, lifecycle receipts,
      and closed refusal enums.
- [ ] `CapacityTarget`, `IdlePolicy`, and capacity-state DTOs.
- [ ] `MailboxEnvelope`, acknowledgements, delivery attempts, archive manifest,
      and payload reference.
- [ ] `WorkflowReceipt` and lineage root references.

### Fail-closed serialization rules

- [ ] `#[serde(deny_unknown_fields)]` on every security-relevant object.
- [ ] Explicit versions and refusal of unknown major versions.
- [ ] Bounded strings, vectors, maps, nesting, and payload references.
- [ ] No floats in signed/budget payloads.
- [ ] Safe defaults only; absence cannot create authority.
- [ ] Workflow fields omitted when absent to preserve direct plan bytes where
      required.
- [ ] Domain-separated digest/signature inputs.

### Tests

- [ ] Serde round-trip for every wire type.
- [ ] Unknown-field and unknown-version refusal.
- [ ] Oversized collection/string refusal before large allocation.
- [ ] Direct plan bytes/frozen vectors unchanged when workflow fields are
      absent.
- [ ] `workflow=None, delegation=Some` refuses.
- [ ] Direct and worker plans cannot deserialize into controller authority by
      omission/default.
- [ ] Python/TypeScript/Rust schema parity for the public authoring subset.
- [ ] Fuzz targets for every guest-facing workflow/mailbox envelope.

### Acceptance

- [ ] `mvm-contract` default dependencies gain no AI, async runtime, AT, DB,
      VMM, or host-service dependency.
- [ ] `cargo run -p xtask -- check-core-runtime-free` remains green.
- [ ] Direct plan compatibility is explicitly witnessed.

---

## WS2 — Formal authority, graph, and budget reference semantics

**Purpose:** Make the most dangerous properties executable before host code
implements them.

### Files

- Create `specs/formal/workflow/workflow.als`.
- Create `specs/formal/workflow/Workflow.tla` and configuration files.
- Create a small Lean project/module set for authority, budget, and graph
  predicates, or place them in the repository's chosen formalization seam.
- Add generated conformance vectors under `crates/mvm-contract/tests/vectors/`.

### Alloy model

- [ ] Authority graph is a rooted forest.
- [ ] Each attempt has one authority parent/root.
- [ ] Delegation depth is bounded.
- [ ] Child capabilities/egress/secrets/filesystem/tools are subsets.
- [ ] Dataflow is acyclic.
- [ ] Every stdin has at most one writer.
- [ ] Cross-tenant and cross-workflow bindings are impossible.
- [ ] Used child state cannot become shared warm capacity.

### TLA+/Apalache model

- [ ] Reserve → intent → admit → start → ready → commit transaction.
- [ ] Crash at every transition.
- [ ] Idempotent retry.
- [ ] Concurrent final-slot reservation.
- [ ] Controller generation failover and stale mutations.
- [ ] Stop/cancel versus completion race.
- [ ] Node loss and orphan recovery.
- [ ] Mailbox accept/ack/retry/expiry.
- [ ] Desired capacity reconciliation under host pressure.

### Lean/reference predicates

- [ ] `effective_child_authority ⊆ effective_parent_authority`.
- [ ] Complete-ancestor attenuation.
- [ ] Budget reserve/release arithmetic cannot underflow or exceed ceilings.
- [ ] Graph patch preserves acyclicity and single-writer constraints.
- [ ] Classification join is monotonic.
- [ ] Unknown schema/ontology inputs cannot widen the result.

### Differential tests

- [ ] Generate valid and invalid constraint snapshots.
- [ ] Generate graph counterexamples.
- [ ] Generate budget boundary vectors.
- [ ] Run the Rust implementation against all vectors.
- [ ] Add mutation cases proving each vector family catches a planted defect.

### Acceptance

- [ ] Reference models expose no counterexample inside agreed bounds.
- [ ] Rust and reference semantics agree on the full vector corpus.
- [ ] Limitations of bounded model checking are documented without overclaim.

---

## WS3 — Constraint compiler, ceilings, and transactional reservations

**Purpose:** Make controller resource and capability amplification impossible
before a lifecycle verb becomes reachable.

### Files

- Add pure attenuation and projection code in `mvm-contract`/`mvm-core`.
- Create `mvm-hostd::workflow::constraints`.
- Create `mvm-hostd::workflow::reservation`.
- Extend local user config with host workflow safety ceilings.
- Add receipt/read-back types to existing resource-control reporting.

### Constraint compilation

- [ ] Compile pinned ontology/ruleset/fact/template inputs into one finite
      `WorkflowConstraintSnapshot`.
- [ ] Record exact input digests/strong refs, issuer IDs, schema digests,
      compiler version, validity, revocations, and effective policies.
- [ ] Refuse missing records, unknown schemas, revoked issuers, expired
      attestations, incomplete synchronization, and ontology/ruleset drift.
- [ ] Separate positive authorization assertions from advisory or
      quarantine-only labels.
- [ ] Ensure a general semantic edge cannot produce a lifecycle binding.
- [ ] Ensure only dedicated validated records can create delegation,
      launch, secret, peer-route, or declassification authority.

### Host and tenant ceilings

- [ ] `HostSafetyCeiling` with VM, resident-VMM, memory, CPU, disk, snapshot,
      artifact, FD, socket, channel, launch-rate, and checkpoint-rate limits.
- [ ] Host minimum free memory and disk reserves.
- [ ] Tenant ceiling interface for local mode and `mvmd` mode.
- [ ] Workflow and per-template ceilings.
- [ ] Maximum-based memory accounting, not current balloon commitment.
- [ ] Backend achieved-tier requirement for production CPU/wall-clock limits.

### Reservation ledger

- [ ] Atomic reserve of every replenishing and non-replenishing dimension.
- [ ] Durable reservation ID and transaction state.
- [ ] Live VMs, resident VMMs, attempts, concurrent launches, launch windows,
      CPU, memory, disk, artifact, mailbox, network, cost, FDs, sockets,
      channels, warm, parked, and private checkpoints.
- [ ] No partial reservation on failure.
- [ ] Reservation expiry/recovery that first checks for no live effect.
- [ ] Release only after confirmed VMM death and host-resource reap.
- [ ] Fair-share refusal that does not leak other tenant inventory.

### Denial containment

- [ ] Per-controller token bucket.
- [ ] Bounded pending request queue.
- [ ] Concurrent launch semaphore.
- [ ] Repeated-denial circuit breaker.
- [ ] Payload-free deduplicated denial audit summaries.
- [ ] Typed `retry_after` and remaining-own-quota hints.
- [ ] No automatic quota increase from `CapabilityNeed` or repeated retries.

### Tests

- [ ] Two requests racing for one final slot yield one winner.
- [ ] A failure in any dimension reserves nothing.
- [ ] `max_live=2` plus launch/terminate churn stops at `max_attempts=4`.
- [ ] Warm parents count against resident VMM and memory ceilings.
- [ ] Parked snapshots count against snapshot bytes and count.
- [ ] Artifact/mailbox/network/cost budgets are cumulative as configured.
- [ ] Host safety reserve overrides a valid workflow request.
- [ ] Stale inventory records cannot permanently lock the host.
- [ ] Live process evidence prevents a stale record from freeing an active
      reservation.
- [ ] A backend with only declared, not enforced, controls is refused in
      production workflow posture.
- [ ] 10,000 denied requests remain within parser/audit CPU and memory bounds.

### Acceptance

- [ ] No guest-reachable lifecycle dispatch exists before this workstream is
      green.
- [ ] Host exhaustion tests prove the workflow envelope cannot expand.

---

## WS4 — Boot-bound encrypted workflow sessions

**Purpose:** Protect lifecycle and mailbox authority against replay, stale boot
reuse, downgrade, and channel confusion.

### Prerequisite

- [ ] Governing crypto/session ADR accepted.

### Work

- [ ] Define handshake transcript and domain separation.
- [ ] Bind tenant, workflow, attempt, boot, plan digest, controller generation,
      channel purpose, and protocol version.
- [ ] Derive separate keys for lifecycle, mailbox, streams, and host services.
- [ ] Monotonic send/receive sequences and replay windows.
- [ ] Explicit key generation/rotation.
- [ ] Nonce-exhaustion behavior.
- [ ] Strict handshake deadline and frame caps.
- [ ] No plaintext or weaker signed-frame fallback.
- [ ] Session teardown zeroization.
- [ ] Guest agent holds session material; workload receives only SDK/service
      access, not reusable keys where avoidable.

### Tests

- [ ] Valid current boot/session succeeds.
- [ ] Plaintext frame refuses.
- [ ] Wrong channel-purpose key refuses.
- [ ] Old boot ID refuses after restore/restart.
- [ ] Old controller generation refuses.
- [ ] Replayed sequence refuses.
- [ ] Out-of-window sequence refuses.
- [ ] Unknown protocol/cipher refuses without downgrade.
- [ ] Truncated, oversized, and malformed handshake fuzz cases remain bounded.
- [ ] Key material is absent from logs, audit, crash text, and persisted
      workflow state.

### Acceptance

- [ ] Every workflow mutation reaches admission only through the encrypted,
      boot-bound session.

---

## WS5 — Process-separated workflow lifecycle service

**Purpose:** Expose real controller authority without placing hypervisor
capability in the guest-facing parser.

### Process model

```text
workflow ingress/parser
    → workflow admission/reservation
    → workflow launch executor
    → warm service / VmBackend
```

### Ingress/parser role

- [ ] Register `host.workflow.v1` only for plans with exact workflow bindings.
- [ ] Parse bounded typed frames.
- [ ] Derive caller identity from channel; ignore guest-authored identity.
- [ ] Hold no signer, reservation writer, `VmBackend`, or VMM handle.
- [ ] Emit normalized DTOs only.
- [ ] Uniform refusal for absent/not-owned/not-in-scope handles.

### Admission role

- [ ] Verify workflow, tenant, authority domain, attempt, boot, plan digest,
      controller generation, snapshot digest, validity, and revocation.
- [ ] Resolve exact action/template binding.
- [ ] Validate input/output schema and launch mode.
- [ ] Reserve all dimensions atomically.
- [ ] Write lifecycle intent before issuing a launch permit.
- [ ] Produce exact permit binding reservation, child plan digest, template,
      controller identity, generation, idempotency key, expiry, and nonce.

### Launch role

- [ ] Accept no guest socket and no arbitrary `VmStartConfig` payload.
- [ ] Load host-prepared launch configuration by reservation ID.
- [ ] Verify the launch permit locally.
- [ ] Reuse existing plan synthesis/sign/verify/replay/audit pipeline.
- [ ] Reuse existing warm claim or cold backend start.
- [ ] Establish fresh child identity and channels before readiness.
- [ ] Commit outcome or leave a recoverable transaction state.

### Lifecycle verbs in first slice

- [ ] `get_planning_snapshot`.
- [ ] `launch_child`.
- [ ] `observe_child`.
- [ ] `release_child`.
- [ ] `set_capacity_target`.
- [ ] `send_message`.
- [ ] `complete_workflow`.

### Tests

- [ ] Direct workload receives `NotBound`.
- [ ] Worker receives `NotBound` for lifecycle verbs.
- [ ] Controller with no `Launch` action refuses.
- [ ] Unauthorized template refuses before plan synthesis.
- [ ] Guest-supplied host path/config fields cannot be represented on wire.
- [ ] Parser process cannot read signer or backend state.
- [ ] Launch process has no guest listener.
- [ ] Tampered permit, wrong reservation, wrong plan digest, wrong generation,
      expiry, and replay refuse.
- [ ] Same idempotency key returns same transaction outcome.
- [ ] Crash after each transition is recoverable.

### Acceptance

- [ ] Compromising the parser does not provide a path to launch a VM without a
      valid reservation and permit.

---

## WS6 — Local single-host vertical slice

**Purpose:** Prove the product and security boundary before mailbox breadth,
recursive delegation, or fleet distribution.

### Local authority

- [ ] Implement `LocalWorkflowAuthority` with local signer/admission.
- [ ] Durable local workflow journal and graph head.
- [ ] Durable controller generation.
- [ ] Exact local template registry.
- [ ] Local transactional reservation ledger.
- [ ] Local opaque binding/ActorHandle resolution.
- [ ] All child launches remain development posture.
- [ ] Workflow components start lazily; direct runs start none of them.

### Controller and workers

- [ ] One sealed controller template.
- [ ] Two sealed worker templates.
- [ ] Controller has no shell, raw host share, unrestricted network, or raw
      secret delivery.
- [ ] Workers have no lifecycle binding.
- [ ] Fixed resource and wall-clock grants.
- [ ] Controller receives the finite planning snapshot.

### Positive path

- [ ] Controller launches two workers.
- [ ] Workers become authenticated ready.
- [ ] Controller observes their lifecycle state.
- [ ] Controller releases workers.
- [ ] Controller launches verifier after budget becomes available.
- [ ] Workflow reaches a terminal sealed state.

### Destructive matrix

- [ ] 10,000 concurrent launch requests never exceed two live workers.
- [ ] Repeated launch/terminate never exceeds four attempts.
- [ ] `resident_warm=65535` refuses before prewarm work.
- [ ] Unauthorized template and action refuse.
- [ ] Resource/policy/host-path alteration is unrepresentable or refused.
- [ ] Stale generation cannot launch, release, observe privileged detail, or
      change capacity.
- [ ] Cross-workflow handle refuses uniformly.
- [ ] Audit-intent write failure prevents launch.
- [ ] Host crash after start/before commit produces no unmanaged child.
- [ ] Used child never reenters pool.
- [ ] Direct `machine run` creates no workflow files, processes, sockets, or
      measurable launch regression.

### Acceptance

- [ ] The vertical slice is to demonstrate that a fully compromised controller can consume only
      the configured envelope.


## WS7 — Structured mailbox, artifacts, streams, and workflow receipts

**Purpose:** Give actors bidirectional, bounded, auditable communication without
turning raw stdout or direct guest addressing into a control plane.

### Mailbox contract

- [ ] Consume `mvm_contract::fabric` for every messaging type. This plan defines
      none of its own. ADR-051 settles the vocabulary: `MailboxAddress`,
      `MessageId`, envelopes, correlation, causation, delivery attempts,
      acknowledgement, and cursors have exactly one definition, in the message
      fabric, and it is the fabric's.
- [ ] Depend on the fabric's local mailbox milestone; this workstream cannot
      start before it lands.
- [ ] `ActorHandle` remains defined here, as the lifecycle capability
      authorizing `observe_child`/`release_child`. It resolves to a
      `MailboxAddress` and carries no second addressing scheme — no VM name,
      node address, CID, socket path, or file descriptor.
- [ ] Sender identity is absent from the authoritative guest-authored payload;
      the host stamps tenant, workflow, attempt, boot, plan digest, and
      controller generation from the authenticated channel.
- [ ] Recipient is a plan-local binding, never a VM name, node address, CID,
      socket path, or host route.
- [ ] Every envelope binds the workflow revision, schema digest, payload digest,
      expiry, idempotency key, and causal metadata.
- [ ] Payload bytes are inline only below a small fixed threshold; larger
      payloads use immutable content-addressed artifact references.
- [ ] No raw host database API, SQL, filesystem path, or query language crosses
      the guest boundary.

### Delivery semantics

- [ ] Specify at-least-once delivery, never exactly-once execution.
- [ ] Preserve order per resolved sender/recipient route; make no global-order
      claim.
- [ ] Deduplicate by `(workflow, recipient, idempotency_key)`.
- [ ] Acknowledgements advance a durable cursor transactionally.
- [ ] Offline recipients retain bounded encrypted queues until TTL or quota.
- [ ] Queue full returns a typed refusal; it never silently evicts an
      unacknowledged control message.
- [ ] Dead-letter behavior is optional, explicitly admitted, classified, and
      bounded.
- [ ] Delivery attempts, acknowledgements, expiry, and dead-letter transitions
      are payload-free workflow lifecycle events.
- [ ] Cancellation and ownership transfer remain authoritative transactional
      commands, not mailbox facts.

### Storage and archive

- [ ] Active mailbox state is encrypted at rest and scoped by tenant/workflow.
- [ ] Message payload and active coordination storage are separate from the
      chain-signed control audit.
- [ ] The guest cannot read, modify, lock, or compact the host store directly.
- [ ] Enforce per-message, per-mailbox, per-workflow, per-tenant, and host-wide
      byte/count quotas before allocation or persistence.
- [ ] When a workflow terminates:
      1. stop accepting new messages;
      2. settle or expire in-flight deliveries;
      3. create an immutable mailbox manifest;
      4. hash and seal archive chunks;
      5. bind the archive root into the workflow receipt/audit chain;
      6. verify the archive;
      7. delete active coordination rows/files.
- [ ] A failed archive verification prevents active-state deletion and is
      surfaced as a terminal workflow cleanup fault.

### Stream integration

- [ ] Reuse the existing workload stream plane for stdout/stderr and operator
      reads.
- [ ] Raw stdout/stderr is never interpreted as an authoritative lifecycle
      request.
- [ ] Reuse plan-local `StreamEdge` bindings and topology validation.
- [ ] Keep one writer per stdin; fan-in requires an explicit merge workload.
- [ ] Refuse all raw edges in the first vertical slice even if lower-level types
      contain a raw posture.
- [ ] A stream edge and operator stdin remain mutually exclusive for one input
      slot.
- [ ] Preserve sequence, gap, redaction, hash-chain, and transcript-root
      semantics from the existing stream plane.

### Artifact integration

- [ ] Add a workflow artifact reference carrying:
      - content digest;
      - manifest digest;
      - producer attempt and boot;
      - producer plan digest;
      - schema/media type;
      - classification;
      - size;
      - retention policy;
      - optional attestation refs.
- [ ] Verify bytes against the digest on every trust-boundary read.
- [ ] A child consumes only artifact bindings admitted in its exact plan.
- [ ] Artifacts never confer authority merely because a controller can name a
      digest.
- [ ] Conservative information classification joins all consumed inputs; a
      guest may raise classification but cannot lower a host-assigned label.
- [ ] Declassification requires a separate exact capability, evidence, and
      audit outcome; it is out of the first slice.

### Workflow receipt

- [ ] Seal one final receipt binding:
      - workflow specification digest;
      - all graph revision digests;
      - all controller generations;
      - every child plan digest;
      - every attempt and boot identity;
      - mailbox archive root;
      - stream transcript roots;
      - artifact manifest roots;
      - constraint/planning snapshot digests;
      - approvals and policy outcomes;
      - audit-chain references;
      - terminal state and cleanup result.
- [ ] The receipt is to attest admitted/executed provenance, not semantic correctness
      of an AI result.

### Tests

- [ ] Unknown fields, oversized frames, oversized counts, deep nesting, invalid
      IDs, and expired envelopes refuse before large allocation.
- [ ] Guest-authored sender identity is ignored or unrepresentable.
- [ ] A copied lifecycle/mailbox binding does not work from another boot.
- [ ] Duplicate delivery is visible but application effect is idempotent.
- [ ] Cursor recovery after process restart resumes without acknowledging an
      undelivered message.
- [ ] Queue quota, tenant quota, workflow quota, TTL, and dead-letter quota all
      fail in the documented direction.
- [ ] A controller cannot turn stdout text into `launch_child`.
- [ ] A consumer cannot address or enumerate another VM directly.
- [ ] Mailbox archive verification and active-state cleanup are crash-tested at
      every boundary.
- [ ] Raw private message payloads never appear in lifecycle audit, semantic
      projection, public export, or logs.

### Acceptance

- [ ] Parent/child bidirectional communication works with no direct guest route,
      shared mutable host filesystem, reverse stdin edge, or authority-bearing
      message field.

---

## WS8 — Warm, parked, cold, and private-checkpoint reconciliation

**Purpose:** Let controllers manage latency and scale-to-zero while ensuring
clean capacity never carries workload authority and used state never becomes
shared capacity.

### Canonical lifecycle vocabulary

- [ ] Define and document these distinct states:
      - `ColdTemplate`: immutable boot artifacts only;
      - `ParkedParent`: clean saved-state parent, no VMM process;
      - `ResidentWarmParent`: clean paused/preloaded VMM, no workload authority;
      - `ClaimingChild`: reserved capacity being bound to a fresh child plan;
      - `RunningChild`: active admitted workload;
      - `PrivateActorCheckpoint`: stateful checkpoint scoped to one logical
        actor/workflow, never shared.
- [ ] Distinguish capacity state from workload-attempt lifecycle state.
- [ ] Do not overload existing `VmStatus` with semantic states that belong to
      the workflow/capacity layer.

### Desired capacity

- [ ] Add exact-template `CapacityTarget`:
      - resident-warm count;
      - parked count;
      - idle TTL;
      - parked TTL;
      - pressure posture;
      - idempotency key.
- [ ] Controllers can set desired capacity only when their lifecycle grant
      contains `SetCapacityTarget` for that template.
- [ ] Effective target is the minimum of controller request, template ceiling,
      workflow ceiling, tenant ceiling, and host pressure policy.
- [ ] The host may reduce non-guaranteed warm capacity under memory, process,
      descriptor, socket, disk, or audit pressure.
- [ ] Repeated controller requests cannot override a pressure-driven target or
      consume an unbounded reconciliation queue.
- [ ] The host reconciler continues after the controller pauses, exits, or is
      fenced; desired state is authoritative host state, not guest memory.

### Accounting

- [ ] Running and claiming children charge live workload slots, resident VMM
      slots, admitted maximum memory, CPU, descriptors, sockets, channels, and
      applicable storage/network/cost dimensions.
- [ ] Resident warm parents charge resident VMM slots, maximum memory, process,
      descriptors, sockets/channels, and pool-specific storage.
- [ ] Parked parents charge parked count and exact snapshot/artifact bytes.
- [ ] Private actor checkpoints charge private checkpoint count and bytes.
- [ ] Cold templates charge artifact-store bytes only.
- [ ] Account memory against the admitted maximum, not balloon commitment.
- [ ] Capacity reservations are not released until the VMM is confirmed dead
      and host-owned live resources are reaped.

### Clean-parent invariant

- [ ] Factory parents contain no tenant plan, secret, workload volume, port,
      destination allowlist, raw lifecycle capability, or mutable workload
      state.
- [ ] Claim binds a fresh child plan, boot identity, channels, credentials, and
      audit lineage before readiness.
- [ ] Release of a used child always stops/destroys the child.
- [ ] Replenishment creates/restores a fresh clean parent only if desired clean
      capacity remains below target.
- [ ] No code path changes a running/used child into `ResidentWarmParent` or
      `ParkedParent` shared capacity.
- [ ] Add an architecture/xtask gate that prevents such a transition from
      appearing outside explicitly scoped private checkpoints.

### Private stateful actors

- [ ] A private actor checkpoint binds workflow, logical actor, previous
      attempt, previous boot, plan digest, classification, and lineage.
- [ ] It cannot satisfy a generic template pool claim.
- [ ] Restore creates a new attempt/boot identity and fresh channel keys.
- [ ] Time-bound credentials, controller generation, and capability grants are
      reissued and reverified.
- [ ] Restore remains within the actor's original/root ceilings; no authority is
      inherited from VM name alone.
- [ ] Cancellation/revocation can make the private checkpoint permanently
      unresumable without deleting forensic metadata.

### Reconciler behavior

- [ ] Event-driven state observation where a stable process/lease handle exists;
      timer-driven TTL/backoff; reconciliation only for distributed/crash
      recovery.
- [ ] Atomic pool reservation prevents double-claim.
- [ ] Quarantine an unhealthy or partially claimed parent; do not return it.
- [ ] Bound concurrent prewarm, snapshot, restore, and cleanup operations.
- [ ] Expensive artifact/image preparation remains outside child launch critical
      path.
- [ ] Scale-down from resident to parked to cold is idempotent and crash-safe.
- [ ] Host restart reconstructs ownership from durable leases and live process
      identity rather than trusting stale inventory records.

### Tests

- [ ] Used child cannot be recorded, claimed, or restored as shared capacity.
- [ ] Warm capacity cannot bypass live/resident VMM limits.
- [ ] Parked/private snapshot bytes cannot exceed workflow, tenant, or host
      quotas.
- [ ] Desired target over ceiling refuses before worker/prewarm enqueue.
- [ ] Controller retry storm does not override pressure eviction.
- [ ] Release reconciles to target rather than unconditionally replenishing.
- [ ] Quarantined capacity is never handed to a later claim.
- [ ] Restore receives new boot identity and rejects old controller grant.
- [ ] Crash at every scale-up/down boundary converges without leaked VMMs or
      double accounting.
- [ ] Direct launch and ordinary warm claims retain existing behavior when no
      workflow owner is present.

### Performance gates

- [ ] Warm workflow child meets the pinned WS0 SLO from admitted command to
      authenticated readiness.
- [ ] Capacity reconciliation and cleanup remain outside the measured launch
      window where safe.
- [ ] Scaling to zero leaves no VMM process, live channel, workflow-owned socket,
      or resident guest memory.

### Acceptance

- [ ] A controller can request warm capacity and scale it back to cold without
      creating a state-reuse or host-exhaustion path.

---

## WS9 — Graph epochs, supervision, cancellation, and recovery

**Purpose:** Make workflows durable and iterative without cyclic live streams or
implicit authority.

### Workflow specification and revisions

- [ ] Define `WorkflowSpec`, `WorkflowRevision`, and `GraphPatch` in
      `mvm-contract`.
- [ ] Root specification binds:
      - authority domain;
      - tenant;
      - initial controller policy;
      - exact template/action catalog digest;
      - initial constraint snapshot;
      - retention/classification posture;
      - initial graph;
      - workflow deadline.
- [ ] `GraphPatch` binds expected revision, previous graph digest, controller
      generation, idempotency key, additions/cancellations, and optional epoch
      seal.
- [ ] Revisions are append-only and CAS-committed against the expected head.
- [ ] Running child plans are immutable. A patch can bind existing declared
      slots or create a new attempt; it cannot mutate a live plan in place.
- [ ] A retry creates a new `NodeAttempt` with `retries` lineage rather than
      rewriting a failed attempt.

### Three graph validators

- [ ] Authority graph is a rooted forest with one authority parent per attempt.
- [ ] Dataflow graph is acyclic and has at most one writer per stdin slot.
- [ ] Causal event graph records correlation/causation but is not used as a
      launch authorization graph.
- [ ] Validate the union of all data-producing routes so hidden feedback cannot
      bypass cycle checks by switching from stream to another equivalent data
      channel.
- [ ] Graph validation runs before revision commit and before affected nodes
      boot.
- [ ] Preserve meaningful refusal paths and avoid revealing hidden topology to
      an unprivileged controller.

### Graph epochs

- [ ] A live stream/dataflow epoch is a DAG.
- [ ] Iteration occurs through a new revision/epoch, not a cyclic stream.
- [ ] Sealing an epoch records:
      - terminal/continuing nodes;
      - delivered artifact/message/stream roots;
      - outstanding work;
      - reason for next epoch.
- [ ] The next epoch may consume immutable outputs of the previous epoch under
      new exact plans.
- [ ] Maximum graph revisions and maximum total attempts remain
      non-replenishing budgets.

### Supervision

- [ ] Support explicit, bounded strategies:
      - `temporary`;
      - `transient`;
      - `permanent`;
      - `one_for_one`;
      - `rest_for_one`;
      - `one_for_all`.
- [ ] Strategy selection is in the admitted workflow/template policy, not
      arbitrary child output.
- [ ] Enforce restart intensity, maximum attempts, exponential backoff, jitter,
      workflow deadline, and subtree budget.
- [ ] A broken stream/mailbox edge fails according to explicit workflow policy;
      no silent reconnect across a new boot where scanner/ordering semantics
      would differ.
- [ ] EOF, cancellation, and terminal status propagate through declared
      supervision/data dependencies only.

### Cancellation and revocation

- [ ] Controller may cancel only descendants and only with an exact action.
- [ ] Cancellation request binds target attempt/boot and controller generation.
- [ ] Uniform refusal prevents existence/ownership oracle.
- [ ] Parent cancellation policy declares whether to cascade, detach, complete,
      or checkpoint descendants.
- [ ] Workflow/tenant revocation is enforced host-side immediately; it does not
      wait for a guest message.
- [ ] Revoked capacity targets reconcile downward.
- [ ] Terminal cancellation records the last delivered message/stream/artifact
      positions without claiming exactly-once completion.

### Controller failure and fencing

- [ ] `ControllerLease` binds controller attempt, boot, generation, validity,
      actions, and workflow revision.
- [ ] Every mutation checks current generation.
- [ ] New generation fences all prior generations before accepting mutations.
- [ ] Old generation may receive only explicitly permitted terminal/read-only
      facts; it cannot launch, release, stop, restore, approve, or change
      capacity.
- [ ] Standby controller recovery replays authoritative workflow state rather
      than trusting predecessor memory.
- [ ] Split-brain resolution never uses wall-clock last-write-wins.

### Recovery

- [ ] Durable state machine covers requested, reserved, intent-recorded,
      admitted, starting, ready, running, releasing, terminal, and cleanup
      fault states.
- [ ] Recovery distinguishes:
      - no side effect;
      - VMM may have started;
      - authenticated child ready;
      - outcome commit missing;
      - teardown incomplete.
- [ ] Reconcile using boot identity, process liveness, lease ownership, and
      signed plan—not VM name alone.
- [ ] Reservation and attempt state remain until live side effects are settled
      absent.
- [ ] Orphan reaper is authority-domain and boot scoped.

### Tests

- [ ] Self, two-node, long, disjoint, and hidden-route cycles refuse.
- [ ] Fan-in refuses and names the required merge-stage remedy.
- [ ] CAS conflict does not partially apply a graph patch.
- [ ] Old controller generation loses all mutating rights immediately.
- [ ] Restart storms remain within total attempts, rate, concurrency, and
      deadline.
- [ ] Every supervisor strategy has normal/failure/cancellation/crash tests.
- [ ] Crash/restart at every lifecycle transaction state has one allowed
      recovery outcome.
- [ ] Partition/failover model checking finds no two active controller
      generations for one mutation authority.

### Acceptance

- [ ] Workflows can iterate and recover without cyclic live streams, duplicate
      authority, unbounded restarts, or rewritten provenance.

---

## WS10 — AI planning snapshots and controller SDK

**Purpose:** Let an optional AI planner choose useful tools, services, models,
and worker templates while keeping authority deterministic and finite.

### AI remains optional and orthogonal

- [ ] Model these dimensions independently:
      - AI configured or absent;
      - workflow member or direct;
      - lifecycle delegation present or absent.
- [ ] An AI-enabled direct workload receives no lifecycle authority by
      implication.
- [ ] An AI worker receives no lifecycle authority by implication.
- [ ] A deterministic controller can use the same lifecycle API without an AI
      dependency.
- [ ] No model library enters `mvm-core`, `mvm-agentd`, plan verification,
      lifecycle admission, VMM supervisors, or the VM launch critical path.

### Unified action catalog

- [ ] Add `ActionDescriptor`, `ActionTarget`, `ActionBinding`,
      `SideEffectClass`, `RiskClass`, `ActionDataPolicy`, `ActionCost`,
      `LatencyClass`, and `IdempotencyClass`.
- [ ] Supported targets include local tool, host service, model service, child
      microVM template, and external connector.
- [ ] Security fields are typed and signed; human descriptions are not parsed
      as permission.
- [ ] Exact descriptor and schema digests bind every executable action.
- [ ] Catalog entries have one status:
      - executable;
      - approval-required;
      - requestable;
      - invisible.
- [ ] A requestable action cannot be submitted to the execution endpoint.

### Planning snapshot compiler

- [ ] Compile a finite controller-specific `ControllerPlanningSnapshot` from:
      - signed constraint snapshot;
      - trusted ontology/ruleset versions;
      - exact action/template records;
      - current workflow revision;
      - authoritative workflow state;
      - controller generation;
      - current remaining budget;
      - sanitized availability hints.
- [ ] Bind ontology, ruleset, compiler, catalog, workflow revision, constraint,
      controller identity/generation, validity, and snapshot digest/signature.
- [ ] Snapshot exposes no signer, host path, physical node credential, raw fleet
      inventory, other-tenant topology, or mutable authority reference.
- [ ] Large catalogs are queried through bounded pagination pinned to the same
      snapshot digest.
- [ ] Stale, partial, unknown-schema, revoked-issuer, expired, or
      ontology-drifted inputs fail snapshot compilation closed.

### Semantic-class discovery

- [ ] Allow workflow policy to preauthorize a semantic class with exact:
      publisher, attestation, capability, risk, resource, instance, data, and
      network ceilings.
- [ ] Compiler evaluates the class against a pinned semantic snapshot and emits
      a finite exact candidate set.
- [ ] AI may rank candidates but must ultimately select one exact binding.
- [ ] Runtime never re-runs open semantic discovery for a privileged action.
- [ ] Similarity, embeddings, tags, or AppView rank cannot include a candidate
      excluded by hard constraints.

### Controller runtime/SDK

- [ ] Add optional `mvm-sdk::workflow` controller runtime:
      - planning snapshot client;
      - typed action catalog query;
      - mailbox client;
      - artifact client;
      - typed planner-decision validator;
      - lifecycle dispatcher;
      - idempotency manager;
      - remaining-budget view;
      - optional model adapter trait.
- [ ] AI emits `PlannerDecision` with snapshot digest, revision, decision ID,
      bounded actions, expected outputs, estimated budget, and optional
      rationale digest.
- [ ] Planned actions are closed typed variants, never shell/natural-language
      commands.
- [ ] Local validation exists for diagnostics; host repeats all checks
      authoritatively.
- [ ] Treat model and child outputs as untrusted context with explicit source,
      digest, classification, issuer, and trust level.
- [ ] Prompt/context construction separates immutable policy, authoritative
      topology, task intent, and untrusted results structurally.

### Model configuration

- [ ] Add optional `AiPlannerConfig` binding:
      - exact model/provider binding;
      - inference mode;
      - maximum planning steps;
      - maximum model calls;
      - input/output token and context-byte limits;
      - planning wall-clock deadline;
      - external cost ceiling;
      - required output schema;
      - context/data policy.
- [ ] Support future embedded, dedicated model microVM, host-mediated model
      service, and external connector modes behind exact capabilities.
- [ ] Host-mediated/external modes never deliver raw provider credentials to
      the controller.
- [ ] Data classification and destination policy decide which context may leave
      the host/workflow.
- [ ] A model response is an untrusted decision candidate, never a signed grant.

### Capability requests and approvals

- [ ] Add advisory `CapabilityNeed` with snapshot digest, semantic role, reason
      digest, schemas, concurrency, estimated budget, and evidence refs.
- [ ] Emitting a need does not reserve, launch, or modify authority.
- [ ] Only parent authority/operator/`mvmd` policy can issue a replacement
      signed constraint/planning snapshot.
- [ ] Approval binds the exact request digest, approver authority, expiry,
      nonce, action, and narrowed limits.
- [ ] Rate-limit and group approval requests to prevent approval fatigue.
- [ ] Some high-risk actions remain non-approvable by runtime prompt and require
      pre-admission policy changes.

### AI abuse controls

- [ ] Bound planner invocations, tokens, context bytes, wall time, provider cost,
      action count, launch attempts, denials, and capability requests.
- [ ] Return typed remaining quota and retry-after without revealing host/global
      inventory.
- [ ] Repeated denied action loops trigger a controller-local circuit breaker.
- [ ] The circuit breaker cannot itself grant more budget or authority.
- [ ] AI cannot make positive trust assertions about its own model, template,
      output, or child.

### Tests

- [ ] Hallucinated action/binding refuses.
- [ ] Descriptor/schema digest mismatch refuses.
- [ ] Semantic result outside exact candidate set cannot execute.
- [ ] Requestable action remains non-executable.
- [ ] Planner snapshot stale revision, generation, expiry, or digest refuses.
- [ ] Prompt injection in child output cannot bypass typed dispatch or host
      admission.
- [ ] Model loop remains within token/call/time/cost/action/denial limits.
- [ ] AI-disabled controller follows the same lifecycle path.
- [ ] Direct AI workload has no workflow files/binding/authority.
- [ ] Disabling semantic ranking may change ordering but cannot change the
      authorized candidate set.

### Acceptance

- [ ] A fully compromised AI can make poor choices only inside the exact finite
      controller partition; it cannot enlarge the partition.

---

## WS11 — Recursive delegation and controller groups

**Status:** DEFERRED until WS0–WS10 are production-witnessed.

**Purpose:** Add controlled recursion and multi-controller policy without
turning every worker into an issuer or introducing guest-side consensus.

### Recursive delegation

- [ ] Default remains `max_depth=1`, `max_controllers=1`, and
      `child_may_delegate=false`.
- [ ] A child controller must be an explicitly admitted controller template.
- [ ] Delegated action set, templates, capabilities, egress, secrets,
      filesystem, tools, resources, budget, validity, and depth are each
      independently attenuated.
- [ ] Every descendant is checked against both immediate parent and workflow
      root ceilings; an intermediary cannot launder authority.
- [ ] Subtree budget is atomically carved from parent delegable remaining
      budget and cannot be double-delegated.
- [ ] Parent retains no power to reclaim consumed non-replenishing budget by
      deleting the child.
- [ ] Revocation cascades according to explicit policy and fences future child
      mutations immediately.

### Controller groups

- [ ] Begin with host-serialized policies:
      - `SingleActive`;
      - `AnyOf`;
      - `Threshold(k)` over distinct boot identities.
- [ ] Do not implement general guest-side distributed consensus.
- [ ] Threshold proposals bind the same patch/action digest and current
      workflow revision.
- [ ] Host/`mvmd` counts distinct current-generation controller identities.
- [ ] One committed action creates one reservation and outcome regardless of
      duplicate proposals.
- [ ] Controller replacement increments generation and invalidates old votes.

### Formal and destructive gates

- [ ] Lean/reference theorem: effective descendant authority is a subset of
      every ancestor/root ceiling.
- [ ] Model-check double delegation, concurrent subtree reservations,
      revocation, stale votes, partitions, and controller replacement.
- [ ] Fuzz deeply nested delegation at the maximum admitted depth without
      recursion-based stack exhaustion.
- [ ] Mutation tests prove removing any root/parent/template intersection check
      is caught.

### Acceptance

- [ ] No path through multiple controllers creates authority or resource budget
      absent from the workflow root.

---

## WS12 — `mvmd` issuer, placement, and distributed workflow routing

**Purpose:** Move production workflow meaning, fleet authority, and cross-node
coordination to `mvmd` while preserving independent node verification.

> The `mvmd` repository was unavailable during this research. Every module name
> in this workstream is provisional until source inspection in WS0.

### Fleet authority

- [ ] `mvmd` owns workflow root identity, tenant mapping, controller leases,
      canonical graph head, fleet budget, template catalog policy, and
      production delegation issuance.
- [ ] Amend production launch semantics so every production child is rooted in
      authenticated `mvmd` authority, including controller-exercised delegated
      launches.
- [ ] A controller is not an issuer: it cannot mint node-verifiable grants or
      change tenant/fleet policy.
- [ ] `mvmd` issues short-lived, audience-bound launch/route/controller grants.
- [ ] Nodes hold verifying material only and fail unknown key IDs closed.
- [ ] Key distribution is out-of-band of the peer being authenticated.
- [ ] Rotation and revocation preserve historical verification evidence.

### Identity

- [ ] Preserve runtime execution identity:
      `node_id + vm_id + boot_id + plan_digest`.
- [ ] Add workflow/attempt/controller-generation context without replacing the
      execution identity.
- [ ] A launch, route, message, artifact delivery, and cancellation names a
      boot/attempt, not a reusable VM name.
- [ ] Avoid assigning a full DID/repository to every ephemeral VM.
- [ ] Tenant/operator/organization/external publisher identities may use DIDs
      at the external identity boundary; runtime decisions use pinned local
      verifier material.

### Placement and reservation

- [ ] Fleet reservation atomically covers tenant/workflow/node/host dimensions.
- [ ] Node selection occurs after hard capability/resource/data constraints and
      before semantic optimization.
- [ ] Destination node independently verifies launch grant, plan, audience,
      tenant, workflow, attempt, boot intent, expiry, nonce, and local host
      safety.
- [ ] Source/controller admission is never trusted as the destination's own
      admission.
- [ ] Placement does not reveal raw fleet inventory to the controller.
- [ ] Node refusal distinguishes operational classes for `mvmd` while keeping
      guest-facing existence/ownership refusals uniform.

### Distributed mailbox/control routing

- [ ] First distributed workflow uses host-mediated control/mailbox relay, not
      general guest L3:

```text
controller guest
  → local encrypted workflow endpoint
  → authenticated node/mvmd transport
  → destination node workflow endpoint
  → destination guest encrypted endpoint
```

- [ ] Every relay hop authenticates node and binds workflow/tenant/source boot/
      destination boot/route grant.
- [ ] Destination node resolves only workloads it currently hosts and refuses
      absent/not-mine identically to untrusted callers.
- [ ] Cross-node payloads preserve digest, classification, schema, sequence,
      causal IDs, TTL, and replay protection.
- [ ] Large payloads route as content-addressed artifacts, not unbounded relay
      frames.
- [ ] General cross-node L3 remains blocked on ADR-040 prerequisites and is not
      needed for initial swarm operation.

### Partition and failover policy

- [ ] New mutations fail closed after controller/route/launch lease expiry.
- [ ] Existing children may continue only according to admitted lease/deadline
      policy.
- [ ] No duplicate replacement without a newer fencing token.
- [ ] Bounded encrypted local queues have explicit partition TTL and quota.
- [ ] Safety is preferred over availability for launch, cancellation,
      delegation, secret release, and capability change.
- [ ] Reconciliation never uses timestamp-only conflict resolution.

### Distributed audit/provenance

- [ ] Node records the decision it makes in its local chain-signed audit.
- [ ] `mvmd` records fleet transaction/placement facts separately.
- [ ] Workflow receipt carries both local execution proof and fleet issuer/
      placement proof.
- [ ] Do not collapse execution, fleet authorization, publication, and labeler
      signatures into one key or assertion.
- [ ] Define off-host audit-root witnessing separately; do not overclaim host
      tamper resistance from host-local signatures alone.

### Tests

- [ ] Wrong node, wrong boot, wrong plan digest, wrong tenant, stale generation,
      expired grant, unknown key ID, revoked issuer, replay, and destination
      absence refuse.
- [ ] Source node cannot cause destination effect without destination
      verification.
- [ ] Network partition, duplicate delivery, controller failover, node loss,
      delayed old-generation command, and orphan recovery are model-checked and
      integration-tested.
- [ ] Cross-tenant topology/message/artifact inference is blocked.
- [ ] Local and fleet authority domains cannot use one another's bindings.
- [ ] A controller cannot select a physical node unless an exact, separate
      placement capability is admitted—and the first release provides none.

### Acceptance

- [ ] Compromising one controller or source node cannot grant reach or launch
      authority on another node beyond independently verified `mvmd` grants.

---

## WS13 — AT-shaped internal semantic/provenance plane

**Purpose:** Adopt useful AT Protocol distributed-systems patterns in `mvmd`
without putting a PDS, relay, repository, AppView, DID resolver, OAuth server,
or eventual semantic state on the execution path.

### Governing choice

- [ ] Implement **AT-shaped internal records first**, not a full internal PDS:
      - globally namespaced record kinds;
      - schema-versioned typed envelopes;
      - exact-byte CIDs/digests;
      - URI-plus-CID strong references;
      - transactional outbox after authoritative commit;
      - replayable cursor streams;
      - idempotent projectors/AppViews;
      - gap detection and snapshot/resync.
- [ ] Keep transactional task claims, leases, mailbox acknowledgements,
      controller generations, launch reservations, cancellation, and ownership
      in the authoritative database/state machine.
- [ ] Project authenticated lifecycle facts only after the authoritative
      transaction commits.
- [ ] Current-state semantic repositories do not replace the existing
      chain-signed audit or transaction journal.

### Record vocabulary

- [ ] Define internal schemas/NSIDs for at least:
      - execution plan/run/audit anchor;
      - node descriptor/machine instance;
      - artifact manifest/provenance;
      - topology edge;
      - policy constraint/snapshot/attestation;
      - agent definition/delegation/task/message fact;
      - workflow revision/controller generation/capacity fact.
- [ ] Use dedicated schemas for security-relevant predicates rather than one
      unconstrained general-purpose edge where validation differs.
- [ ] Every authoritative projection carries issuer, evidence, tenant/workflow,
      node/VM/boot/plan where relevant, validity/revocation, ontology/ruleset,
      and exact strong references.
- [ ] Distinguish exact byte identity from optional semantic identity/address.

### Outbox and projectors

- [ ] Authoritative transaction writes state plus outbox atomically.
- [ ] Projector consumption is idempotent by event/record identity.
- [ ] Cursor gaps trigger bounded resync/snapshot, never guessed continuity.
- [ ] Projector lag/staleness is observable.
- [ ] No scheduler, plan admission, launch, packet, secret release, mailbox
      ownership, or cancellation waits on an AppView.
- [ ] Projector/database/parser processes hold no plan/lease/grant/audit signing
      keys unless the role specifically owns one—and external ingest owns none.

### Labels and attestations

- [ ] Model authorship separately from trust, truth, and authorization effect.
- [ ] Trust policy defines:
      - issuers allowed to make positive authorization assertions;
      - issuers allowed to force quarantine;
      - advisory-only labels;
      - labels that may only narrow capability;
      - quorum/evidence/expiry/revocation/conflict rules.
- [ ] Workload scanners emit evidence as ordinary isolated workloads.
- [ ] Scanner workload never receives labeler/issuer signing key.
- [ ] A key-holding labeler role validates evidence and signs the assertion.
- [ ] A workload cannot positively attest to its own trustworthiness.
- [ ] Conflicting, stale, unknown, or unavailable external labeler results fail
      according to explicit policy, never implicit allow.

### Constraint compiler integration

- [ ] Compile exact URI/CID/digest inputs, issuers/key IDs, schema digests,
      ontology/ruleset/compiler versions, resource/data/network/filesystem/
      secret/tool/spawn/delegation policy, attestations, validity, revocations,
      digest, and `mvmd` signature into `ConstraintSnapshot`.
- [ ] The compiler is deterministic with frozen golden vectors across `mvm` and
      `mvmd`.
- [ ] Existing live plans are never silently widened when semantic records
      change.
- [ ] Replacement snapshot is a new explicit authorization event.

### Security hardening

- [ ] External/semantic parser process:
      - holds no launch authority or signing key;
      - has strict byte/depth/count/time/redirect/URL limits;
      - validates into internal DTOs;
      - cannot directly trigger a launch;
      - is fuzzed independently.
- [ ] Prevent SSRF, redirect abuse, decompression bombs, CAR/CBOR parser abuse,
      repository rollback, mutable-reference races, cross-tenant inference, and
      attacker-authored positive trust assertions.
- [ ] Public-data assumptions are explicit; raw private payloads are prohibited.

### Tests

- [ ] Transaction commits even when projector/AppView is down; projection
      catches up later.
- [ ] Stale AppView cannot authorize a launch.
- [ ] Gap/resync, duplicate event, rollback, schema drift, revoked issuer,
      conflicting labels, and unavailable labeler all follow explicit policy.
- [ ] Strong reference detects record mutation/substitution.
- [ ] CID alone never authenticates an issuer or makes an assertion true.
- [ ] Chain-signed audit remains independently verifiable and is not replaced by
      repository current state.

### Acceptance

- [ ] Semantic/provenance views improve discovery and explanation while system
      safety is unchanged if every projector and external semantic service is
      disabled.

---

## WS14 — Optional true AT Protocol interoperability bridge

**Status:** DEFERRED until WS13 validates the internal model and official protocol
maturity/dependency assessment remains favorable.

**Purpose:** Publish/import sanitized portable templates, capabilities,
attestations, provenance, and optional run summaries without making AT Protocol
the scheduler, private mailbox, or execution trust root.

### Protocol pinning

- [ ] Pin official AT specifications, repository revisions, supported signing
      algorithms, Lexicon behavior, CAR/MST formats, OAuth permissions, DID
      resolution, event stream semantics, deletion/tombstone limitations, and
      Rust implementation/conformance status.
- [ ] Re-evaluate public/private-data assumptions and permissioned-data maturity
      at implementation time.
- [ ] Decide between a small conformance-pinned Rust subset, generated data
      model types, sidecar, or deferred implementation based on evidence—not
      ecosystem enthusiasm.
- [ ] Keep AT dependencies out of `mvm-core`, `mvm-agentd`, VMMs, plan verifier,
      and immediate guest/host protocol path.

### Export bridge

- [ ] Separate bridge process holds no fleet issuer, plan signer, lease signer,
      audit signer, raw secret, or lifecycle capability.
- [ ] Explicit allowlist controls every exported field.
- [ ] Eligible public records include sanitized workflow/template descriptors,
      capability descriptors, public artifact provenance, public attestations,
      and opt-in redacted final run summaries.
- [ ] Prohibit raw stdout/stderr, prompts, mailbox payloads, secrets, PII,
      private topology, placement, node health, leases, controller grants,
      active constraints, or transactional state.
- [ ] Publication happens after local authoritative commit and is never required
      for boot or workflow completion.
- [ ] Preserve dual proof: original `mvm` execution proof plus authenticated AT
      publication proof.

### Import bridge

- [ ] Resolve and pin publisher identity/keys according to explicit trust policy.
- [ ] Verify repository commit/record proof and pin exact record URI+CID.
- [ ] Validate Lexicon/schema/version and strict bounds.
- [ ] Fetch referenced artifacts through constrained resolvers.
- [ ] Verify `mvm`-native bundle signatures, content digests, provenance,
      scanners, and policy before template admission.
- [ ] Imported record is a proposal/publication, never an executable command.
- [ ] Mutable names are resolved and pinned before workflow snapshot
      compilation, not during launch.

### Event/federation semantics

- [ ] Treat firehose/subscription as replayable event distribution, not lock,
      lease, task claim, causal total order, or exactly-once executor.
- [ ] Handle cursors, gaps, bounded backfill, repository resync, duplicate
      events, deletion, and rollback explicitly.
- [ ] No runtime decision requires live PDS, relay, AppView, DID, or OAuth.

### Tests

- [ ] Forged publication, wrong DID key, mutable record substitution, deleted
      record, rollback, gap, duplicate, oversized CAR/CBOR, malicious redirect,
      SSRF target, and schema drift refuse safely.
- [ ] Bridge compromise cannot launch, stop, route, issue, sign, or alter an
      admitted workflow.
- [ ] Public export allowlist prevents every prohibited private field.
- [ ] PDS/relay/AppView outage has zero effect on direct or workflow launch.

### Acceptance

- [ ] AT Protocol provides optional portability/federation without becoming an
      internal authority, confidential store, transaction database, or
      availability dependency.

---

## WS15 — CLI, SDK, observability, Studio, and documentation

**Purpose:** Make the security posture and actual lifecycle visible without
inventing a second control path.

### CLI separation

- [ ] Preserve existing direct commands:
      - `machine run`;
      - `machine stop`;
      - `invoke`;
      - existing stream/log operations.
- [ ] Add explicit workflow surface rather than silently treating direct runs as
      one-node workflows:
      - `workflow run`;
      - `workflow inspect`;
      - `workflow status`;
      - `workflow logs`;
      - `workflow events`;
      - `workflow capacity`;
      - `workflow cancel`;
      - `workflow verify-receipt`.
- [ ] A one-node workflow is legal only when explicitly launched through the
      workflow surface.
- [ ] CLI output distinguishes requested, authorized, reserved, achieved,
      warm/cold origin, enforced/declared resource tier, workflow/controller
      generation, and terminal cleanup state.
- [ ] No CLI flag can locally promote a direct workload into a controller or
      production workflow.

### SDK/client

- [ ] Add separate `MachineClient` and `WorkflowClient` surfaces sharing
      internal launch primitives.
- [ ] Local and remote workflow backends implement one stable contract.
- [ ] SDK types expose opaque bindings/handles, never host routes or raw VMM IDs.
- [ ] Rust/Python/TypeScript parity fixtures include workflow, action, mailbox,
      constraint, and receipt types where those SDKs are supported.
- [ ] Unknown fields and unsupported versions refuse consistently across SDKs.

### Observability

- [ ] `doctor` reports workflow prerequisites and achieved backend enforcement
      honestly.
- [ ] Per-workflow metrics include live/running/claiming/warm/parked/private
      counts, reserved versus used budgets, launches, refusals, denial circuit
      breakers, queue/storage use, reconciliation lag, graph revision, and
      projector lag.
- [ ] Metrics are bounded-cardinality and do not reveal tenant-private
      topology/data.
- [ ] Lifecycle audit entries carry no raw payloads, prompts, secrets, or model
      outputs.
- [ ] Repeated identical denials are bounded/deduplicated with signed summaries
      so audit signing/storage cannot be DoSed.
- [ ] Every user-visible receipt/status states limits and uncertainty honestly:
      AI semantic correctness is not attested; host threat-model limits remain.

### Studio/read-only visualization

- [ ] First Studio support is read-only:
      - authority tree;
      - dataflow DAG by epoch;
      - causal event view;
      - node attempt/boot lineage;
      - capacity states;
      - budget and refusal view;
      - artifact/transcript/mailbox roots;
      - constraint/planning snapshot provenance.
- [ ] Mutating Studio controls are deferred until the CLI/API transaction model
      is complete and independently audited.
- [ ] Visualization uses projected views and clearly marks staleness; it never
      becomes the scheduler or authorization source.

### Documentation

- [ ] User guide: direct versus workflow execution.
- [ ] Controller-author guide: exact templates, actions, budgets, AI planning,
      approvals, and lifecycle.
- [ ] Security guide: controller compromise, resource partition, attenuation,
      process split, warm-state rules, mailbox privacy, and AT boundary.
- [ ] Operator guide: host/tenant ceilings, pressure policy, key rotation,
      revocation, incident response, orphan recovery, and scale-to-zero.
- [ ] Formal-model guide: abstractions, invariants, bounds, and how witnesses map
      to production code.
- [ ] Migration guide for plan/wire versions and omitted-when-absent fields.
- [ ] Document every unsupported/deferred feature explicitly.

### Tests

- [ ] CLI help/parsing and local/remote behavior tests.
- [ ] Direct commands remain byte/behavior compatible where intended.
- [ ] Inspect/status never claim an enforced tier not read back from backend.
- [ ] Studio/AppView outage does not affect execution.
- [ ] Metrics/audit/log redaction and cardinality bounds are tested.

### Acceptance

- [ ] Operators can explain exactly why a controller could or could not perform
      an action and what resources/evidence each workflow consumed.

---

## WS16 — Security evidence, formal refinement, performance, and claim promotion

**Purpose:** Prevent design prose and unit-tested dormant controls from being
mistaken for a production security property.

### Claims discipline

- [ ] Add workflow/controller claims to the claim ledger as `Open` or `Preview`
      before implementation.
- [ ] Every claim has:
      - exact prose;
      - threat-model scope;
      - known limits;
      - named production caller;
      - positive witness;
      - negative witness;
      - planted-defect/mutation witness where practical;
      - platform/backend applicability.
- [ ] Do not promote controls that have no production caller.
- [ ] Do not claim malicious-host protection under the current threat model.
- [ ] Do not claim exactly-once execution, universal secret detection, semantic
      correctness, or complete steganographic exfiltration prevention.

### Required property suite

- [ ] `check-workflow-no-ambient-authority`.
- [ ] `check-workflow-direct-path-isolation`.
- [ ] `check-workflow-single-launch-projection`.
- [ ] `check-workflow-authority-attenuation`.
- [ ] `check-workflow-budget-conservation`.
- [ ] `check-workflow-template-exactness`.
- [ ] `check-workflow-no-guest-addressing`.
- [ ] `check-workflow-used-child-never-pooled`.
- [ ] `check-workflow-encrypted-no-fallback`.
- [ ] `check-workflow-parser-holds-no-authority`.
- [ ] `check-workflow-audit-before-effect`.
- [ ] `check-workflow-formal-vector-drift`.
- [ ] `check-workflow-atproto-off-critical-path`.
- [ ] `check-workflow-semantic-state-cannot-authorize`.

### Fuzzing

- [ ] Guest workflow control frames.
- [ ] Mailbox envelopes, cursors, archive manifests, and artifact refs.
- [ ] Constraint/planning snapshots and exact binding resolution.
- [ ] Graph patches and topology validators.
- [ ] Launch permits and recovery journals.
- [ ] Cross-node relay envelopes.
- [ ] Semantic/AT ingest parsers independently from trusted roles.
- [ ] Size/depth/count/unknown-field/version/replay ladders for every wire type.

### Formal refinement

- [ ] Maintain Alloy model for authority/dataflow/static shape.
- [ ] Maintain TLA+/Apalache model for launch/reservation/fencing/recovery/
      partition transitions.
- [ ] Maintain Lean or equivalent pure reference semantics for attenuation,
      budget arithmetic, information-label joins, and graph patch predicates.
- [ ] Generate shared valid/invalid golden vectors consumed by Rust tests.
- [ ] Record bounds and explicitly state what each finite model check does not
      prove.
- [ ] For each implementation phase, map concrete states/transitions to the
      abstract model and update the refinement table.

### Destructive and mutation matrix

- [ ] Remove each authority-intersection term and prove a test/gate fails.
- [ ] Remove atomic reservation and prove concurrent launches oversubscribe in
      the mutant but not production.
- [ ] Re-enable used-child pool return and prove the gate catches it.
- [ ] Permit stale controller generation and prove failover tests catch it.
- [ ] Skip audit intent and prove launch-before-evidence gate catches it.
- [ ] Allow semantic/AppView result to reach launch and prove architecture gate
      catches it.
- [ ] Add plaintext/downgrade fallback and prove encrypted-session gate catches
      it.
- [ ] Make parser role hold signer/backend dependency and prove trust-gradient
      gate catches it.
- [ ] Remove total-attempt budget and prove restart/launch churn test fails.

### Live platform/backend evidence

- [ ] Linux KVM/Firecracker local controller/worker vertical slice.
- [ ] macOS HVF/libkrun path according to actual supported enforcement tiers.
- [ ] Windows/QEMU path or explicit unsupported/refusal posture.
- [ ] 1,000+ successful bounded claims per supported warm backend.
- [ ] Launch storm, denial storm, mailbox flood, snapshot pressure, audit
      pressure, process/FD/socket exhaustion, and controller crash tests.
- [ ] Host restart and orphan recovery on real VMM processes.
- [ ] Cross-node authenticated flow on two real nodes before fleet claim
      promotion.
- [ ] Key rotation/revocation and historical receipt verification.

### Performance gates

- [ ] Direct launch benchmark before/after with no statistically significant
      regression beyond the WS0 threshold.
- [ ] Idle host with no workflow has zero workflow-only resident process and a
      tightly bounded/zero workflow memory footprint.
- [ ] Workflow graph/semantic compilation occurs before launch permit, not on
      the VMM start hot path.
- [ ] Message route lookup is bounded and based on resolved bindings.
- [ ] Warm child launch meets pinned SLO at p50/p95/p99/max across required
      platform matrix.
- [ ] Capacity scale-down and cleanup do not delay unrelated direct launches.
- [ ] AI model latency is measured separately from lifecycle launch latency.
- [ ] PDS/relay/AppView outage adds zero launch latency.

### Security review gates

- [ ] Independent review of controller lifecycle grant and permit model.
- [ ] Independent review of reservation/recovery state machine.
- [ ] Independent review of encrypted session and key lifecycle.
- [ ] Independent review of process privileges/dependency graph.
- [ ] Independent review of cross-node issuer/verifier split.
- [ ] Privacy review for mailbox/artifact/semantic/public export fields.
- [ ] Threat model and ADR updated with every accepted residual risk.

### Acceptance

- [ ] Claims are promoted only after the real production call path, negative
      cases, live platform witnesses, mutation witnesses, formal-vector parity,
      and independent review all agree.

---

## Security invariant and witness matrix

| Invariant | Primary owner | Required witness |
|---|---|---|
| One guest is one workload | existing runtime + workflow admission | controller/worker image and launch-path tests |
| Direct run creates no workflow state | CLI/runtime | process, filesystem, socket, dependency, and benchmark witness |
| Every child has an admitted signed plan | workflow admission + existing plan path | child launch receipt and tamper/replay ladder |
| Controller has no hypervisor authority | process/contract boundary | dependency/privilege scan and parser compromise test |
| Controller launches exact templates only | constraint compiler/admission | unauthorized/mutated template refusal before side effect |
| Authority only attenuates | contract compiler + node verifier | formal subset theorem, golden vectors, mutation tests |
| Budget never becomes negative | transactional reservation ledger | concurrent reservation model and launch-storm test |
| Host safety reserve survives valid workflows | host admission | real pressure/oversubscription test |
| Attempts are non-replenishing | workflow ledger | churn test with low live count/high retries |
| One idempotency key has at most one live effect | transaction journal | crash/retry/concurrent duplicate test |
| Stale generation cannot mutate | controller lease/fencing | delayed old-controller command test |
| Used child never becomes shared warm capacity | warm reconciler | state-transition gate and secret/state-bleed mutant |
| Dataflow remains a DAG | topology validator | cycles across all data-route types |
| One stdin has one writer | stream/mailbox composition | fan-in and operator-stdin refusal |
| Guest never directly addresses another guest | binding resolver | enumeration/forged VM ID/cross-workflow tests |
| Mailbox sender is channel-derived | mailbox ingress | spoofed sender ignored/refused |
| Security effect has prior durable intent | lifecycle transaction | fail audit store and crash between every phase |
| Raw private data does not enter semantic/public plane | projector/export allowlist | canary/secrets/PII fixtures and schema scans |
| Semantic state cannot authorize live effect | compiler/execution separation | disable/corrupt AppView while launch path remains safe |
| AI cannot enlarge partition | planning snapshot + admission | malicious/hallucinated planner matrix |
| Destination node verifies independently | node verifier | compromised source/forged grant two-node test |
| AT services are off critical path | optional bridge boundary | total AT outage during direct/workflow launch |

---

## Dependency and stop/go checkpoints

### Checkpoint A — after WS0

Proceed only when:

- ADR-045 and threat-model amendments are accepted;
- production delegation rule is settled;
- launch SLO is pinned;
- mailbox ownership and encryption prerequisite are settled;
- actual `mvmd` seams are inspected.

Stop if the project cannot define a separate host/tenant/workflow ceiling or
cannot refuse unenforceable production resource bounds.

### Checkpoint B — after WS1–WS3

Proceed only when:

- direct plan bytes/behavior remain compatible;
- pure authority/budget semantics have formal vectors;
- reservation ledger survives concurrency and crash tests;
- no guest wire type can carry arbitrary launch configuration.

Stop if atomic multi-dimensional reservation cannot be made durable without
putting a heavyweight database or global lock on direct launch.

### Checkpoint C — after WS4–WS6

Proceed only when:

- workflow session has no plaintext downgrade;
- parser/admission/launch roles are split;
- local vertical slice contains controller compromise to the configured
  envelope;
- direct run has no workflow process/state/performance regression.

Stop if the controller can reach a backend/VMM authority directly or if audit
failure can leave an unrecorded launch.

### Checkpoint D — after WS7–WS10

Proceed only when:

- mailbox/archive/artifact privacy and bounds hold;
- warm/cold reconciliation destroys used children;
- graph epochs/recovery are safe;
- AI ranking cannot change the authorized candidate set.

Recursive delegation remains deferred unless all of these are production
witnessed.

### Checkpoint E — before WS12 fleet production

Proceed only when:

- `mvmd` issuer/verifier/key lifecycle is implemented;
- two-node destination verification and fencing pass;
- partition/orphan behavior is model-checked and live-tested;
- local/fleet authority domains cannot cross.

General cross-node L3 remains independent and blocked on its own ADR
prerequisites.

### Checkpoint F — before true AT compatibility

Proceed only when:

- AT-shaped internal records/projectors have demonstrated value;
- official protocol and Rust implementation maturity is pinned and acceptable;
- public/private-data constraints are enforceable;
- bridge compromise cannot affect execution;
- there is a concrete interoperability/federation user need.

---

## Explicit blockers and open decisions

These are genuine implementation blockers rather than ordinary coding choices.

- [ ] The actual `mvmd` repository/source tree and issuer/key model must be
      inspected.
- [ ] The current `mvm-mailbox` research/implementation must be reconciled with
      this plan rather than duplicated.
- [ ] The authoritative 200 ms versus sub-300 ms launch SLO must be settled.
- [ ] Production wall-clock enforcement must be verified complete on every
      admitted backend, or production workflow launch must refuse unsupported
      tiers.
- [ ] Host-wide admission budget from workload grants must be complete or an
      equivalent workflow-safe host budget must land first.
- [ ] The encrypted workflow-session primitive and key/bootstrap ownership must
      be selected in a separate accepted decision.
- [ ] Audit intent/action atomicity and recovery semantics must be accepted; no
      filesystem/database primitive provides literal cross-process atomicity
      with a VMM start, so the design must specify recoverable intent/effect
      ordering rather than claim impossible atomicity.
- [ ] Local standalone workflow storage must be selected consistently with the
      accepted minimal-storage posture and without burdening direct execution.
- [ ] Private actor checkpoint policy, classification, and deletion/revocation
      semantics must be accepted before stateful resume ships.
- [ ] Public domain/NSID ownership must be confirmed before publishing real AT
      Lexicons.

---

## Definition of done

Plan 329 is complete only when all of the following are true:

- [ ] Direct single-workload execution remains fully supported and independent.
- [ ] Local controller workflows launch exact single-workload child microVMs.
- [ ] Controller lifecycle authority is boot-bound, opaque, non-transferable,
      attenuated, transactionally budgeted, rate-limited, and fenced.
- [ ] A malicious controller cannot exceed workflow, tenant, or host ceilings.
- [ ] Used workload state never returns to shared capacity.
- [ ] Structured mailbox, stream, artifact, and receipt paths are bounded,
      private, and verifiable.
- [ ] AI planning is optional and can choose only exact compiled actions.
- [ ] Semantic/AT state cannot directly authorize an execution effect.
- [ ] `mvmd`-rooted production workflows independently verify on every node.
- [ ] Warm, parked, private-checkpoint, and cold capacity scale safely and
      honestly.
- [ ] Formal reference semantics, Rust implementations, golden vectors,
      fuzzing, mutation tests, destructive tests, and live platform witnesses
      agree.
- [ ] Performance gates pass and no AT/model/semantic dependency appears on the
      direct or child-launch critical path.
- [ ] ADRs, claims ledger, plan checkboxes, `specs/SPRINT.md`, and
      `specs/REFACTOR-STATUS.md` are updated together as work lands.
- [ ] User/operator/security documentation describes both properties and
      residual limits without overclaiming.

## Final implementation principle

```text
The AI chooses a desired topology.
The signed snapshots define the legal topology.
The transactional ledger is to establish that capacity is available.
The host or mvmd realizes the legal topology through ordinary admitted
single-workload microVM launches.
```

The workflow feature is successful only if a compromised controller can cause
bad work inside its assigned partition but cannot make the partition larger,
reach outside its authority domain, or weaken the isolation and audit properties
that direct `mvm` workloads already rely upon.

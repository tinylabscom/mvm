# Intelligent, capability-secure microVM workflows for `mvm` and `mvmd`

**Status:** Consolidated research and architecture proposal  
**Date:** 2026-08-13  
**Primary decision:** `mvm` keeps one workload per microVM as its atomic
execution unit. An optional workflow layer composes those same units into
host-mediated actor graphs. A controller is an ordinary microVM with a narrow,
boot-bound lifecycle capability and, optionally, an AI planner. The AI chooses
a desired topology from a finite signed planning snapshot; it cannot create
new authority or exceed the workflow's pre-admitted resource partition.

## 1. Purpose and scope

This document consolidates the design discussion around five related goals:

1. Preserve `mvm` as a fast, secure single-workload microVM runner.
2. Add an optional workflow and actor layer in which one admitted controller
   can cause additional single-workload microVMs to launch, communicate, stop,
   checkpoint, and scale between cold, parked, resident-warm, and running
   states.
3. Allow the controller to use AI, when explicitly configured, to determine
   which admitted tools, host services, model services, connectors, and worker
   microVMs are useful for a task.
4. Add an ontological topology that gives the planner semantic understanding
   without making semantic similarity, an AppView, or AI output into
   authorization.
5. Reuse useful AT Protocol distributed-systems ideas for schema, strong
   references, provenance, replay, projection, and optional federation while
   keeping AT Protocol outside the synchronous `mvm` execution and security
   path.

The design is intentionally strict. A benign, confused, prompt-injected, or
malicious controller must be able to consume at most the finite partition
already assigned to its workflow. It must never be able to grant itself more
microVMs, more resident warm capacity, more memory, more CPU, more external
cost, more secrets, more network reach, or more delegation depth.

## 2. Source-tree findings and standing constraints

The current `mvm` tree already contains much of the required mechanism. The
new work should compose it rather than establish a second runtime.

### 2.1 Existing decisions that remain authoritative

- `specs/adrs/001-microvm-security-posture.md` establishes the hardware-backed
  isolation model, one workload per guest, signed-plan guarantees, default-deny
  networking, host-service binding, secret containment, and the claim ledger.
- `specs/adrs/014-signed-audited-execution-plans.md` requires every boot to be
  represented by a typed, signed, replay-protected, audited `ExecutionPlan`.
- `specs/adrs/020-host-services-broker.md` provides a guest-to-host service
  broker with channel-derived workload identity, per-VM bindings, bounded
  frames, and parser/key-holder process separation.
- `specs/adrs/022-target-architecture.md` requires role-named crates, explicit
  process boundaries, a decreasing trust gradient, and no authority below its
  proper tier.
- `specs/adrs/031-serialization-crypto-storage-selection.md` keeps the core
  wire, crypto, and storage substrate on minimal in-tree primitives and places
  relational fleet state in `mvmd`, not `mvm`.
- `specs/adrs/035-workload-stream-plane.md` provides bounded, redacted,
  hash-chained workload streams and a plan-bound input path. It also defines
  host-mediated stream edges without guest-to-guest addressing.
- `specs/adrs/037-mvmd-only-production-launch.md` states that production launch
  authority belongs to authenticated `mvmd`; this document proposes a narrow
  amendment so `mvmd` can delegate a bounded child-launch capability without
  making a controller a fleet issuer.
- `specs/adrs/040-node-to-node-transport.md` and
  `specs/adrs/041-node-control-api.md` split fleet issuance from local node
  verification and reject peer-established trust roots.
- `specs/adrs/042-single-flow-vsock-networking.md` keeps one host-mediated
  flow-aware networking path and rejects multiple production network stacks.

### 2.2 Existing implementation seams to reuse

- `mvm-contract::stream::edge` already gives consumers plan-local bindings
  rather than VM addresses, defaults to redacted and lossy behavior, and
  refuses duplicate bindings, unacknowledged raw edges, and stdin contention.
- `mvm-contract::stream::topology::validate` already refuses cycles and fan-in
  and returns flow order. It explicitly assigns binding resolution to `mvmd`
  and refusal to `mvm`.
- Plan 296 already states the intended split: `mvm` ships the safe stream-edge
  mechanism; `mvmd` declares the graph and resolves bindings.
- The warm-pool substrate already has exact compatibility keys, template
  identity, cold/optional/required warm modes, typed refusal reasons,
  resident and saved-state standbys, claim leases, prewarm requests, and
  backend capability reporting.
- `WarmLease` already enforces the security-correct rule that a used child is
  destroyed and fresh clean capacity is replenished. Mutated workload state is
  never returned to a shared warm pool.
- Plan 308 separates workload grants from a host- or fleet-controlled ceiling
  and already recognizes that host-wide resource admission must be independent
  of plan-authored grants.

### 2.3 Verified limits and incomplete surfaces

- The `mvm` half of fleet verification exists, but the `mvmd` issuer and its
  current source tree were not available through the connected repository view
  used for this research. `mvmd` internals below are therefore recommendations,
  not claims about current code.
- The stream-edge primitives are deliberately dormant in `mvm`; a fleet caller
  must resolve and validate the complete graph.
- The warm service has a strong local substrate, but workflow-owned dynamic
  desired capacity, subtree accounting, and AI-facing authorization do not yet
  exist.
- Host admission budgeting remains a prerequisite. A controller-facing launch
  path must not ship while live-workflow aggregate accounting can fail open.
- Direct workload execution must not incur workflow storage, semantic indexing,
  graph validation, controller leases, or mailbox startup.

## 3. Core product model

### 3.1 One workload per microVM remains the atomic unit

```text
Single-workload microVM
├── one signed ExecutionPlan
├── one workload identity
├── one entrypoint/workload
├── one resource envelope
├── one network and host-service policy
└── one audited lifecycle
```

Everything else is composition:

```text
Direct workload
    = one single-workload microVM

Workflow worker
    = one single-workload microVM
    + workflow membership
    + admitted mailbox/stream/artifact bindings

Workflow controller
    = one single-workload microVM
    + workflow membership
    + admitted communication bindings
    + delegated microVM lifecycle authority
    + optional AI planner
```

There is no separate nested-hypervisor controller VM and no multi-workload
swarm guest. The workflow layer never weakens one-guest-one-workload.

### 3.2 Four operating combinations

The direct/workflow choice and local/fleet authority are independent:

| Execution topology | Local `mvm` authority | Fleet `mvmd` authority |
| --- | --- | --- |
| Direct | User launches one development workload on one host | `mvmd` places and launches one production workload |
| Workflow | A local controller launches local development workers | A controller exercises `mvmd`-rooted delegated production authority across one or more nodes |

All four may coexist on one host. Authority domains never cross implicitly.

### 3.3 Per-plan states

| Workflow membership | Lifecycle delegation | Meaning |
| --- | --- | --- |
| Absent | Absent | Direct workload |
| Present | Absent | Workflow worker |
| Present | Present | Workflow controller |
| Absent | Present | Invalid; admission refuses |

AI configuration is a third, independent dimension. An AI-enabled direct
workload remains unable to launch children unless its plan also contains valid
workflow membership and lifecycle delegation.

## 4. Goals and non-goals

### 4.1 Goals

- Preserve direct `machine run`, `invoke`, and fleet single-machine launch.
- Give controllers real authority to cause exact admitted children to launch.
- Keep all hypervisor and host authority outside the controller guest.
- Allow AI to plan across tools, services, models, connectors, and microVMs.
- Compile semantic possibilities into finite exact execution bindings.
- Enforce workflow, tenant, and host safety limits transactionally.
- Scale clean capacity between cold, parked, resident-warm, claimed, and
  running states.
- Support structured bidirectional communication without direct guest
  addressing.
- Support standalone local workflows and distributed `mvmd` workflows through
  one guest-facing contract.
- Produce independently verifiable workflow lineage and receipts.
- Make formal invariants and negative witnesses part of the implementation.

### 4.2 Non-goals

- Nested virtualization inside the controller.
- A guest-visible hypervisor API.
- Arbitrary images, host paths, VMM flags, or backend choice from AI output.
- Returning a used child to shared warm capacity.
- Universal guest-to-guest IP networking as a prerequisite.
- Exactly-once distributed task execution.
- Treating AI output, embeddings, ontology edges, labels, CIDs, or AT records as
  authority by themselves.
- Replacing the chain-signed `mvm` audit log with an AT repository.
- Putting a PDS, relay, AppView, live DID resolution, or AT publication on the
  boot, packet, secret-release, or child-launch critical path.

## 5. Terminology

- **Workflow** — one admitted orchestration domain with an immutable identity,
  a succession of graph revisions, budgets, controller policy, and retention.
- **Logical node** — a stable role in the workflow graph.
- **Node attempt** — one immutable attempt to run a logical node. Retries
  create new attempts.
- **Controller** — a workflow node whose plan carries lifecycle delegation.
- **Worker** — a workflow node without lifecycle delegation.
- **Template** — an immutable, digest-bound workload definition from which a
  child plan is derived.
- **Action binding** — an opaque plan-local handle for one exact tool, service,
  model, connector, or template operation.
- **Constraint snapshot** — a finite signed authorization artifact compiled
  from policy, ontology, trusted facts, ceilings, revocations, and templates.
- **Planning snapshot** — a controller-specific, AI-readable projection of the
  legal action set, topology, remaining budget, and semantic metadata.
- **Authority graph** — who created, supervises, cancels, or delegates to whom.
- **Dataflow graph** — which output feeds which input.
- **Causal graph** — which message, result, approval, or decision caused a
  later event.
- **Resident warm parent** — clean authority-free VMM capacity kept resident.
- **Parked parent** — clean saved-state capacity with no live VMM process.
- **Private actor checkpoint** — state belonging to one logical actor, never
  shared as generic warm capacity.

## 6. The controller has real lifecycle authority

The controller needs more than an advisory `propose_spawn` API. If its plan
contains an admitted lifecycle binding, a valid `launch_child` command is
sufficient authority to cause the host to launch the child.

The controller may be authorized for a closed set of operations:

```rust
pub enum LifecycleAction {
    Launch,
    Release,
    Terminate,
    Pause,
    Resume,
    Checkpoint,
    Restore,
    SetCapacityTarget,
    CancelDescendant,
    ObserveDescendant,
}
```

The controller does not receive the implementation objects behind those
operations. It never gets `/dev/kvm`, an HVF VM object, a libkrun context, a
Firecracker API socket, a host PID, a Unix socket path, a raw `VmBackend`, or a
signing key.

The host is not an AI reviewer. For each typed request it performs exact
verification and returns one of a closed set of outcomes:

```text
Succeeded
RefusedByGrant
TemplateNotAuthorized
BudgetExceeded
RateLimited
ApprovalRequired
InvalidLifecycleTransition
NoWarmCapacity
BackendCapabilityMissing
StaleControllerGeneration
OperationalFailure
```

### 6.1 Minimal controller request

```rust
pub struct LaunchChildRequest {
    pub template: TemplateBinding,
    pub input_artifacts: BoundedVec<ArtifactRef>,
    pub reply_binding: Option<BindingId>,
    pub launch_mode: LaunchMode,
    pub idempotency_key: IdempotencyKey,
}
```

The request does not carry host-path-bearing launch configuration.

### 6.2 Opaque actor handle

```rust
pub struct ActorHandle {
    pub workflow_id: WorkflowId,
    pub logical_node_id: WorkflowNodeId,
    pub attempt_id: AttemptId,
    pub boot_id: BootId,
    pub controller_generation: u64,
    pub input_binding: Option<BindingId>,
    pub output_binding: BindingId,
    pub mailbox_binding: BindingId,
    pub handle_nonce: HandleNonce,
}
```

The guest never targets a lifecycle operation with a raw `VmId`. The host
resolves the opaque handle within tenant, authority-domain, workflow, attempt,
boot, and generation scope.

### 6.3 No promotion in place

A direct workload or worker cannot acquire controller authority by sending a
message to the host. Authority changes require a newly admitted plan and a new
boot/attempt.

Allowed:

```text
operator or mvmd admits a controller template
→ launches a new controller attempt
```

Forbidden:

```text
running direct VM
→ asks host to become a controller
```

The same rule applies when a controller wants a worker to become a recursive
controller. It must launch a separately admitted child-controller template.

## 7. Authorization is an intersection, never a union

A controller command is executable only inside all independent limits:

```text
effective_child_authority =
    HostSafetyCeiling
    ∩ TenantCeiling
    ∩ WorkflowConstraintSnapshot
    ∩ ControllerLifecycleGrant
    ∩ TemplateLaunchCeiling
    ∩ RemainingTransactionalBudget
```

No field supplied by the controller can widen this intersection.

### 7.1 Host safety ceiling

Established by the local operator or node policy:

```rust
pub struct HostSafetyCeiling {
    pub max_all_workflow_vms: u32,
    pub max_resident_vmm_processes: u32,

    pub minimum_free_memory_mib: u64,
    pub maximum_reserved_memory_mib: u64,
    pub maximum_reserved_cpu_millicores: u64,

    pub minimum_free_disk_bytes: u64,
    pub maximum_snapshot_bytes: u64,
    pub maximum_artifact_bytes: u64,

    pub maximum_open_fds: u64,
    pub maximum_host_sockets: u64,
    pub maximum_vsock_channels: u64,

    pub maximum_launches_per_second: u32,
    pub maximum_checkpoint_ops_per_minute: u32,
    pub fair_share: FairSharePolicy,
}
```

The controller cannot inspect or change global capacity. It may receive a
coarse `HostCapacityUnavailable` refusal and its own remaining quota.

### 7.2 Tenant ceiling

Owned by `mvmd` in fleet mode or a local authority in standalone mode. It
prevents multiple workflows belonging to one tenant from collectively
exceeding the tenant's admitted reach.

### 7.3 Workflow constraint snapshot

A finite signed artifact whose digest is bound into every controller and child
plan:

```rust
pub struct WorkflowConstraintSnapshot {
    pub workflow_id: WorkflowId,
    pub tenant_id: TenantId,
    pub revision: u64,

    pub valid_from: Timestamp,
    pub valid_until: Timestamp,
    pub revocation_epoch: u64,

    pub controller_policy: ControllerPolicy,
    pub templates: BoundedVec<TemplateLaunchCeiling>,

    pub max_live_workload_vms: u16,
    pub max_resident_vmm_slots: u16,
    pub max_total_attempts: u32,
    pub max_concurrent_launches: u16,
    pub max_launches_per_window: RateLimit,

    pub max_depth: u8,
    pub max_controllers: u8,
    pub max_children_per_controller: u16,
    pub max_graph_revisions: u32,

    pub max_resident_warm: u16,
    pub max_parked_snapshots: u16,
    pub max_private_actor_checkpoints: u16,

    pub max_memory_mib: u64,
    pub max_cpu_millicores: u64,
    pub max_disk_bytes: u64,
    pub max_artifact_bytes: u64,
    pub max_mailbox_bytes: u64,
    pub max_network_bytes: u64,
    pub max_external_cost_microunits: u64,

    pub max_open_fds: u32,
    pub max_host_sockets: u32,
    pub max_vsock_channels: u32,

    pub workflow_deadline: Timestamp,

    pub ontology_digest: Digest,
    pub ruleset_digest: Digest,
    pub compiler_version: CompilerVersion,
    pub issuer_key_id: KeyId,
    pub snapshot_digest: Digest,
    pub signature: Signature,
}
```

Eventually consistent facts may influence the next snapshot. They never modify
the current snapshot in place.

### 7.4 Controller lifecycle grant

The controller plan contains a boot-bound delegation:

```rust
pub struct WorkflowLifecycleGrant {
    pub workflow_id: WorkflowId,
    pub controller_attempt_id: AttemptId,
    pub controller_boot_id: BootId,
    pub controller_generation: u64,

    pub permitted_templates: BoundedVec<TemplateBinding>,
    pub permitted_actions: BoundedSet<LifecycleAction>,

    pub subtree_budget: WorkflowBudget,
    pub max_depth: u8,
    pub max_children: u16,

    pub constraint_snapshot_digest: Digest,
    pub valid_until: Timestamp,
}
```

This grant is non-transferable because the host derives caller identity from
the channel and verifies attempt, boot, plan digest, and generation.

### 7.5 Template launch ceiling

```rust
pub struct TemplateLaunchCeiling {
    pub binding: TemplateBinding,
    pub template_digest: Digest,

    pub max_live_instances: u16,
    pub max_total_attempts: u32,
    pub max_resident_warm: u16,
    pub max_parked: u16,

    pub fixed_memory_mib: u32,
    pub fixed_cpu_grant: CpuGrant,
    pub fixed_wall_clock: Duration,

    pub allowed_launch_modes: BoundedSet<LaunchMode>,
    pub input_schema_digest: Digest,
    pub output_schema_digest: Digest,

    pub child_capability_ceiling: CapabilitySet,
    pub child_egress_ceiling: EgressPolicy,
    pub child_secret_ceiling: SecretBindingSet,
    pub child_filesystem_ceiling: FilesystemPolicy,
    pub child_tool_ceiling: ToolPolicy,

    pub child_may_delegate: bool,
}
```

The launch path resolves the binding to this exact host-held definition. It
never deserializes a guest-originated `VmStartConfig`.

## 8. Transactional resource accounting

Static ceilings alone do not prevent two concurrent requests from consuming
the same final capacity. A durable reservation ledger tracks the mutable
remaining budget.

```rust
pub struct WorkflowReservation {
    pub live_workload_vms: u16,
    pub resident_vmm_slots: u16,
    pub total_attempts_consumed: u32,
    pub launches_in_flight: u16,

    pub resident_warm: u16,
    pub parked_snapshots: u16,
    pub private_checkpoints: u16,

    pub memory_reserved_mib: u64,
    pub cpu_reserved_millicores: u64,
    pub disk_reserved_bytes: u64,
    pub artifact_bytes_consumed: u64,
    pub mailbox_bytes_consumed: u64,
    pub network_bytes_consumed: u64,
    pub external_cost_consumed: u64,

    pub open_fds: u32,
    pub host_sockets: u32,
    pub vsock_channels: u32,
}
```

### 8.1 Atomic reservation rule

```text
validate every dimension
→ reserve every dimension in one transaction
→ record durable lifecycle intent
→ begin plan derivation and launch
```

If any dimension cannot be reserved, nothing is reserved and no expensive
launch side effect begins.

### 8.2 Replenishing and non-replenishing dimensions

Resources normally released after confirmed teardown:

```text
live VM slots
resident VMM slots
reserved memory
active CPU share
open FDs
host sockets
vsock channels
```

Budgets that normally do not replenish during a workflow:

```text
total launch attempts
total network bytes
total external cost
total artifact bytes retained
total graph revisions
cumulative repeated-denial allowance
```

`max_total_attempts` is essential. A controller must not stay under two live
VMs while launching and terminating millions of children.

### 8.3 One child per launch command

The initial API launches one child per idempotent request. It does not accept
an unbounded batch count.

An AI asking for five hundred workers must encounter the limits incrementally
and cheaply. A refusal happens before child plan signing, warm-pool claim, VMM
start, state-directory creation, large artifact preparation, or substantial
memory commitment.

### 8.4 Idempotency

One workflow-scoped idempotency key maps to one durable lifecycle transaction:

```text
already running  → return existing ActorHandle
in progress      → return same attempt and state
terminal failure → return same terminal receipt
```

The system should claim at most one live child effect per idempotency key. It
must not claim exactly-once distributed execution.

### 8.5 Release rule

A reservation is released only after the VMM is confirmed dead, active leases
are closed, live host resources are reaped, and the terminal lifecycle state
is durably recorded. A stop request alone is not proof of release.

## 9. AI-planned topology under compiled authority

### 9.1 Three independent questions

```text
SHOULD the action be used?
    AI planner or deterministic planner

MAY the action be used?
    Signed constraint snapshot and exact binding

CAN the action be used now?
    Transactional budget, backend support, health, and placement
```

The executable set is the intersection. AI cannot promote an unavailable or
unauthorized action.

### 9.2 Controller planning snapshot

```rust
pub struct ControllerPlanningSnapshot {
    pub workflow_id: WorkflowId,
    pub controller_attempt_id: AttemptId,
    pub controller_boot_id: BootId,
    pub controller_generation: u64,
    pub workflow_revision: u64,

    pub ontology_digest: Digest,
    pub ruleset_digest: Digest,
    pub constraint_snapshot_digest: Digest,

    pub executable_actions: BoundedVec<ActionDescriptor>,
    pub approval_required_actions: BoundedVec<ActionDescriptor>,
    pub requestable_capabilities: BoundedVec<CapabilityDescriptor>,

    pub topology: BoundedVec<WorkflowNodeSummary>,
    pub remaining_budget: RemainingBudgetSummary,
    pub availability: BoundedVec<ActionAvailability>,

    pub valid_until: Timestamp,
    pub snapshot_digest: Digest,
    pub issuer_key_id: KeyId,
    pub signature: Signature,
}
```

This is a finite world model for one planning epoch. For large catalogs the
controller can issue bounded, paginated read-only queries pinned to the same
snapshot digest. It never receives unrestricted fleet inventory or a mutable
global AppView as authority.

### 9.3 Unified action vocabulary

```rust
pub enum ActionTarget {
    LocalTool { tool_binding: ToolBinding },
    HostService {
        service_binding: ServiceBinding,
        verb: ServiceVerb,
    },
    ChildMicroVm { template_binding: TemplateBinding },
    ModelService { model_binding: ModelBinding },
    ExternalConnector { connector_binding: ConnectorBinding },
}
```

```rust
pub struct ActionDescriptor {
    pub semantic_id: SemanticId,
    pub descriptor_digest: Digest,
    pub target: ActionTarget,

    pub roles: BoundedVec<SemanticRole>,
    pub input_schema_digest: Digest,
    pub output_schema_digest: Digest,

    pub side_effect_class: SideEffectClass,
    pub risk_class: RiskClass,
    pub data_policy: ActionDataPolicy,

    pub maximum_cost: ActionCost,
    pub expected_latency: LatencyClass,
    pub idempotency: IdempotencyClass,

    pub required_capabilities: CapabilitySet,
    pub required_attestations: AttestationSet,
    pub opaque_binding: ActionBinding,
}
```

Tools, services, model calls, external connectors, and child microVMs are
semantically comparable but execute through different typed mechanisms.

### 9.4 Four action statuses

| Status | Controller behavior |
| --- | --- |
| Executable | May invoke within current budget |
| Approval required | May request the exact action and wait for a bound approval |
| Requestable | May explain the missing need; cannot execute it |
| Invisible | Not present in the planning view |

A `CapabilityNeed` is advisory. It can cause a parent authority to compile a
replacement signed snapshot, but it cannot mutate the current one.

### 9.5 AI configuration

```rust
pub struct AiPlannerConfig {
    pub model: ModelBinding,
    pub inference_mode: InferenceMode,

    pub maximum_planning_steps: u32,
    pub maximum_inference_calls: u32,
    pub maximum_input_tokens: u64,
    pub maximum_output_tokens: u64,
    pub maximum_context_bytes: u64,
    pub maximum_external_cost_microunits: u64,
    pub maximum_planning_wall_clock: Duration,

    pub context_policy: PlannerContextPolicy,
    pub required_output_schema_digest: Digest,
}
```

Possible model deployments include a pinned embedded model, a dedicated model
microVM, an admitted host model service, or an external connector with explicit
egress, destination, cost, credential, and data-classification policy. In all
cases model output is untrusted planner output.

### 9.6 Deterministic runtime around the model

```text
controller microVM
├── deterministic controller runtime
│   ├── planning snapshot client
│   ├── mailbox client
│   ├── action-schema validator
│   ├── idempotency manager
│   ├── local budget display
│   └── AI adapter
└── AI planner
```

The model emits a typed `PlannerDecision`; natural language is never sent to
host lifecycle dispatch.

### 9.7 Trust-tagged planning context

Planner context must structurally distinguish:

```text
signed planning snapshot
authoritative workflow state
trusted attestations
operator/controller instructions
mailbox messages
workload output
external artifacts
```

Child output and external artifacts are untrusted data even when included in a
prompt. Prompt injection may cause poor planning, but the host still enforces
the same finite capability and resource envelope.

## 10. Three graphs, not one swarm DAG

### 10.1 Authority and supervision graph

This graph answers who created, supervises, cancels, or delegates to whom.

Required shape:

```text
rooted forest
one authority parent per attempt
acyclic
boot- and generation-bound
```

A logical node may have multiple attempts over time, but every attempt has one
explicit authority origin.

### 10.2 Dataflow graph

This graph connects one producer's output or artifact to one consumer's input.

Required properties:

```text
DAG per committed revision
one stdin writer
fan-out allowed
fan-in requires an explicit merge workload
cycles refused before boot
```

The existing stream-edge rules remain authoritative. A guest names a
consumer-local binding, never another guest or physical node. The host resolves
the binding between two independent channels.

### 10.3 Causal event graph

This graph links:

```text
request → admission result
message → reply
planner decision → lifecycle command
lifecycle command → child attempt
child result → graph patch
approval request → approval result
```

Child-to-parent communication is a new event with `correlation_id` and
`causation_id`; it is not a reverse stdin edge and does not create a dataflow
cycle.

### 10.4 Iteration through graph epochs

Agent workflows need iteration, but the stream graph should remain acyclic.
Represent iteration as successive graph revisions:

```text
revision 0 / epoch 0
    planner → researchers → reducer

reducer result causes a new committed revision

revision 1 / epoch 1
    verifier → remediation → final reviewer
```

A `GraphPatch` is an append-only compare-and-swap mutation:

```rust
pub struct GraphPatch {
    pub workflow_id: WorkflowId,
    pub expected_revision: u64,
    pub previous_graph_digest: Digest,
    pub controller_generation: u64,
    pub idempotency_key: IdempotencyKey,

    pub add_nodes: BoundedVec<NodeDeclaration>,
    pub add_edges: BoundedVec<EdgeDeclaration>,
    pub cancel_nodes: BoundedVec<WorkflowNodeId>,
    pub seal_epoch: bool,
}
```

Running plans are immutable. A patch binds predeclared input and output slots
or creates new attempts under new plans; it does not rewrite an already running
child's authority.

## 11. Lifecycle and capacity states

The workflow layer must distinguish runtime activity from reusable capacity.

| State | VMM process | Resident memory | Workload authority | Purpose |
| --- | ---: | ---: | ---: | --- |
| Cold template | No | No | No | Immutable artifacts only |
| Parked clean parent | No | No | No | Saved clean capacity |
| Resident warm parent | Yes, paused/preloaded | Yes | No | Fast claimable capacity |
| Claimed child | Yes | Yes | Being freshly bound | Host channels and identity are arming |
| Running child | Yes | Yes | Yes | Active workload |
| Private actor checkpoint | No | No | Bound to one logical actor | Stateful resume only |

### 11.1 Clean shared capacity contains no workload authority

A reusable parent must carry no tenant-specific workload plan, raw secrets,
workload volumes, ports, per-launch credentials, destinations, mailbox
payloads, or child authority. Every claim creates fresh identity and host
channels and supplies the child's own signed plan.

### 11.2 A used child never returns to the shared pool

Forbidden:

```text
Running child
    → shared resident warm parent
```

Required:

```text
Running child
    → close input
    → flush and archive mailbox/stream output
    → seal evidence
    → stop and destroy child
    → optionally replenish fresh clean capacity
```

This preserves the current `WarmLease` security property and prevents secret,
model-context, filesystem, credential, flow, or kernel state from crossing
workload boundaries.

### 11.3 Stateful actor suspension uses a private checkpoint

```text
Running actor A
    → quiesce
    → checkpoint A
    → stop A
    → private checkpoint A

Later:
    private checkpoint A
    → restore logical actor A as a new attempt/boot
    → fresh boot identity and channel keys
    → reissued credentials and grants
```

The checkpoint cannot be claimed by another logical actor or converted into a
generic warm parent.

### 11.4 Desired capacity

The controller may be granted `SetCapacityTarget`:

```rust
pub struct CapacityTarget {
    pub template: TemplateBinding,
    pub resident_warm: u16,
    pub parked: u16,
    pub idle_ttl: Duration,
    pub parked_ttl: Duration,
    pub idempotency_key: IdempotencyKey,
}
```

The effective target is:

```text
min(
    controller request,
    template ceiling,
    workflow ceiling,
    tenant ceiling,
    host pressure policy
)
```

Host pressure may reduce warm capacity below the controller's preference unless
a separate operator-defined guaranteed reservation exists. A controller cannot
keep the host exhausted by repeatedly requesting warm capacity.

### 11.5 Reconcile, do not unconditionally replenish

The existing release path can replenish a fresh parent after consuming a warm
lease. Workflow-owned dynamic capacity should refine this into:

```text
release used child
→ destroy child
→ read desired clean-capacity target
→ replenish only when clean capacity is below target
→ otherwise remain parked or cold
```

The reconciler, not a live AI loop, owns TTL and pressure-driven transitions.
The controller can therefore be paused or cold while the host continues
honoring the last admitted desired state.

### 11.6 Idle policies

```rust
pub enum IdleAction {
    KeepRunning,
    Pause,
    CheckpointAndStop,
    Stop,
}

pub struct IdlePolicy {
    pub idle_after: Duration,
    pub action: IdleAction,
    pub keep_template_resident_warm: u16,
    pub keep_template_parked: u16,
}
```

Host-owned events and monotonic timers enforce the policy. The controller may
choose an admitted policy; it does not need to remain awake to run the timer.

## 12. Communication planes

The swarm's “network” is initially a typed host-mediated overlay, not a
workload-visible IP network.

| Plane | Purpose | Semantics |
| --- | --- | --- |
| Control | Launch, stop, capacity, status, approval, graph mutation | Typed, capability-bound, replay-protected |
| Mailbox | Structured tasks, messages, replies, results | At-least-once, idempotent, bounded, optionally durable |
| Stream | stdout/stderr and producer-output-to-consumer-input | Unidirectional DAG, sequence and gap aware |
| Artifact | Large files, datasets, model output, checkpoints | Immutable content-addressed objects and signed manifests |

### 12.1 Logical bindings, never guest addresses

Guests receive plan-local opaque bindings such as:

```text
planner-parent
reviewer
final-artifact
result-mailbox
```

The host maps those bindings to local or remote routes. A guest does not learn
a physical node, host socket, raw CID, or sibling `VmId`.

### 12.2 Mailbox envelope

```rust
pub struct MailboxEnvelope {
    pub protocol_version: u32,
    pub workflow_id: WorkflowId,
    pub workflow_revision: u64,

    pub message_id: MessageId,
    pub recipient_binding: BindingId,
    pub correlation_id: CorrelationId,
    pub causation_id: Option<MessageId>,
    pub reply_to: Option<MessageId>,

    pub schema: SchemaRef,
    pub payload_digest: Digest,
    pub payload: PayloadLocation,

    pub expires_at: Timestamp,
    pub idempotency_key: IdempotencyKey,
}
```

The host stamps sender tenant, workflow, attempt, boot, plan digest, and
controller generation from the channel. A sender field supplied by the guest is
metadata, never identity.

### 12.3 Mailbox guarantees

- Ordered per admitted sender/recipient route, not globally.
- At-least-once delivery with durable deduplication.
- No exactly-once execution claim.
- Durable acknowledgement cursor.
- Explicit message, payload, queue, workflow, and disk limits.
- TTL and expiration.
- `MailboxFull` instead of silent loss.
- Dead-letter storage only when explicitly admitted and bounded.
- Payload-free lifecycle audit containing IDs, digests, sizes, and outcomes.
- No guest access to the host database, SQL, filesystem path, or query
  language.
- Archive and seal when the workflow closes; verify the archive before clearing
  active queue state.

### 12.4 Transactional commands versus lifecycle facts

Commands and mutable coordination require an authoritative transaction:

```text
claim task
renew lease
acknowledge message
cancel task
request child run
stop machine
send stdin
transfer ownership
```

Only after commit may the system publish facts such as:

```text
task claimed
message accepted
message acknowledged
child run admitted
child run rejected
artifact produced
constraint violated
run quarantined
```

An append/replay semantic stream is a projection of committed authority, not
the command scheduler.

### 12.5 stdout and stderr are not control messages

Raw workload output may contain prompt injection, terminal escapes, fake JSON,
secret material, huge binary payloads, or text asking the controller to launch
more workers. It remains untrusted data.

Operational results that drive privileged behavior use schema-bound mailbox
messages. The controller may inspect raw streams for reasoning and diagnostics,
but the host never turns stdout into a lifecycle command.

### 12.6 Existing stream rules remain

- Redaction happens at the established seam.
- Sequence numbers, hash chains, gaps, and sealed roots remain intact.
- The producer is not stalled by a slow consumer.
- `stdin` has one writer.
- Fan-in requires an explicit merge stage.
- A broken reliable edge fails loudly rather than silently becoming lossy.
- A broken edge does not reconnect across a consumer restart without a new
  workflow decision.

### 12.7 Artifact transfer

Large values move by immutable artifact reference rather than mailbox body or
stdio. A manifest records producer attempt and boot, exact bytes, schema,
classification, derivation inputs, scanner attestations, and retention.

## 13. Guest-host session security

The lifecycle and mailbox surfaces are high-value guest-reachable channels.
They should use a per-boot authenticated encrypted session with no plaintext
fallback.

A session binds:

```text
protocol version
boot ID
plan digest
tenant
workflow
channel purpose
controller generation
send and receive sequence
key generation
```

Requirements:

- Established authenticated encryption, not custom cryptography.
- Separate traffic keys for lifecycle, mailbox, streams, and broker services.
- Boot- and purpose-bound key derivation.
- Monotonic sequence and replay protection.
- Strict version and cipher negotiation with no downgrade.
- Explicit key rotation and nonce-exhaustion behavior.
- Handshake and frame-size limits.
- Secrets held by the guest agent and host endpoint, not the workload process.
- Zeroization on teardown.
- Negative tests that plaintext and stale-session frames are refused.

The host normally terminates and re-encrypts mediated traffic. Fully opaque
guest-to-guest encryption would prevent host-side schema validation,
redaction, routing policy, and audit attribution and is not the default model.

This requirement should be reconciled through a dedicated ADR because older
broker and encryption decisions describe weaker topology-based or signed-frame
assumptions.

## 14. Local authority and `mvmd` authority

One guest-facing contract has two implementations.

```rust
pub trait WorkflowAuthority {
    fn launch_child(
        &self,
        caller: ActorIdentity,
        request: LaunchChildRequest,
    ) -> Result<LaunchReceipt, WorkflowRefusal>;

    fn commit_graph_patch(
        &self,
        caller: ActorIdentity,
        patch: GraphPatch,
    ) -> Result<GraphRevisionReceipt, WorkflowRefusal>;

    fn send_message(
        &self,
        caller: ActorIdentity,
        message: OutboundMessage,
    ) -> Result<MessageReceipt, WorkflowRefusal>;

    fn set_capacity_target(
        &self,
        caller: ActorIdentity,
        target: CapacityTarget,
    ) -> Result<CapacityReceipt, WorkflowRefusal>;

    fn cancel_descendant(
        &self,
        caller: ActorIdentity,
        target: ActorHandle,
    ) -> Result<CancelReceipt, WorkflowRefusal>;
}
```

### 14.1 Standalone local workflows

A `LocalWorkflowAuthority`:

- Uses the existing local signing and plan-admission path.
- Places all children on the current host.
- Resolves bindings locally.
- Owns a local transactional workflow journal and reservation ledger.
- Uses local mailbox, stream, artifact, warm-service, and backend mechanisms.
- Refuses any remote-placement requirement.
- Starts lazily only for workflow launches.
- Treats all local controller and child launches as development posture under
  the standing production-authority rule.

### 14.2 Fleet workflows

Recommended `mvmd` responsibilities:

- Fleet and tenant identity.
- Workflow root and canonical graph revision.
- Constraint and planning snapshot compilation.
- Controller generation and fencing leases.
- Fleet-wide and tenant-wide resource reservation.
- Template resolution and placement.
- Issuance of node-verifiable launch and route grants.
- Cross-node mailbox and artifact routing.
- Node loss, controller failover, orphan reconciliation, and revocation.
- Semantic records, provenance projections, AppViews, and optional AT
  publication.

The executing `mvm` node independently verifies every grant. A source node or
controller is a peer, not an authority over the destination node.

### 14.3 Production delegation amendment

The production rule should become:

> Every production launch is rooted in authenticated `mvmd` authority. `mvmd`
> may issue a narrow, boot-bound workflow lifecycle delegation to an admitted
> controller. A resulting child launch is production only when the executing
> node verifies the full delegation chain, exact template, constraint snapshot,
> controller generation, reservation, plan, and expiry.

This does not make the controller a signer, fleet issuer, placement authority,
or ceiling owner.

### 14.4 Distributed workflows do not require general L3 first

Control and mailbox routing can use:

```text
controller guest
→ local encrypted vsock/session
→ source node workflow gateway
→ authenticated node/control-plane transport
→ destination node workflow gateway
→ destination guest session
```

Large data uses content-addressed artifacts. Cross-host live streams can follow
with bounded relay semantics. General guest IP connectivity remains subject to
the separate cross-node networking prerequisites.

### 14.5 Partition behavior

Safe defaults:

- Existing children continue only through their admitted deadlines and lease
  policy.
- New graph mutations and launches fail closed after controller lease expiry.
- Newer fencing generations invalidate older controllers immediately at the
  host.
- Local mailbox buffering is encrypted and quota-bounded.
- No timestamp-only split-brain merge.
- Safety is preferred over availability for launch, cancellation, secret
  release, and authority mutation.

## 15. Process and privilege separation

The guest-facing parser must not hold signing keys or backend lifecycle
authority.

```text
controller guest
    │ bounded encrypted request
    ▼
workflow ingress/parser role
    - parses hostile guest bytes
    - derives caller from channel
    - holds no signer key
    - holds no VmBackend or VMM handle
    │ normalized bounded DTO
    ▼
workflow admission/reservation role
    - verifies grant, snapshot, generation, template, and budget
    - owns transactional reservation ledger
    - records lifecycle intent
    - accepts no guest sockets
    │ exact launch permit / reservation ID
    ▼
workflow launch role
    - owns backend lifecycle access
    - accepts no guest connections
    - accepts no arbitrary launch config
    - loads host-prepared config by reservation ID
    ▼
existing warm service / VmBackend
```

The launch permit binds:

```text
workflow
controller attempt and boot
controller generation
template digest
child plan digest
reservation ID
idempotency key
expiry
nonce
```

The lifecycle process must not deserialize guest-originated host paths or
`VmStartConfig` values.

External AT/CAR/CBOR/DID ingestion should use another keyless, launch-incapable
process with strict parser limits. Its output is an internal validated DTO or
quarantine result, never a direct launch command.

## 16. AT Protocol's bounded role

### 16.1 Recommendation

Adopt an **AT-shaped internal semantic plane** in `mvmd` before attempting full
AT Protocol compatibility.

This corresponds to the following architecture:

```text
transactional authoritative state
    → durable outbox
    → typed semantic event envelope
    → replayable ordered tenant stream
    → idempotent AppView-style projectors
    → topology/provenance/compliance views
    → optional sanitized AT Protocol bridge
```

Use AT Protocol ideas where they solve real distributed-systems problems:

- Globally namespaced schema identifiers.
- Typed records and event messages.
- Content identifiers for exact record bytes.
- URI-plus-CID strong references.
- Replayable subscription streams with cursors.
- Explicit gap detection and snapshot/resynchronization.
- Idempotent materialized views.
- Authenticated authorship of published records and labels.
- Optional federation and portable public provenance.

Do not make full repository/MST/PDS/relay semantics the internal transactional
scheduler in the first implementation.

### 16.2 Why not full AT Protocol internally first

Full internal AT adoption would introduce repository, MST, CAR/CBOR, DID,
OAuth, relay, AppView, and public-data assumptions before the workflow
transaction model is stable. It would also create a temptation to use
repository commits or a firehose for task claims, leases, launch admission, or
resource reservations—operations that require transactional consistency and
fencing.

The internal system needs first-class answers for:

```text
one winner claims a task
one reservation consumes a final VM slot
one controller generation mutates the graph
one idempotency key maps to at most one live child
one acknowledgement advances a mailbox cursor
```

Those are database and coordination transactions, not repository publication.

### 16.3 Why not export-only as the first and only design

An export-only bridge would avoid risk but would miss the architectural value
of typed semantic records, strong references, durable replay, gap-aware
projectors, and provenance/AppView separation inside `mvmd`.

The recommended middle path captures those useful shapes without forcing an
external protocol into the TCB.

### 16.4 What AT Protocol can represent well

Appropriate optional records include:

```text
com.runmvm.execution.plan
com.runmvm.execution.run
com.runmvm.execution.auditAnchor
com.runmvm.node.descriptor
com.runmvm.machine.instance
com.runmvm.artifact.manifest
com.runmvm.artifact.provenance
com.runmvm.topology.edge
com.runmvm.policy.constraint
com.runmvm.policy.snapshot
com.runmvm.policy.attestation
com.runmvm.agent.definition
com.runmvm.agent.delegation
com.runmvm.agent.task
com.runmvm.agent.messageSummary
```

The publication layer is useful for public or deliberately federated facts,
provenance, templates, attestations, and redacted run summaries.

### 16.5 What AT Protocol must not replace

AT Protocol does not by itself provide the properties required for:

```text
authoritative transactional chronology
distributed locking
lease fencing
exactly-once task execution
immutable forensic history
confidential private mailbox storage
truth of an assertion
authorization
ontology reasoning
constraint enforcement
host admission
packet admission
secret release
```

Repository signatures prove authenticated publication by the repository
identity. They do not prove the assertion is true or authorized.

A CID identifies bytes. It is not an identity, permission, or attestation.

A Lexicon defines syntax and validation shape. It is not a complete ontology or
policy engine.

A label proves that a labeler authored an assertion. Whether the issuer is
trusted and what authorization consequence follows are separate local policy
decisions.

### 16.6 Critical-path prohibition

No immediate boot, child spawn, packet, secret release, local audit
verification, or VMM lifecycle decision may depend on:

```text
PDS availability
relay availability
AppView freshness
online DID resolution
external OAuth
external repository write
public firehose delivery
eventually consistent semantic state
```

This boundary is the central conclusion of the parallel AT Protocol research
brief: AT Protocol may surround and describe the system, but the synchronous
local authority remains `mvm` and the transactional fleet authority remains
`mvmd`.

### 16.7 Optional bridge

```text
mvm / mvmd trusted state
    │ sanitized allowlisted projection
    ▼
keyless mvm-atproto-ingress/egress bridge
    │
    ▼
AT Protocol repository / PDS / relay / AppView
```

Inbound AT records are proposals or publications. Before use they must be:

```text
schema-pinned
record-CID-pinned
publisher-identity verified
artifact bytes fetched and hash verified
mvm-native signatures verified
scanned and classified
admitted by local/fleet policy
compiled into a normal ConstraintSnapshot or template binding
```

An AT record never directly calls `launch_child`.

### 16.8 Revisit conditions

Full protocol compatibility becomes more attractive if all of the following
hold:

- A stable internal semantic record model exists.
- Private-data and permissioned repository assumptions match the deployment.
- A maintained Rust implementation or isolated sidecar passes conformance and
  fuzzing requirements.
- CAR/CBOR/MST parsing can remain outside the runtime TCB.
- A real federation/customer portability requirement justifies the dependency
  and operational cost.

## 17. Semantic layers

The ontological topology is composed of separate layers with explicit trust
transitions.

```text
1. Schema/Lexicon
2. Authenticated facts
3. Typed graph edges
4. Ontology and rules
5. Deterministic constraint compilation
6. Materialized AppViews
7. Local execution enforcement
```

### 17.1 Schema layer

Defines record syntax, identifiers, bounded fields, and versioning. A schema
must not contain hidden policy semantics that only one implementation knows.

### 17.2 Authenticated fact layer

Records who asserted what and the exact bytes of the assertion:

```text
issuer
key ID
record URI
record CID/digest
creation/publication metadata
evidence references
scope
validity
```

Authentication proves authorship, not truth.

### 17.3 Typed graph edge layer

A general edge may describe non-authoritative semantics:

```rust
pub struct TopologyEdge {
    pub subject: StrongRef,
    pub predicate: SemanticPredicate,
    pub object: StrongRef,

    pub issuer: IssuerRef,
    pub evidence: BoundedVec<StrongRef>,

    pub tenant_scope: TenantId,
    pub workflow_scope: Option<WorkflowId>,

    pub node_id: Option<NodeId>,
    pub vm_id: Option<VmId>,
    pub boot_id: Option<BootId>,
    pub plan_digest: Option<Digest>,

    pub valid_from: Timestamp,
    pub valid_until: Option<Timestamp>,
    pub revocation: Option<RevocationRef>,

    pub ontology_digest: Digest,
    pub ruleset_digest: Digest,
}
```

Security-relevant relationships need dedicated record types and validators.
Examples:

```text
DelegationRecord
LaunchAdmissionRecord
ConstraintSnapshotRecord
SecretReleaseAttestation
PeerRouteGrant
ControllerLeaseRecord
```

A generic `topology.edge` is not sufficient for authority-bearing predicates.

### 17.4 Ontology and rules

Define classes, subsumption, compatibility, semantic roles, data
classification, risk, and planner ranking. Rules are versioned and digest
pinned.

Security matching remains exact unless a specific signed rule explicitly
permits a finite expansion. Approximate vector similarity never authorizes.

### 17.5 Constraint compiler

The compiler consumes pinned facts and policy and emits the finite signed
snapshot used by admission. It records:

```text
exact input URI+CIDs or internal strong refs
issuer identities and key IDs
schema digests
ontology digest
ruleset digest
compiler version
effective egress/ingress/filesystem/secret/tool policies
child spawn permissions
delegated capabilities
CPU, memory, disk, time, token, network, and cost budgets
retention and classification
required attestations
validity and revocations
snapshot digest
mvmd/local-authority signature
```

Unknown schema, missing fact, revoked issuer, stale view, expired attestation,
conflicting positive labels, incomplete synchronization, or ontology drift
fails closed for positive authorization.

### 17.6 AppViews

AppViews project committed facts into useful read models:

```text
workflow topology
artifact provenance
compliance status
available action catalog
controller planning snapshot
fleet health
public run summaries
```

An AppView is rebuildable and may be stale. It is not the scheduler or launch
authority.

### 17.7 Execution enforcement

At the boundary, `mvm` verifies exact signed artifacts and finite bindings. It
does not run open-ended ontology reasoning during boot or packet processing.

## 18. Labels and attestations

Potential labels include:

```text
image-approved
image-vulnerable
reproducible-build
sbom-present
pii-detected
secret-like-output
malware-suspected
license-incompatible
human-reviewed
quarantined
artifact-public
artifact-confidential
```

Four questions are always separate:

1. Who authored the assertion?
2. Does policy trust that issuer for this label and scope?
3. Is the assertion actually true?
4. What local authorization consequence follows?

### 18.1 Trust policy

A label trust policy specifies:

```text
which issuers may make positive authorization assertions
which issuers may force quarantine
which labels are advisory only
which labels may only narrow capabilities
quorum/multi-labeler requirements
conflict resolution
expiration
revocation
evidence requirements
```

A safe default is asymmetrical:

- Negative/quarantine labels from a trusted security authority may narrow or
  stop execution quickly.
- Positive labels that widen authority require an explicitly trusted issuer,
  evidence, freshness, and often quorum.
- A workload cannot positively attest to its own trustworthiness.

### 18.2 Isolated labeler microVMs

A scanner runs as an ordinary `mvm` workload and produces evidence and an
unsigned workload assertion through the host broker/mailbox. A separate host
or `mvmd` label-authority role verifies provenance, applies issuer policy, and
signs the final label. The scanner receives neither the labeler signing key nor
an identity that can impersonate another scanner.

## 19. Storage ownership matrix

| Object | Authoritative store | Exact-byte identity | Semantic identity | Signature authority | Retention | AT record |
| --- | --- | --- | --- | --- | --- | --- |
| Signed `ExecutionPlan` | `mvm` admission/audit store; fleet copy in `mvmd` | Plan digest/JCS bytes | Plan/workload identity | Local host or `mvmd`-rooted issuer | Security/audit policy | Optional public/private summary; never replacement |
| Plan admission evidence | Chain-signed local audit; transactional fleet journal | Entry hash/signature | Admission event | `mvm` audit signer | Audit policy | Anchor/summary appropriate |
| Audit entries | Append-only chain-signed local log | Entry bytes/hash | Category/event | `mvm` signer | Rotation/prune policy with accountability | Only anchored digest/summary |
| Transcript records | `mvm` transcript store | Record hash/sequence | Stream/run identity | Hash chain; sealed root anchored in audit | Per signed retention | Raw publication prohibited by default |
| Transcript manifest/root | `mvm` store + audit anchor | Manifest/root digest | Run/stream | `mvm` signer/audit chain | Audit policy | Redacted anchor appropriate |
| stdout/stderr | Bounded stream/transcript | Exact record bytes before/after documented redaction seam | Run/stream | Chain, not per-record signature | Signed retention | Raw public record prohibited |
| Structured trace events | Stream plane | Record digest | Typed event | Chain/audit anchor | Signed retention | Sanitized summaries optional |
| Output artifacts | Content-addressed artifact store | Artifact digest | Artifact URI/schema/classification | Producer provenance + manifest signer | Artifact policy | Manifest/provenance appropriate |
| Build provenance | Build/attestation store | Manifest/evidence digests | Build action | Build/attestation authority | Supply-chain policy | Strong fit |
| OCI/Nix inputs | Existing cache/store | Native digests | Package/source refs | Registry/Nix plus mvm admission | Cache/provenance policy | Reference/manifest fit |
| Snapshots | Local/fleet snapshot store | Snapshot manifest/content digests | Parent/actor checkpoint identity | `mvm` checkpoint/audit signer | TTL/quota/private actor policy | Metadata only; bytes prohibited |
| Mailbox messages | Transactional mailbox store | Envelope/payload digest | Message/correlation ID | Channel-derived sender + host acceptance fact | Workflow policy | Raw private content prohibited; summary facts optional |
| Tasks | Transactional `mvmd`/local workflow DB | Task record digest | Task ID | Workflow authority | Workflow retention | Created/completed fact appropriate |
| Task claims/leases | Transactional authority store | Transaction version/fencing token | Claim/lease ID | `mvmd` or local authority | Active + audit history | Resulting fact only |
| Host inventory | Local node state and `mvmd` inventory | Node report digest | Node identity | Node/control-plane authority | Operational | Sanitized publication only |
| Launch/controller leases | Transactional authority store | Signed lease bytes | Lease ID, generation | `mvmd` or local authority | Short-lived + audit | Public publication inappropriate |
| Topology edges | Workflow DB + semantic log | Record digest | Strong refs/predicate | Issuer appropriate to predicate | Workflow/provenance | Strong fit for sanitized edges |
| Labels | Attestation/semantic store | Signed label bytes | Subject+label+issuer | Labeler authority | Expiry/revocation | Strong fit |
| Constraint snapshots | Transactional policy store; cached by nodes | Snapshot digest | Workflow/revision | `mvmd` or local authority | At least workflow/audit lifetime | Summary/strong ref appropriate; not authority through AT |
| Ontology versions | Immutable ruleset store | Bundle digest | Version/NSID | Ontology authority | Long-lived | Strong fit |
| Public exports | AT bridge/PDS | CID/repository commit | AT URI | Repository identity | Publisher policy | Native target |

The local chain-signed audit remains the forensic source. AT repository current
state and publication history do not silently replace it.

## 20. Identity and key division

Preserve the execution identity:

```rust
pub struct VmInstanceIdentity {
    pub node_id: NodeId,
    pub vm_id: VmId,
    pub boot_id: BootId,
    pub plan_digest: Digest,
}
```

Extend it in workflow contexts with:

```text
tenant
authority domain
workflow ID
logical node ID
attempt ID
controller generation
constraint snapshot digest
```

### 20.1 Appropriate uses of DIDs

DIDs may be useful for long-lived external principals:

```text
organization
tenant/operator
public agent/template publisher
external labeler
mvmd control-plane identity, if operationally justified
```

Avoid assigning a DID and repository to every short-lived VM boot. Ephemeral
boots already need a compact, local, boot-bound identity rather than a public
account abstraction.

### 20.2 Separate proof domains

```text
mvm execution/audit signature
    proves local admission and execution provenance

mvmd issuer signature
    proves fleet authorization, lease, delegation, or constraint snapshot

AT repository signature
    proves authenticated publication by a repository identity

labeler signature
    proves authorship of a semantic assertion

OAuth credential
    authorizes an application to access an AT service

node-channel authentication
    proves the peer node/control-plane channel identity
```

These proofs may reference one another but are never silently substituted.

### 20.3 Key placement

- Guest workloads hold no host, `mvmd`, repository, labeler, or audit signing
  key.
- The guest agent may hold only ephemeral session material required for its
  own boot-bound channel.
- Guest-facing parser processes hold no signing key and no backend authority.
- Launch processes hold no fleet issuer key and accept only exact host-issued
  launch permits.
- Nodes hold verifying material for `mvmd` issuers, not the issuer's signing
  key.
- AT ingest/egress bridges hold only the minimum publication/application keys
  needed for their isolated function.
- Rotation and revocation are key-ID explicit and fail closed. Nodes do not
  try every historical issuer key after an unknown key ID.
- Runtime boot and packet decisions never require live DID resolution.

## 21. Security objective and threat model extension

Adding a guest-reachable lifecycle API necessarily adds attack surface. The
honest security objective is not “no new surface.” It is:

1. Authority blast radius is bounded to exact descendants, actions, templates,
   and validity.
2. Resource blast radius is bounded by transactional workflow, tenant, and host
   ceilings.
3. Data blast radius is bounded by capability, egress, secret, filesystem,
   tool, and classification attenuation.
4. Parser compromise does not yield signer or backend lifecycle authority.
5. Direct workloads receive none of the new authority or resident machinery.

Assume the AI model and controller workload may be irrational, buggy,
prompt-injected, malicious, or fully compromised.

The desired worst case is:

> The compromised controller exercises every action explicitly delegated to it
> and consumes the entire finite workflow partition, after which further
> requests fail cheaply. It cannot enlarge the partition, cross the workflow or
> tenant boundary, or acquire host/hypervisor authority.

## 22. Threat register

| Threat | Example failure | Required control |
| --- | --- | --- |
| Direct hypervisor access | Controller opens KVM/HVF/Firecracker/libkrun interfaces | No device, path, handle, verb, or broker binding; typed workflow API only |
| General launch configuration | AI supplies arbitrary rootfs, kernel, argv, environment, backend, or host path | Exact plan-local template bindings; host-held config only |
| Capability amplification | Parent grants a child authority it lacks | Machine-checked intersection and subset relation across every ancestor |
| Delegation laundering | Parent routes authority through an intermediary | Every descendant checked against root ceiling and complete delegation chain |
| Ambient workflow membership | Any workflow worker can spawn | Separate lifecycle grant; workers receive `NotBound` |
| Authority transfer | Controller copies a bearer token into a mailbox | Channel-derived identity; boot/attempt/generation binding; opaque non-bearer handles |
| Promotion in place | Direct VM asks to become controller | New plan and boot required |
| Spawn bomb | AI repeatedly launches children | Live, resident, total-attempt, concurrent, rate, depth, template, tenant, and host limits |
| Low-live-count churn | Launch/kill loop remains below live limit | Non-replenishing total-attempt and cumulative cost budgets |
| Warm-capacity bomb | Hundreds of paused/preloaded VMMs evade live-worker count | Separate resident-VMM and resident-warm limits; full memory/process/FD accounting |
| Parked-snapshot bomb | Controller parks unlimited saved parents | Parked-count, snapshot-byte, I/O-rate, disk-reserve, and TTL limits |
| Checkpoint amplification | AI checkpoints repeatedly | Private-checkpoint count/bytes/rate; task queue bounds; host-pressure cancellation |
| Artifact amplification | Repeated derived artifacts exhaust disk | Cumulative artifact-byte budget, retention, CAS dedupe, queue bounds |
| Mailbox amplification | Message flood fills database/disk | Envelope, payload, queue, sender rate, workflow disk, TTL, and dead-letter limits |
| Denial storm | 10,000 invalid launch requests consume parser/audit CPU | Small frames, bounded queue, token bucket, circuit breaker, deduplicated denial audit |
| Audit amplification | Every refusal synchronously signs a record | First-event plus bounded summaries; security effects still require durable intent |
| Host-memory exhaustion | Valid workflows collectively use final RAM | Host safety reserve, maximum-based accounting, atomic admission, fair share |
| Balloon-accounting bypass | Current commitment used instead of admitted maximum | Account against configured maximum, not momentary balloon commitment |
| CPU exhaustion | Many low-memory CPU burners | Aggregate millicore reservations and enforced backend tier |
| Process/thread exhaustion | Each VMM consumes processes/threads beyond CPU/memory | Explicit resident process/thread/VM limits |
| FD/socket exhaustion | MicroVMs consume host FDs, UDS, listeners, event-loop slots | Explicit workflow/tenant/host FD, socket, and vsock-channel ceilings |
| Backend downgrade | Requested CPU/wall-clock bound is declared but unenforced | Production workflow admission requires an enforceable achieved tier |
| Uncapped startup window | Limits applied after child begins executing | Born-bounded VMM spawn or refuse |
| TOCTOU reservation | Capacity changes after check and before launch | Atomic reservation ID held until commit or rollback |
| Partial reservation leak | Memory reserved but VM slot fails | One transaction across every dimension |
| Double launch | Retry races after timeout | Durable idempotency key, one live effect, same receipt on retry |
| Host crash after VMM start | Child runs without journal entry | Write-ahead intent, launch marker, recovery reconciler, orphan reaper |
| Host crash before VMM start | Reservation remains forever | Transaction state and expiry; recovery rolls back only after proving no live effect |
| Unsafe reservation release | Stop request assumed successful | Release only after VMM death and resource reap are confirmed |
| Stale controller | Failed-over controller continues mutations | Monotonic fencing generation checked on every operation |
| Controller split brain | Two controllers both act during partition | Single active generation or threshold policy; no timestamp-only merge |
| Approval replay | Old human approval reused | Request digest, exact action, expiry, operator identity, nonce, first-valid resolution |
| Approval fatigue | AI repeatedly asks until approved | Pending-request cap, grouping, rate limits, risk classes that cannot be human-overridden |
| Graph race | Two patches commit against same revision | Compare-and-swap revision and graph digest |
| Dataflow cycle | Outputs loop forever and never propagate EOF | Validate each committed revision as DAG before boot |
| Hidden feedback | Mailbox/stream combination creates undeclared control loop | Distinct edge classes and full topology validation for authority-affecting routes |
| Fan-in corruption | Two producers interleave one stdin | Single writer; explicit merge actor |
| Prompt injection | Child output tells controller to launch many workers | Output marked untrusted; typed action binding and host-side revalidation |
| Tool-description injection | Malicious descriptive text changes security meaning | Signed structured descriptors; security fields not parsed from prose |
| Hallucinated action | Model invents a tool or worker | Exact opaque binding and descriptor digest required |
| Ontology poisoning | Malicious fact makes unsafe worker look compatible | Trusted issuers, pinned snapshot, evidence, compiler policy, exact candidate set |
| Semantic authority confusion | `similarTo` treated as delegation | General semantic edges never authorize; dedicated signed bindings only |
| Stale AppView | Planner sees outdated availability or policy | AppView advisory; execution checks current signed snapshot and transaction |
| Mutable semantic reference | Launch resolves a changed URI | URI-plus-digest/CID strong ref; exact template digest |
| Schema drift | Unknown field silently drops a limit | `deny_unknown_fields`, explicit versions, unknown-version refusal |
| Old-client omission | New restrictive field absent in old plan | Safe serde defaults and omitted-when-absent compatibility rules |
| Revoked issuer | Stale signed snapshot still accepted | Revocation epoch/key ID/freshness checked locally |
| Clock skew | Lease expiry disagreement | Bounded assumptions, monotonic local timers, conservative expiry |
| Snapshot authority reuse | Restored controller reuses old boot authority | New boot ID, generation, keys, grants, and identity handshake |
| Old VM-name inheritance | Child inherits authority from stable name | Authorization binds attempt, boot, plan digest, generation—not name alone |
| Cross-workflow handle use | Controller stops sibling workflow's VM | Tenant/authority-domain/workflow scope; uniform coarse refusal |
| Cross-tenant graph inference | Error reveals hidden node existence | “Not bound/not yours/not present” indistinguishable externally |
| Sender spoofing | Guest claims another actor's sender ID | Host stamps sender from channel; guest sender field non-authoritative |
| Message replay | Old request delivered again | Message ID, sequence, idempotency key, durable dedupe, expiry |
| Message reordering | Relay changes causal behavior | Per-route order, sequence, causation IDs; no unsupported global order claim |
| Message tampering | Relay modifies payload | AEAD, payload digest, destination verification |
| Offline recipient pressure | Unbounded queue accumulates | Per-recipient/workflow quota, TTL, explicit full/refusal, optional bounded dead-letter |
| Raw stdout control | Fake JSON in stdout triggers lifecycle action | stdout/stderr never dispatched as control |
| Secret exfiltration | Child result or artifact contains credential | No raw secret grant, destination restrictions, redaction, classification, leak gates |
| Semantic/steganographic exfiltration | Model encodes secret meaning without byte match | Recipient/egress constraints; explicit residual risk; redaction not overclaimed |
| Unauthorized observation | Parent reads every child merely because it spawned it | Separate observe/read capabilities and classification clearance |
| Information-label downgrade | Guest marks secret-derived artifact public | Host-assigned classification only rises; explicit declassifier required to lower |
| Raw stream edge bypass | Unredacted data crosses trust domains | Redacted default; raw initially refused or separately operator-acknowledged |
| Used-child reuse | Mutated workload state returned to shared pool | Destroy used child; replenish from clean parent only |
| Private-checkpoint sharing | Actor checkpoint becomes generic warm capacity | Workflow/logical-actor binding; refuse other consumers |
| Egress amplification | Many children exceed network/cost budget | Aggregate network byte, destination, rate, and external-cost ceilings |
| Secret amplification | Parent delegates secrets it may use but not delegate | Distinct `usable` and `delegable` secret sets; subset checks |
| Tool amplification | Child receives broader host-service registry | Exact per-child binding projection and descriptor digest |
| Filesystem amplification | Child gains wider share or write access | Filesystem attenuation and exact share slots; read-only default |
| Cross-node impersonation | Compromised node claims another node's VM | `mvmd`-issued short-lived node/VM grants; destination independently verifies |
| Remote misrouting | Message reaches wrong physical node | Audience, destination node, attempt, boot, plan, and placement-lease binding |
| Membership oracle | Remote refusal distinguishes nonexistent versus other-node VM | Uniform refusal |
| Partitioned queue divergence | Two nodes accept same command | Transaction authority and fencing; no firehose-as-lock |
| Compromised parser | Guest frame exploit reaches key or backend | Parser/key-holder/backend separation and minimal normalized DTO |
| Compromised launch role | Launch role accepts arbitrary configuration | Exact permit plus reservation ID; no guest connection; no raw paths on wire |
| Compromised `mvmd` | Fleet issuer creates malicious delegations | Narrow issuer API, process/key separation, audit, rotation, optional HSM/threshold control |
| Malicious host | Host reads/modifies guest or workflow state | Remains outside current ADR-001 threat model; confidential computing is separate work |
| AT public-data leak | Raw mailbox/output published | Allowlisted sanitized bridge; private content publication prohibited |
| Encrypted-but-public leak | Ciphertext metadata or future key disclosure | Do not publish private payload ciphertext as ordinary public records |
| Malicious labeler | Positive trust assertion widens capability | Issuer trust policy, quorum, evidence, expiration; positive widening tightly restricted |
| Compromised PDS/relay/AppView | External semantic state lies or disappears | Never on synchronous authority path; resync/gap handling; signatures verified |
| Repository deletion/rollback | Published fact disappears or history rewrites | Local authoritative store/audit retained; AT publication is secondary |
| CAR/CBOR parser exploit | External file exhausts memory or escapes parser | Isolated parser, hard caps, fuzzing, no keys, no launch capability |
| DID/URL SSRF | Resolver fetches attacker-controlled endpoint | Allowlist, redirect policy, IP filtering, size/time caps, isolated network role |
| Model-provider leakage | Sensitive context sent externally | Planner context classification and explicit model destination/data policy |
| Model-weight compromise | Embedded model intentionally misbehaves | Treat as controller compromise; same finite envelope |
| AI-generated code | Controller launches unreviewed source directly | Isolated build, provenance, scan, signature, then normal template admission |

### 22.1 Residual truths

- A workflow receipt proves admitted configuration, lifecycle facts, recorded
  communication, and artifact lineage. It does not prove an AI result is
  semantically correct.
- Byte redaction cannot prevent every semantic or steganographic leak.
- The host remains trusted under the standing threat model.
- Formal model checking covers the modeled abstraction and bounds; it does not
  replace implementation testing or operational evidence.

## 23. Formalization and machine-checked invariants

### 23.1 State model

```text
State = {
    workflow_head,
    node_attempts,
    authority_edges,
    data_edges,
    controller_leases,
    delegations,
    reservations,
    warm_capacity,
    mailboxes,
    messages,
    artifacts,
    approvals,
    audit_intents,
}
```

Transitions include:

```text
AdmitWorkflow
IssueControllerLease
PlanActions
ReserveLaunch
AdmitChildPlan
StartChild
RecordReady
SendMessage
AcknowledgeMessage
CommitGraphPatch
SetCapacityTarget
PauseChild
CheckpointChild
ReleaseChild
CancelSubtree
ExpireLease
FailNode
RecoverHost
FenceController
SealWorkflow
```

### 23.2 Core invariants

```text
I1  NoGuestHypervisorAuthority
I2  EveryLiveAttemptHasVerifiedPlan
I3  EveryAttemptHasExactlyOneAuthorityParent
I4  DescendantAuthorityNeverExceedsEveryAncestorCeiling
I5  DataflowIsAcyclicPerRevision
I6  EveryStdinHasAtMostOneWriter
I7  WorkflowAndHostBudgetsNeverBecomeNegative
I8  OneIdempotencyKeyHasAtMostOneLiveEffect
I9  StaleControllerGenerationCannotMutate
I10 MessageSenderIsChannelDerived
I11 CrossTenantAndCrossWorkflowEdgesDoNotExist
I12 SecurityEffectHasPriorDurableIntent
I13 EveryArtifactHasAttemptAndBootProvenance
I14 InformationClassificationNeverDecreasesWithoutDeclassifier
I15 UnknownSchemaOrOntologyVersionCannotWidenAuthority
I16 GuestVisibleValuesDoNotRevealPhysicalRoutes
I17 UsedWorkloadStateNeverReentersSharedCapacity
I18 ReleasedReservationImpliesNoLiveHostEffect
I19 SemanticAssertionsCannotWidenALiveSnapshot
I20 DirectWorkloadsCreateNoWorkflowAuthorityOrState
```

### 23.3 Tool division

- **Alloy:** static authority forests, DAGs, binding cardinality, capability
  reachability, cross-tenant separation, and information-flow relationships.
- **TLA+ / Apalache:** launch transactions, crash points, reservations,
  idempotency, approvals, controller failover, partitions, lease expiry,
  duplicate placement, cancellation races, and recovery.
- **Lean 4:** pure capability attenuation, budget arithmetic, graph-patch
  predicates, classification lattice, canonical domain separation, and
  theorems such as `effective(child) ⊆ effective(parent)`.

The Rust implementation should consume generated valid, invalid, and
counterexample vectors from the reference semantics and run differential and
mutation tests.

### 23.4 Claim discipline

All swarm claims begin as preview claims. Promotion requires:

```text
real production caller
negative paths exercised through real process boundaries
formal and Rust vector agreement
cross-platform witnesses
mutation/planted-defect proof that the gate fires
no direct-path performance regression
independent receipt/audit verification
```

Suggested gates:

```text
check-workflow-authority-attenuation
check-workflow-no-guest-addressing
check-workflow-topology-witnesses
check-workflow-budget-accounting
check-workflow-mailbox-bounds
check-workflow-encrypted-no-fallback
check-workflow-audit-before-effect
check-workflow-formal-vector-drift
check-workflow-no-ambient-authority
check-direct-path-workflow-absence
```

## 24. Rust implementation strategy

### 24.1 Keep the trusted contract dependency-light

New workflow, mailbox, planning, and constraint DTOs belong in
`mvm-contract`, preserving its dependency-light and portable role. They should
use:

```text
closed enums
bounded vectors/maps
integer units, never floating-point policy values
explicit versions
`deny_unknown_fields`
omitted-when-absent compatibility fields
canonical digests
domain-separated signatures
```

No model runtime, vector database, AT repository/MST implementation, CAR
parser, DID resolver, OAuth client, or ontology engine belongs in
`mvm-contract`, `mvm-core`, `mvm-agentd`, or a VMM supervisor.

### 24.2 Reuse existing mechanisms

- Every child is launched through the same admitted single-machine runtime used
  by direct execution.
- Child resource grants use the existing `Grants` and backend enforcement
  seams.
- Warm launch uses the existing warm service, compatibility keys, leases, and
  claim path.
- Communication uses the existing stream plane plus the mailbox work, not a
  second guest networking stack.
- Host-service dispatch uses the existing binding registry and process
  separation.
- Audit and transcript evidence use the existing chain, roots, and manifests.

### 24.3 Suggested contracts

```text
mvm-contract/src/workflow/
    ids.rs
    membership.rs
    template.rs
    action.rs
    delegation.rs
    constraints.rs
    budget.rs
    reservation.rs
    graph.rs
    lifecycle.rs
    planning.rs
    receipt.rs

mvm-contract/src/mailbox/
    envelope.rs
    cursor.rs
    limits.rs
    archive.rs
```

### 24.4 Suggested host modules and binaries

```text
mvm-hostd/src/workflow/
    ingress.rs
    admission.rs
    reservation.rs
    local_authority.rs
    lifecycle.rs
    capacity.rs
    reconciler.rs
    audit.rs

mvm-hostd/src/mailbox/
    router.rs
    store.rs
    archive.rs
```

The final process split may use additional `[[bin]]` roles inside `mvm-hostd`
when a separate address space is required. Do not create a new crate for every
concept; follow the existing role/dependency-boundary discipline.

### 24.5 Controller SDK

```text
mvm-sdk/src/workflow/
    planning_client.rs
    action_dispatch.rs
    mailbox.rs
    idempotency.rs
    ai_adapter.rs
```

AI provider integrations are optional features or separate workload code. The
default SDK must not pull a model stack into normal workloads.

### 24.6 Recommended `mvmd` modules

These are design recommendations pending inspection of the actual repository:

```text
workflow/
    journal
    constraints
    issuer
    controller_lease
    reservation
    placement
    reconciliation
    routing

semantic/
    record_envelope
    outbox
    projector
    ontology
    action_catalog
    planning_snapshot
    provenance_view

atproto/
    ingress
    exporter
    lexicons
    identity_mapping
```

### 24.7 AT implementation posture

- Implement the internal typed semantic envelope first with ordinary Rust
  serde and the existing signing primitives.
- Adopt NSID-like names and URI-plus-digest strong references without claiming
  wire compatibility.
- Keep CAR/CBOR/MST/DID/OAuth support in an optional isolated bridge.
- Use generated types from pinned Lexicons when true compatibility is added.
- Require conformance vectors, fuzzing, parser bounds, dependency review, and
  process isolation before accepting a Rust library or sidecar.
- Never place external parser dependencies in the immediate guest/host or boot
  path.

## 25. API surface

### 25.1 Direct execution remains explicit

```rust
pub trait MachineClient {
    fn run_machine(&self, spec: MachineSpec) -> Result<MachineHandle>;
}
```

CLI remains:

```text
mvmctl machine run
mvmctl machine stop
mvmctl invoke
```

A direct plan has absent workflow fields and should serialize exactly as legacy
plans do when omitted-when-absent compatibility is required.

### 25.2 Workflow execution is separate

```rust
pub trait WorkflowClient {
    fn run_workflow(&self, spec: WorkflowSpec) -> Result<WorkflowHandle>;
    fn describe_workflow(&self, id: WorkflowId) -> Result<WorkflowDescription>;
    fn cancel_workflow(&self, id: WorkflowId) -> Result<WorkflowReceipt>;
}
```

Possible CLI:

```text
mvmctl workflow run workflow.toml
mvmctl workflow status <id>
mvmctl workflow logs <id>
mvmctl workflow graph <id>
mvmctl workflow cancel <id>
```

A one-node workflow is legal but uses the workflow API because the caller wants
workflow identity, mailbox, revision, supervision, and receipt semantics. A
normal `machine run` is not silently converted into one.

### 25.3 Controller-facing verbs

A first `host.workflow.v1` service can expose:

```text
get_planning_snapshot
query_action_catalog
launch_child
observe_child
release_child
set_capacity_target
send_message
subscribe_events
request_capability
request_approval
complete_workflow
```

Later phases may add pause, checkpoint, restore, graph patching, subtree cancel,
and recursive delegation.

## 26. Launch transaction

A child launch is one durable lifecycle transaction:

```text
1. Read and bound the request frame before allocation.
2. Derive caller identity from the encrypted channel.
3. Verify workflow, controller attempt, boot, plan, generation, expiry,
   revocation epoch, and service binding.
4. Resolve the plan-local template binding to an exact digest.
5. Verify the action, input schema, launch mode, and child ceilings.
6. Atomically reserve every resource and non-replenishing budget.
7. Record a durable lifecycle intent.
8. Derive the complete child ExecutionPlan host-side.
9. Sign, verify, replay-check, and admit the child plan.
10. Select local or remote placement.
11. Claim compatible warm capacity or cold-start according to the admitted
    launch mode.
12. Establish fresh attempt, boot, session keys, mailbox, streams, secrets,
    and host-service bindings.
13. Wait for authenticated readiness.
14. Commit the attempt and lifecycle outcome.
15. Publish derived facts through the outbox.
16. Return an opaque ActorHandle and receipt.
```

The real implementation is a multi-step refinement of the abstract atomic
operation:

```text
authorize + consume budget + create child
```

Crash recovery must preserve that abstraction.

## 27. Performance requirements

### 27.1 Direct path

When workflow membership and delegation are absent, the runtime must not
initialize:

```text
workflow journal
reservation ledger
controller lease
mailbox router
capacity reconciler
semantic index
AT bridge
fleet route resolver
```

The only new work should be the constant-time validation that optional workflow
fields are absent.

### 27.2 Workflow launch path

Semantic reasoning and full graph validation happen when compiling or
committing a planning/graph revision, not in the VMM start hot path.

```text
planning/patch phase:
    semantic ranking
    exact binding resolution
    DAG validation
    attenuation
    reservation preparation

child launch phase:
    verify prepared authorization
    reserve/commit
    derive/sign child plan
    claim or start existing backend path
```

### 27.3 SLO reconciliation

The conversation treats approximately 200 ms cold/warm launch as a hard
product requirement, while current repository plan 298 is framed around a
sub-300 ms warm claim. Resolve and document the authoritative SLO before
implementation. In either case:

- Workflow composition may not regress ordinary direct launch.
- A pre-admitted workflow child must use the same backend start SLO as a direct
  workload of the same shape.
- No ontology, model, AT, repository, or AppView operation is on the measured
  VM launch window.
- Warm pool accounting and safety checks must remain bounded and constant-time
  relative to the workflow's configured maxima.

## 28. First vertical slice

The first slice deliberately proves the safety architecture rather than broad
feature coverage.

### 28.1 Configuration

```text
single host
local development authority
one sealed controller
one controller generation
maximum depth: 1
maximum controllers: 1
maximum live workers: 2
maximum resident VMM slots: 3
maximum total attempts: 4
maximum concurrent launches: 1
launch rate: 2/minute
maximum resident warm parents: 1
maximum parked parents: 1
two exact worker templates
no child delegation
no worker network
no worker secrets
no writable host shares
fixed memory and enforced CPU/wall-clock limits
structured mailbox
redacted streams only
content-addressed artifacts
```

Controller verbs:

```text
get_planning_snapshot
launch_child
observe_child
release_child
set_capacity_target
send_message
complete_workflow
```

### 28.2 Positive demonstration

```text
controller
├── launches researcher-a
├── launches researcher-b
├── receives structured results
├── launches verifier using artifact refs
└── seals final workflow receipt
```

The live-worker ceiling means the verifier begins only after a researcher is
released or the workflow was admitted with a different exact schedule.

### 28.3 Required destructive tests

```text
10,000 concurrent launch requests never create more than 2 live workers

launch/terminate churn never exceeds 4 total attempts

warm target 65,535 is refused before prewarm work

worker calling launch_child receives NotBound

unauthorized template is refused before plan synthesis

controller cannot alter memory, CPU, network, secret, filesystem, backend, or
host path

same idempotency key never creates two live children

stale controller generation cannot launch, stop, or change capacity

cross-workflow ActorHandle is refused without revealing membership

host crash after VMM start but before journal commit leaves no unmanaged child

audit-intent failure prevents launch

snapshot and artifact quotas prevent parked-capacity/disk exhaustion

used child state never enters the shared warm pool

backend without enforceable resource controls is refused

plaintext or stale-session lifecycle frame is refused

direct machine run creates no workflow state or process
```

### 28.4 Go/no-go criteria

Proceed only if:

- No test can exceed the configured workflow or host envelope.
- Every launch/refusal has a durable, payload-free authoritative result.
- Crash injection at each transaction boundary recovers to one effect or a
  terminal refusal.
- Direct launch benchmarks remain within the accepted noise/SLO.
- The controller compromise model is demonstrated, not merely documented.

## 29. Phased roadmap

### Phase 0 — Decisions, claims, and protocol freeze

Deliver:

```text
ADR 043
ADR-001 threat-model amendment
ADR-037 production-delegation amendment or superseding clarification
encrypted-session ADR
workflow/mailer terminology
preview claims and dormant-control declaration
formal model skeleton
```

Stop/go: no unresolved owner of signing, verification, workflow truth,
reservation truth, or host safety ceilings.

### Phase 1 — Contract types and direct-path compatibility

Deliver workflow IDs, membership, attempts, templates, action descriptors,
constraint/planning snapshots, lifecycle requests/receipts, bounded mailbox
DTOs, serde/schema tests, frozen compatibility vectors, and direct-path absence
witnesses.

Stop/go: absent workflow fields preserve direct semantics and no normal path
can construct lifecycle authority accidentally.

### Phase 2 — Constraint compiler and transactional budget ledger

Deliver exact template compilation, capability/resource attenuation,
HostSafetyCeiling, tenant/workflow ceilings, atomic reservations, idempotency,
rate limits, denial circuit breakers, and crash-recoverable intents.

Stop/go: a hostile concurrency test cannot over-reserve any dimension.

### Phase 3 — Encrypted session and process split

Deliver per-boot encrypted channels, parser/admission/launch process separation,
exact launch permits, protocol fuzzing, and no plaintext fallback.

Stop/go: parser compromise tests cannot access signer or backend authority.

### Phase 4 — Local single-host lifecycle vertical slice

Deliver `host.workflow.v1`, `LocalWorkflowAuthority`, exact controller and
worker templates, child launch/observe/release, direct child plan derivation,
and local receipts.

Stop/go: first vertical slice and destructive test matrix pass.

### Phase 5 — Mailbox and artifact integration

Deliver durable structured messages, cursors, dedupe, TTL, quotas, sealed
archives, artifact manifests, and controller result handling. Preserve existing
stream behavior.

Stop/go: no raw private content reaches audit or semantic publication.

### Phase 6 — Warm/cold desired-state integration

Deliver capacity targets, reconciler, clean parent accounting, parked state,
host-pressure overrides, idle policies, and private actor checkpoints.

Stop/go: used child never reenters shared capacity and all resident resources
are fully charged.

### Phase 7 — Graph revisions and supervision

Deliver compare-and-swap graph patches, DAG validation, graph epochs,
restart strategies, attempt intensity, cancellation propagation, controller
fencing, and final workflow receipts.

Stop/go: crash/retry/failover model passes TLA+/implementation witnesses.

### Phase 8 — AI planning snapshot and controller SDK

Deliver finite action catalogs, AI planner configuration, trust-tagged context,
typed decisions, requestable capabilities, cost/token/time bounds, and semantic
ranking after hard filtering.

Stop/go: disabling semantic/AI components changes ranking and convenience, not
the authorized action set.

### Phase 9 — Recursive delegation and controller groups

Deliver child-controller templates, subtree budgets, maximum depth,
threshold/any-of controller policy, and complete ancestor attenuation.

Stop/go: Alloy/Lean/Rust vectors agree that no delegation path widens authority.

### Phase 10 — `mvmd` distributed workflows

Deliver fleet issuer, controller leases, placement, fleet reservations,
node-verifier distribution, cross-node mailbox/artifact routing, independent
destination verification, partition behavior, and orphan recovery.

Stop/go: source node/controller cannot make a destination perform an action
without a valid `mvmd`-rooted grant.

### Phase 11 — AT-shaped semantic plane

Deliver internal semantic envelopes, strong references, durable outbox,
replayable tenant streams, gap detection, resync, projectors, provenance and
topology views, isolated labelers, and constraint-input capture.

Stop/go: AppViews can be deleted and rebuilt without affecting authoritative
workflow state.

### Phase 12 — Optional AT Protocol bridge

Deliver pinned Lexicons, repository publication/import, CAR export, sanitized
run/template/provenance records, DID/operator mapping, label integration, and
strict data-publicity controls.

Stop/go: PDS/relay/AppView outage or malicious data cannot affect live
execution authority.

### Phase 13 — Production evidence and documentation

Deliver cross-platform witnesses, fuzzing, mutation tests, performance gates,
operator CLI/studio views, claim promotion review, and independent receipt
verification.

## 30. Adopt / prototype / defer / reject

| Decision | Posture | Reason |
| --- | --- | --- |
| One workload per microVM | Adopt now | Preserves the isolation and plan model |
| Optional workflow composition layer | Adopt now | Adds swarm behavior without replacing direct execution |
| Exact template-bound child launches | Adopt now | Minimum safe authority surface |
| Workflow/tenant/host hierarchical ceilings | Adopt now | Prevents controller-caused host exhaustion |
| Non-replenishing attempt and cost budgets | Adopt now | Prevents churn attacks |
| Atomic reservation ledger | Adopt now | Prevents concurrent over-admission |
| Separate parser/admission/launch roles | Adopt now | Limits compromise blast radius |
| Structured mailbox | Adopt now | Needed for bidirectional agent coordination |
| Stream DAG with explicit merge nodes | Adopt now | Existing reviewed mechanism |
| Desired warm/parked/cold capacity | Adopt now | Needed for efficient scale-to-zero |
| Used child destroyed, never returned | Adopt now | Prevents cross-run state bleed |
| AI planner against finite signed snapshot | Prototype after local lifecycle | Gives autonomy without semantic authority |
| Semantic action catalog | Prototype | Useful planning abstraction; exact binding at execution |
| Alloy/TLA+/Lean reference models | Adopt early | High-value for delegation, budgets, and crash states |
| Recursive controller delegation | Defer | Large authority and formalization increase |
| Controller threshold groups | Defer | Host-serialized single generation is simpler first |
| Cross-host live streams | Defer | Mailbox/artifact routing proves distribution first |
| General cross-node guest L3 | Defer to networking prerequisites | Not required for workflow control |
| AT-shaped internal semantic log | Adopt in `mvmd` after transaction core | Captures useful protocol patterns safely |
| True AT repository/PDS compatibility | Defer/optional bridge | Federation value, but outside TCB |
| Full AT Protocol as internal scheduler | Reject | Wrong consistency and publicity assumptions |
| Firehose as task claim or distributed lock | Reject | No transactional/fencing semantics |
| AppView as scheduler/admission source | Reject | Rebuildable/eventually consistent projection |
| AI output as permission | Reject | Model is untrusted |
| Semantic similarity as authority | Reject | Approximation cannot widen security |
| Arbitrary guest `VmStartConfig` | Reject | Expands host and hypervisor attack surface |
| Nested virtualization in controller | Reject | Unnecessary and dangerous |
| Returning used child to shared pool | Reject | Cross-workload state leakage |
| Public raw mailbox/output records | Reject | Privacy and secret leakage |

## 31. Open questions and implementation blockers

1. **Authoritative launch SLO:** reconcile the user-level 200 ms requirement
   with the current sub-300 ms repository plan and define cold versus warm
   measurement boundaries.
2. **Encrypted-session ADR:** choose and pin the handshake/session primitive and
   reconcile older signed-frame/topology-based assumptions.
3. **Host admission completeness:** finish aggregate live resource accounting
   for every production backend before enabling controller launch authority.
4. **Production delegation:** decide whether ADR-037 is amended or superseded
   by a precise `mvmd`-rooted delegation rule.
5. **Local workflow store:** select the minimal durable transactional substrate
   for standalone mode without turning `mvm` into a fleet database.
6. **`mvmd` current architecture:** inspect the actual repository and map the
   proposed issuer, journal, routing, semantic, and projector modules onto
   existing seams.
7. **`mvm-mailbox` source:** reconcile this design with the final mailbox ADR
   and storage/archival implementation once available in the working tree.
8. **Classification/declassification:** define the conservative label lattice
   and the rare capabilities allowed to lower classification.
9. **Guaranteed warm capacity:** decide whether host pressure may always evict
   workflow capacity or whether paid/operator-pinned reservations exist.
10. **Template parameterization:** define which inputs can vary without
    changing the template digest or warm compatibility shape.
11. **Model bindings:** define local, dedicated-microVM, host-service, and
    external-provider model policies and receipt semantics.
12. **AT namespace/domain:** pin the controlled NSID domain before publishing
    wire-compatible Lexicons.
13. **Claim promotion:** decide which properties are strong enough for numbered
    claims versus permanently qualified preview claims.

## 32. Reference architecture diagrams

### 32.1 Dependency graph

```text
existing signed-plan, grants, stream, audit, and warm-pool substrate
    │
    ├── workflow contract types
    │     ├── authority and budget reference semantics
    │     ├── direct-path compatibility
    │     └── exact template/action bindings
    │
    ├── transactional constraint and reservation authority
    │     ├── encrypted boot-bound workflow session
    │     ├── parser / admission / launch process separation
    │     └── local single-host lifecycle vertical slice
    │
    ├── mailbox, artifact, stream, and receipt composition
    │     ├── warm / parked / cold desired-state reconciliation
    │     ├── graph epochs, supervision, cancellation, and recovery
    │     └── optional AI planning snapshot and controller SDK
    │
    └── mvmd production issuer, placement, and cross-node routing
          ├── AT-shaped semantic outbox and AppViews
          └── optional true AT Protocol import/export bridge
```

Recursive delegation and controller groups depend on production evidence for
all single-controller layers. True AT compatibility depends on value proven by
the AT-shaped internal semantic plane; neither is a prerequisite for the first
secure workflow.

### 32.2 Local controller child-launch sequence

```text
AI or deterministic planner
  │ selects exact action binding from signed planning snapshot
  ▼
controller runtime inside controller microVM
  │ validates DTO shape and attaches idempotency key
  ▼ encrypted boot-bound guest/host workflow channel
keyless workflow parser
  │ derives caller from channel; parses bounded request
  ▼ normalized request
workflow admission authority
  │ verifies workflow / attempt / boot / plan / generation
  │ resolves exact template binding
  │ intersects host, tenant, workflow, controller, and template ceilings
  │ transactionally reserves every resource dimension
  │ writes durable lifecycle intent
  │ derives and admits exact child ExecutionPlan
  ▼ exact launch permit + reservation ID
workflow launch role
  │ verifies permit; loads host-prepared config by reservation ID
  │ chooses admitted warm-required / warm-preferred / cold path
  ▼
existing WarmLaunchService or VmBackend launch path
  │ binds fresh attempt, boot identity, channels, grants, and audit lineage
  ▼
child microVM authenticated readiness
  │
  ├── lifecycle outcome committed to workflow journal
  ├── local chain-signed audit outcome emitted
  ├── lifecycle fact appended to semantic outbox
  └── opaque ActorHandle returned to controller
```

At no point does the controller provide a host path, VMM handle, backend name,
raw `VmStartConfig`, signing key, or physical placement target.

### 32.3 Distributed controller-to-child sequence

```text
controller microVM on Node A
  │ LaunchChild(exact binding, input refs, idempotency key)
  ▼
Node A keyless parser
  ▼
Node A / mvmd workflow transaction authority
  │ verifies controller delegation and reserves fleet budget
  │ selects Node B after hard constraints
  │ issues audience-bound launch grant for Node B
  ▼ authenticated control-plane transport
Node B node verifier
  │ verifies mvmd key ID, signature, audience, tenant, workflow,
  │ attempt, plan digest, expiry, nonce, and local host safety
  ▼
Node B local workflow launch role
  │ admits exact child plan locally
  │ claims warm capacity or cold-boots
  ▼
child microVM on Node B
  │ authenticated ready under fresh boot identity
  ▼
Node B local audit + mvmd transactional outcome
  │
  └── opaque logical ActorHandle returned to controller on Node A
```

Node B never trusts Node A's assertion that admission was performed correctly.
The destination node verifies the fleet grant and executes its own local
admission once. This is the same issuer-versus-verifier split already selected
for node control: `mvmd` owns fleet issuance; `mvm` owns local verification.

### 32.4 Communication and data-flow diagram

```text
                         ┌────────────────────────────┐
                         │ authoritative workflow DB │
                         │ leases, budgets, graph CAS │
                         └─────────────┬──────────────┘
                                       │ committed facts via outbox
                                       ▼
                         ┌────────────────────────────┐
                         │ semantic replay stream /  │
                         │ AppView projectors        │
                         └────────────────────────────┘

controller microVM
  │
  ├── CONTROL ── typed launch/cancel/capacity/approval commands
  │                → transactional authority → lifecycle roles
  │
  ├── MAILBOX ─ structured private task/result messages
  │                → bounded transactional mailbox → actor binding
  │
  ├── STREAM ─── stdout/stderr and optional producer→consumer stdin
  │                → existing redaction/hash-chain/ring stream plane
  │
  └── ARTIFACT ─ immutable large inputs/outputs/checkpoints
                   → content-addressed artifact/snapshot stores

No plane grants authority merely by carrying a string, URI, CID, semantic
predicate, model response, or workload output. The control plane uses exact
compiled bindings and current transactional reservation state.
```

### 32.5 Trust and key-flow diagram

```text
mvmd fleet issuer key
  └── signs controller, launch, route, and ConstraintSnapshot grants
       └── nodes hold verifying keys only

mvm local execution/audit key
  └── signs/admission-verifies local ExecutionPlans and audit evidence
       └── guest workloads never receive it

workflow encrypted-session material
  └── ephemeral, boot-bound, channel-purpose-separated
       └── controller/workload receives only its own session material

labeler/attestation key
  └── signs an assertion after evidence verification
       └── scanner microVM never receives it

AT repository/publication key
  └── proves authenticated publication only
       └── never substitutes for execution, fleet, or labeler proof
```

The proof domains may reference one another by exact digest, but no verifier
silently treats one signature type as another.

## 33. Concrete semantic record shapes

These examples are close pseudocode rather than a commitment to a particular
AT Lexicon version. The internal AT-shaped model should use the same semantic
fields even before true wire-compatible Lexicons exist.

### 33.1 Common strong reference and proof envelope

```text
StrongRef {
  uri: string,                  // internal globally scoped URI or AT URI
  cid_or_digest: string,        // exact bytes, never semantic similarity
  media_type?: string,
  size?: integer
}

ExecutionIdentity {
  node_id: string,
  vm_id: string,
  boot_id: string,
  plan_digest: string
}

AuthenticatedRecordEnvelope {
  record_type: NSID,
  schema_digest: string,
  record_uri: string,
  record_cid_or_digest: string,
  issuer: string,
  issuer_key_id: string,
  tenant_id: string,
  workflow_id?: string,
  valid_from?: timestamp,
  valid_until?: timestamp,
  revocation_ref?: StrongRef,
  ontology_digest?: string,
  ruleset_digest?: string,
  evidence: [StrongRef],
  payload: typed-record
}
```

The envelope proves who authored exact bytes. It does not, by itself, prove
truth or authorize a runtime action.

### 33.2 `com.runmvm.execution.run`

```text
record execution.run {
  workflow: StrongRef?,
  workflow_revision: integer?,
  logical_node_id: string?,
  attempt_id: string,
  execution_identity: ExecutionIdentity,
  plan: StrongRef,
  constraint_snapshot: StrongRef?,
  controller_generation: integer?,
  lifecycle_state: enum[
    admitted, starting, ready, running, releasing,
    completed, failed, cancelled, cleanup_fault
  ],
  launch_origin: enum[direct, cold, parked_restore, resident_warm_claim],
  parent_attempt: StrongRef?,
  admitted_at: timestamp,
  ready_at: timestamp?,
  terminal_at: timestamp?,
  local_execution_proof: StrongRef,
  fleet_authorization_proof: StrongRef?
}
```

Authoritative state lives in the local/fleet transaction and audit stores. The
semantic run record is a replayable projection carrying exact proof refs.

### 33.3 `com.runmvm.artifact.manifest`

```text
record artifact.manifest {
  artifact_id: string,
  content_digest: string,
  byte_size: integer,
  media_type: string,
  schema: StrongRef?,
  classification: enum[public, internal, confidential, secret_derived],
  producer_run: StrongRef,
  producer_identity: ExecutionIdentity,
  consumed_inputs: [StrongRef],
  chunks: [StrongRef],
  retention_policy: StrongRef,
  attestations: [StrongRef],
  local_manifest_proof: StrongRef
}
```

Artifact bytes remain in the content-addressed artifact store. A public record
is emitted only when classification and publication policy explicitly permit
it.

### 33.4 `com.runmvm.topology.edge`

```text
record topology.edge {
  subject: StrongRef,
  predicate: enum[
    runsOn, spawnedBy, requestedBy, delegatedTo, constrainedBy,
    consumes, produces, derivedFrom, verifiedBy, communicatesWith,
    supersedes, revokes, similarTo, specializes, compatibleWith
  ],
  object: StrongRef,
  edge_class: enum[authoritative_fact, advisory_semantic],
  workflow_revision: integer?,
  execution_identity: ExecutionIdentity?,
  evidence: [StrongRef],
  valid_from: timestamp,
  valid_until: timestamp?,
  ontology_digest: string,
  ruleset_digest: string
}
```

Predicates that can carry authority—delegation, launch admission, controller
leases, secret release, route grants, and constraint snapshots—use dedicated
record types rather than relying on this general edge alone.

### 33.5 `com.runmvm.policy.attestation`

```text
record policy.attestation {
  subject: StrongRef,
  assertion: enum[
    image_approved, image_vulnerable, reproducible_build, sbom_present,
    pii_detected, secret_like_output, malware_suspected,
    license_incompatible, human_reviewed, quarantined,
    artifact_public, artifact_confidential
  ],
  verdict: enum[positive, negative, indeterminate],
  scope: string,
  evidence: [StrongRef],
  scanner_run: StrongRef?,
  issued_at: timestamp,
  expires_at: timestamp?,
  revocation_ref: StrongRef?,
  policy_version: StrongRef
}
```

A scanner run produces evidence. A separate label/attestation authority signs
the assertion after applying issuer and evidence policy.

### 33.6 `com.runmvm.policy.snapshot`

```text
record policy.snapshot {
  workflow: StrongRef,
  workflow_revision: integer,
  controller_attempt_id: string,
  controller_boot_id: string,
  controller_generation: integer,
  exact_inputs: [StrongRef],
  issuer_key_ids: [string],
  schema_digests: [string],
  ontology_digest: string,
  ruleset_digest: string,
  compiler_id: string,
  compiler_version: string,
  executable_action_bindings: [StrongRef],
  approval_required_bindings: [StrongRef],
  requestable_capabilities: [StrongRef],
  effective_egress: StrongRef,
  effective_filesystem: StrongRef,
  effective_secrets: StrongRef,
  effective_tools_services: StrongRef,
  child_spawn_permissions: [StrongRef],
  delegated_capability_ceiling: StrongRef,
  budgets: StrongRef,
  retention_and_classification: StrongRef,
  required_attestations: [StrongRef],
  valid_from: timestamp,
  valid_until: timestamp,
  revocation_epoch: integer,
  snapshot_digest: string,
  fleet_or_local_signature: StrongRef
}
```

The authoritative node-consumable snapshot is signed by `mvmd` or the local
workflow authority and cached with the node. An AT publication of its summary
is secondary and cannot become authority merely by being present in a
repository.

### 33.7 `com.runmvm.agent.task`

```text
record agent.task {
  task_id: string,
  workflow: StrongRef,
  workflow_revision: integer,
  created_by_run: StrongRef,
  requested_role: string,
  exact_template_candidates: [StrongRef],
  input_artifacts: [StrongRef],
  expected_output_schemas: [StrongRef],
  dependency_tasks: [StrongRef],
  classification: string,
  deadline: timestamp?,
  authoritative_task_state_ref: StrongRef
}
```

Task creation/completion facts are appropriate semantic records. Claiming,
renewing, fencing, cancelling, and ownership remain transactional mutable
state.

### 33.8 `com.runmvm.agent.message`

```text
record agent.messageSummary {
  message_id: string,
  workflow: StrongRef,
  sender_run: StrongRef,
  recipient_binding_hash: string,
  schema: StrongRef,
  payload_digest: string,
  payload_size: integer,
  classification: string,
  correlation_id: string?,
  causation_id: string?,
  accepted_at: timestamp,
  acknowledged_at: timestamp?,
  delivery_outcome: enum[accepted, acknowledged, expired, dead_lettered]
}
```

This is deliberately a summary. Raw private message content, prompts, and
payload ciphertext are not ordinary public AT repository records.

### 33.9 `com.runmvm.agent.delegation`

```text
record agent.delegation {
  workflow: StrongRef,
  parent_controller_run: StrongRef,
  child_controller_template: StrongRef,
  delegated_actions: [StrongRef],
  delegated_templates: [StrongRef],
  capability_ceiling: StrongRef,
  egress_ceiling: StrongRef,
  filesystem_ceiling: StrongRef,
  secret_ceiling: StrongRef,
  subtree_budget: StrongRef,
  maximum_depth: integer,
  controller_generation: integer,
  audience: string,
  valid_from: timestamp,
  valid_until: timestamp,
  revocation_epoch: integer,
  fleet_authorization_proof: StrongRef
}
```

The semantic record describes an already-issued delegation. The node accepts
only the original `mvmd`-signed delegation/grant bytes, not a repository record
that happens to describe them.

## 34. Complete worked execution flow

This example combines AI planning, exact constraints, `mvm-mailbox`, cross-node
placement, artifact provenance, isolated scanners, the semantic outbox, and a
new constraint snapshot without making an AppView the scheduler.

### 34.1 Initial admitted state

1. An operator submits a workflow definition to `mvmd`.
2. `mvmd` resolves trusted template, tool, service, model, ontology, ruleset,
   label, and attestation records to exact URI+CID/digest inputs.
3. The deterministic compiler emits `ConstraintSnapshot S0` and controller
   planning snapshot `P0`.
4. `S0` authorizes:
   - one controller;
   - up to two live worker microVMs;
   - four total attempts;
   - exact `rust-audit.small`, `license-scan.small`, and `result-verifier`
     templates;
   - exact mailbox, artifact, and service bindings;
   - fixed aggregate resources and costs.
5. `mvmd` signs `S0` and a production controller launch grant.
6. The selected node verifies the grant and launches the controller through the
   ordinary signed-plan path.

Authoritative stores and proofs:

| Object | Authority/store | Proof |
| --- | --- | --- |
| workflow definition/head | `mvmd` transactional DB | transaction revision |
| `S0` | `mvmd` constraint store; node cache | `mvmd` signature + digest |
| controller `ExecutionPlan` | node plan/audit store | local execution signature/audit |
| planning snapshot `P0` | `mvmd` planning store; controller cache | compiler inputs + signature |
| semantic workflow/run facts | outbox/replay stream | record digest, issuer envelope |

### 34.2 Controller plans

7. The controller receives a task: review a Rust repository.
8. Its optional AI reads `P0` and selects two exact executable bindings:
   `rust-audit.small` and `license-scan.small`.
9. The AI emits a typed `PlannerDecision`; natural-language rationale is stored
   only as an optional classified artifact/digest.
10. The controller runtime validates the DTO and sends one `LaunchChild`
    command per worker with distinct idempotency keys and the repository
    artifact strong reference.

No authority is created here. The AI chooses among bindings already present in
`P0` and `S0`.

### 34.3 Authoritative child launch transaction

For each child:

11. The local parser derives the controller's workflow, attempt, boot, plan,
    and generation from the encrypted channel.
12. The `mvmd`/node workflow authority verifies the exact template binding and
    atomically reserves one live slot, one attempt, memory, CPU, descriptors,
    sockets, mailbox/artifact budget, and applicable cost.
13. It records lifecycle intent before any VMM effect.
14. `mvmd` selects Node B for one worker and Node C for the other after hard
    constraints; semantic ranking may choose among only those valid nodes.
15. `mvmd` signs destination-specific launch grants.
16. Each destination node independently verifies the grant and its own host
    safety reserve.
17. Each destination derives/adopts the exact child plan and claims compatible
    clean warm capacity or cold-boots according to the admitted launch mode.
18. Each child receives a fresh attempt, boot identity, encrypted channel,
    plan-bound mailbox and artifact bindings, and no lifecycle delegation.
19. Authenticated readiness commits the launch outcome; retries with the same
    idempotency key return the existing handle/result.

Emitted facts after commit:

```text
agent.task created
execution.run admitted/ready
child run admitted
spawnedBy(controller-run, child-run)
requestedBy(child-run, planner-decision)
constrainedBy(child-run, S0)
consumes(child-run, repository-artifact)
```

These facts are appended through the durable outbox and may be projected later.
They do not cause the launch; the authoritative transaction already did.

### 34.4 Worker execution and result delivery

20. Workers consume the exact repository artifact after digest verification.
21. stdout/stderr enters each node's existing bounded redacted stream plane.
22. Structured results are written as content-addressed artifacts and sent as
    private mailbox envelopes containing artifact references.
23. The host stamps sender identity from each worker's boot-bound channel.
24. The controller acknowledges messages transactionally.
25. Artifact manifests record producer attempt/boot/plan, input refs,
    classification, schema, and retention.

Emitted post-commit facts include:

```text
artifact produced
message accepted
message acknowledged
produces(worker-run, output-artifact)
derivedFrom(output-artifact, repository-artifact)
```

Raw private payloads remain in mailbox/artifact stores according to policy;
semantic records carry only allowed summaries and strong references.

### 34.5 Isolated scanners and labels

26. `mvmd` schedules admitted scanner microVMs for the output artifacts if
    required by policy.
27. Each scanner produces evidence as an ordinary artifact and an unsigned
    workload assertion.
28. A separate key-holding label authority verifies scanner provenance,
    evidence, freshness, and trust policy, then signs labels such as
    `pii-detected`, `license-incompatible`, or `artifact-confidential`.
29. The scanner never receives the labeler key and cannot impersonate another
    run.
30. Quarantine labels may narrow immediately according to policy; positive
    authority-widening labels require the configured issuer/evidence/quorum.

### 34.6 Next constraint snapshot

31. The semantic projector updates provenance/compliance views from committed
    facts and labels.
32. The controller determines that a `result-verifier` would improve confidence.
33. If already executable in `P0`, it launches the exact binding under the
    remaining budget. If only requestable, it emits a bounded `CapabilityNeed`.
34. A parent/operator/`mvmd` policy may deny it or compile a replacement
    `ConstraintSnapshot S1` and planning snapshot `P1`.
35. `S1` records exact input refs, label/attestation issuers, ontology/ruleset,
    compiler version, changed bindings/budgets, validity, revocation epoch, and
    signature.
36. The current controller may use the new action only after it receives and
    verifies `P1`/`S1`; stale `P0` cannot widen the live plan.

### 34.7 Completion and scale-down

37. The controller launches the verifier if authorized, receives its result,
    and emits `complete_workflow`.
38. The workflow authority stops accepting new mutations and drains/settles
    bounded mailbox deliveries.
39. Used workers are destroyed, never returned to shared warm capacity.
40. Desired template capacity is reconciled from resident-warm to parked or
    fully cold according to target, TTL, pressure, and quotas.
41. Mailbox, transcript, and artifact manifests are sealed and bound into the
    final workflow receipt.
42. The receipt binds all graph revisions, plans, attempts, boots, snapshot
    digests, artifacts, stream roots, mailbox archive root, policy outcomes,
    and local/fleet audit references.
43. Sanitized public provenance/run-summary records may be published by the
    optional AT bridge after completion; publication failure cannot change the
    terminal authoritative result.

### 34.8 Command/fact separation in the example

| Operation | Authoritative command/transaction | Projected fact after commit |
| --- | --- | --- |
| create task | create task transaction | `task created` |
| claim/launch worker | reservation + launch transaction | `child run admitted/ready` |
| renew lease | lease/fencing transaction | `lease renewed` summary if useful |
| send message | mailbox acceptance transaction | `message accepted` |
| acknowledge message | cursor/ack transaction | `message acknowledged` |
| stop/release child | boot-scoped lifecycle transaction | `child terminated/released` |
| produce artifact | artifact publication transaction | `artifact produced` |
| quarantine | policy transaction | `run/artifact quarantined` |
| change authority | compile/sign replacement snapshot | `snapshot supersedes` |

A firehose, repository, semantic edge, model response, or AppView never serves
as the transaction on the left side of this table.

## 35. Initial issue and workstream breakdown

The implementation plan contains detailed checkboxes. An initial issue series
can be cut along these independently reviewable boundaries:

| Issue | Scope | Acceptance criterion |
| --- | --- | --- |
| Workflow decisions and threat-model freeze | ADR amendments, SLO, encryption/mailbox/production-delegation decisions | No unresolved trust-root or performance boundary before guest lifecycle API |
| Workflow contract and direct-path compatibility | IDs, membership, grants, exact templates/actions, omitted-when-absent fields | Existing direct plans and launch behavior remain unchanged |
| Formal authority and budget semantics | Alloy/TLA+/Lean or equivalent reference models and vectors | Attenuation, conservation, fencing, and graph invariants agree with Rust |
| Transactional constraints and reservation ledger | constraint compiler, ceilings, multidimensional reservations, host safety | Concurrent launch storms cannot oversubscribe or leak reservations |
| Encrypted boot-bound workflow session | handshake, purpose-separated keys, replay, no fallback | Plaintext/downgrade/replayed/wrong-boot frames refuse |
| Process-separated lifecycle service | parser, admission, launch roles and exact permits | Parser compromise cannot directly launch or sign |
| Local workflow vertical slice | one controller, two workers, exact launch/release/capacity | Compromised controller remains inside tiny configured envelope |
| Structured mailbox and artifact receipt | private transactional messages, artifact refs, archives, receipt | Bidirectional results work with bounded storage and no raw audit/public leak |
| Warm/parked/cold reconciler | desired capacity, accounting, clean-parent/private checkpoint rules | Used child never re-enters shared pool; scale-to-zero removes VMMs |
| Graph epochs and supervision | CAS revisions, DAG validation, restart/cancel/fencing/recovery | Iterative workflows recover without cyclic streams or unbounded restarts |
| AI planning snapshot and SDK | finite catalog, planner DTO, model budgets, capability needs | AI ranking cannot change authorized candidate set |
| Recursive delegation/controller groups | subtree budgets, attenuation, host-serialized thresholds | No descendant authority/budget absent from root |
| `mvmd` production workflows | issuer, placement, node verifier, relay, partitions | Destination independently verifies every cross-node effect |
| AT-shaped semantic plane | outbox, records, projectors, labels, deterministic snapshots | AppView outage/staleness cannot affect execution safety |
| Optional AT bridge | pinned Lexicons, sanitized import/export, federation | Bridge compromise/outage cannot trigger or block execution |
| Evidence and claim promotion | fuzzing, mutation, live platform tests, independent review | Claims promote only with real callers and destructive witnesses |

Numbering and repository ownership should be assigned only after the ADR and
plan merge and after the actual `mvmd`/mailbox source trees are inspected.

## 36. Final recommendation

Proceed with the workflow layer, but define it as a capability-secure extension
of the existing single-workload runtime rather than a second orchestrator
inside the guest.

The governing rule is:

```text
AI chooses the desired topology.
The signed snapshot bounds the legal topology.
The transactional authority reserves the legal topology.
The host realizes the legal topology through the existing mvm runtime.
```

A controller has real power to cause admitted microVMs to launch and to manage
clean warm/cold capacity. Its power is nevertheless finite, exact,
non-transferable, boot-bound, descendant-scoped, and subordinate to independent
workflow, tenant, and host ceilings.

AT Protocol should be used as inspiration and, later, an interoperability
surface for semantic records, provenance, replay, labels, and federation. It
must not become the scheduler, constraint engine, forensic audit replacement,
or synchronous authorization dependency.

This architecture produces the intended differentiator without discarding the
reason `mvm` is valuable: isolated one-workload microVMs, exact signed plans,
host-mediated communication, default-deny policy, bounded resources, auditable
lifecycle, and an honest security boundary.

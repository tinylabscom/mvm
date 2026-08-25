# ADR-045 — Capability-secure intelligent workflow controllers

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

**Status:** Proposed  
**Date:** 2026-08-13  
**Related:** ADR-001, ADR-014, ADR-020, ADR-022, ADR-031, ADR-035,
ADR-037 (`mvmd` production authority), ADR-040, ADR-041, ADR-042,
ADR-047 (the agent memory plane); Plan 296,
Plan 298, Plan 308, and Plan 329.  
**Depends on:** ADR-046. The message fabric owns the messaging contract; this
ADR defines no message types of its own and consumes `mvm_contract::fabric`.
The workflow communication workstream cannot start before the fabric's local
mailbox milestone lands.  
**Reconciled by:** ADR-051, which names the shared workload actor model, settles
the vocabulary split against this ADR, and records the rejection of a
third-party actor framework.  
**Research basis:**
`specs/research/intelligent-capability-secure-microvm-workflows.md`.

## Context

`mvm` runs one untrusted-shaped workload per hardware-isolated microVM. Every
boot is described by a typed signed `ExecutionPlan`, admitted before the
backend starts, and recorded in the chain-signed audit log. The guest does not
own the host network, signing keys, hypervisor, or host-service registry.

We want to compose those same single-workload microVMs into intelligent
workflows:

- A controller microVM may launch worker microVMs for specific workloads.
- The controller may use AI to determine which tools, services, model services,
  connectors, and worker microVMs are useful for a goal.
- Workers communicate through host-mediated mailbox, stream, and artifact
  bindings rather than by addressing other guests.
- Clean capacity may move between cold, parked, resident-warm, claimed, and
  running states so workflows can start quickly and scale back to zero.
- The same model must work on one local `mvm` host and across a fleet managed by
  `mvmd`.
- Ordinary direct single-microVM execution must remain supported and must not
  pay the workflow runtime cost.

The dangerous interpretation is to give a controller ambient or general
hypervisor authority. A benign but confused model, a prompt-injected model, or
a malicious controller could then launch enough VMs to exhaust memory, CPU,
processes, descriptors, sockets, disk, audit capacity, or external-provider
budget. Resource limits on one child would not solve recursive fan-out or
launch/terminate churn.

The other dangerous interpretation is to make semantic or eventually
consistent state authoritative. An embedding match, ontology edge, AppView,
AT repository record, or AI response may describe a useful action without
proving the action is authorized, current, affordable, or safe.

This ADR decides the boundary before a guest-reachable lifecycle API is built.

## Decision

### 1. One workload per microVM remains the atomic execution model

The workflow layer is additive.

```text
Direct workload
    = one signed plan + one microVM + one workload

Workflow worker
    = direct workload + workflow membership + communication bindings

Workflow controller
    = workflow worker + delegated lifecycle authority + optional AI planner
```

A controller is not a nested hypervisor, privileged guest, or multi-workload
container. It is an ordinary single-workload microVM whose signed plan carries
additional exact bindings.

The host may run direct and workflow microVMs simultaneously. A direct
workload is not silently represented as a one-node workflow.

### 2. Workflow membership, lifecycle authority, and AI are separate

The valid combinations are:

| Workflow membership | Lifecycle grant | Result |
| --- | --- | --- |
| Absent | Absent | Direct workload |
| Present | Absent | Workflow worker |
| Present | Present | Workflow controller |
| Absent | Present | Invalid; refuse admission |

AI configuration is orthogonal. An AI-enabled direct workload or worker does
not gain launch authority by virtue of using a model.

A running workload cannot be promoted in place. New authority requires a new
signed plan and new boot/attempt.

### 3. A controller has real delegated lifecycle authority

A valid controller command such as `launch_child` is sufficient authority to
cause the trusted host to launch an admitted child. It is not merely an
advisory proposal.

The controller may be granted a closed subset of:

```text
Launch
Release
Terminate
Pause
Resume
Checkpoint
Restore
SetCapacityTarget
CancelDescendant
ObserveDescendant
```

The controller never receives:

```text
/dev/kvm
Hypervisor.framework handles
Firecracker API sockets
libkrun contexts
host PIDs
host paths
raw VmBackend access
signing keys
physical node credentials
```

The host verifies and executes an exact capability. It does not parse natural
language as a lifecycle command.

### 4. Controllers launch exact workload templates

The controller does not submit a `VmStartConfig` or arbitrary image reference.
It selects a plan-local `TemplateBinding` whose host-held definition pins:

```text
template and artifact digests
kernel, initramfs, rootfs, and runtime-overlay identity
entrypoint and parameter schema
resource shape and ceiling
network and host-service policy
secret slots
filesystem/share topology
mailbox and stream slots
input/output schemas
warm compatibility
checkpoint posture
child delegation ceiling
```

The controller may supply only values admitted by the template's parameter and
input schemas. It cannot supply host paths, arbitrary argv/environment,
mutable image tags, raw resource values, network policy, secrets, backend,
VMM flags, or placement.

Different admitted resource sizes are different exact template bindings, for
example `reviewer.small`, `reviewer.medium`, and `reviewer.large`.

### 5. Effective authority is an intersection

Every action is bounded by independent authorities:

```text
effective_child_authority =
    HostSafetyCeiling
    ∩ TenantCeiling
    ∩ WorkflowConstraintSnapshot
    ∩ ControllerLifecycleGrant
    ∩ TemplateLaunchCeiling
    ∩ RemainingTransactionalBudget
```

No controller field can widen the result.

The host and tenant ceilings are not stored in the controller-authored request
or plan-precedence chain. The workflow constraint snapshot is signed by the
local workflow authority in standalone mode or by `mvmd` in fleet mode. The
controller plan binds its digest.

### 6. Resource accounting is hierarchical, transactional, and multidimensional

A workflow snapshot bounds at least:

```text
live workload microVMs
resident VMM slots
total attempts
concurrent launches
launch rate
controller count
delegation depth
children per controller
graph revisions
resident-warm parents
parked parents
private checkpoints
CPU
memory
disk
artifact bytes
mailbox bytes
network bytes
external cost
open file descriptors
host sockets
vsock channels
workflow deadline
```

`max_total_attempts` is non-replenishing. A controller must not evade a
live-VM limit by repeatedly launching and terminating children.

Resident warm parents and preloaded children count against a separate resident
VMM ceiling and are charged for their full admitted memory/process/descriptor
shape. Paused capacity is not free.

All dimensions are reserved atomically before plan derivation, warm claim,
VMM start, large artifact work, child state creation, or host-channel setup.
Two concurrent requests cannot consume the same final slot.

A reservation is released only after the VMM is confirmed dead, leases and
host resources are reaped, and the terminal result is durable.

The host retains an independent safety reserve. Even a valid workflow snapshot
cannot consume the host's final free memory, disk, descriptors, or process
capacity.

### 7. Lifecycle requests are idempotent and single-child

The first lifecycle protocol launches one child per request. It does not expose
an unbounded batch count.

Every mutating command carries a workflow-scoped idempotency key. At most one
live effect may exist for that key. Retries return the same in-progress,
running, or terminal receipt.

The system does not claim exactly-once distributed execution.

### 8. AI chooses among compiled exact actions; it does not create authority

When configured, the AI plans against a finite signed
`ControllerPlanningSnapshot` derived from:

```text
current workflow revision
current descendants and logical topology
constraint snapshot
ontology and ruleset versions
exact executable action bindings
approval-required actions
requestable capabilities
remaining budget
sanitized availability/cost/latency hints
```

Every action is classified as:

```text
Executable
ApprovalRequired
Requestable
Invisible
```

The AI may rank and compose executable candidates. It may request a missing
capability. It cannot promote requestable or invisible actions, increase a
ceiling, or modify the live snapshot.

The controller runtime converts model output into a typed `PlannerDecision`.
Natural-language text, stdout, child output, embeddings, and semantic
similarity are never passed to lifecycle dispatch as authority.

An approved capability increase requires a replacement signed constraint and
planning snapshot. No automatic quota increase follows solely from an AI
request.

### 9. Semantic topology is layered

The system separates:

```text
schema
authenticated facts
typed graph edges
ontology/rules
deterministic constraint compilation
materialized AppViews
local execution enforcement
```

General semantic predicates such as `similarTo`, `specializes`, or
`preferredFor` are advisory. Security-relevant relationships use dedicated
signed records and validators, such as delegation, launch admission,
controller lease, and constraint snapshot records.

Approximate semantic similarity never widens authority. The constraint
compiler may use semantic facts to produce a finite exact candidate set before
the planning epoch. Execution selects a binding from that set.

### 10. Workflows contain three graphs

- **Authority graph:** a rooted acyclic forest of attempts and delegation.
- **Dataflow graph:** a DAG per committed revision; one stdin writer; fan-in
  requires an explicit merge workload.
- **Causal graph:** messages, replies, approvals, decisions, attempts, and
  results linked by correlation and causation IDs.

Child-to-parent replies do not create reverse stdin edges.

Iteration is represented through append-only graph revisions/epochs. Every
revision is validated before it can launch new nodes.

### 11. Communication remains host-mediated

The workflow layer uses four separate planes:

| Plane | Purpose |
| --- | --- |
| Control | Lifecycle, approval, graph, and capacity commands |
| Mailbox | Structured tasks, messages, replies, and results |
| Stream | stdout/stderr and admitted output-to-input DAG edges |
| Artifact | Immutable large payloads and checkpoints |

Guests use plan-local bindings, never physical node addresses, host socket
paths, raw vsock CIDs, or sibling `VmId`s.

Mailbox commands and acknowledgements are transactional. Lifecycle facts are
emitted only after the authoritative transaction commits.

Mailbox delivery is at-least-once and idempotent, bounded by message, payload,
route, workflow, disk, TTL, and rate limits. Raw private mailbox contents are
not published into a normal public semantic/AT repository.

stdout and stderr are untrusted data, not a control protocol.

### 12. Clean capacity may scale down; used workload state is never shared

Capacity states are distinct:

```text
Cold template
Parked clean parent
Resident warm parent
Claimed child
Running child
Private actor checkpoint
```

Reusable parents contain no tenant/workload authority, secret, destination,
mailbox payload, or mutable child state.

A used child is flushed, sealed, stopped, and destroyed. It never becomes a
shared warm parent. If the desired clean-capacity target remains above zero,
the host replenishes a fresh clean parent.

A stateful actor may use a private checkpoint bound to its workflow and logical
actor. Restoring it creates a fresh boot identity, session keys, credentials,
and grants. The private checkpoint cannot become generic warm capacity.

A controller may be granted `SetCapacityTarget`, but the effective target is
bounded by template, workflow, tenant, and host-pressure policy. The host may
reduce warm capacity under pressure unless a separate operator-defined
reservation is what makes it hold.

Host-owned events and monotonic timers execute idle TTL and scale-down policy;
the controller need not remain resident to run timers.

### 13. Direct execution remains operationally absent from workflow machinery

For a direct plan:

```text
workflow membership = absent
lifecycle grant = absent
```

The runtime does not initialize a workflow journal, reservation ledger,
controller lease, mailbox router, capacity reconciler, semantic index, AT
bridge, or fleet workflow resolver.

Calling the workflow host service from a direct workload returns the same
`NotBound` response as any other ungranted host service.

Workflow fields are optional and omitted when absent so existing serialized
plans and frozen vectors are preserved where compatibility requires it.

### 14. Local and fleet workflow authorities implement one contract

A local workflow authority places every child on the current host, uses the
existing local signer/admission path, and remains development posture.

`mvmd` owns production workflow issuance, graph truth, fleet reservation,
placement, controller fencing, routing, and reconciliation. Nodes hold
verifying material and independently verify every launch and route grant.

The production launch rule is refined as follows:

> Every production launch remains rooted in authenticated `mvmd` authority.
> `mvmd` may issue a narrow, boot-bound workflow lifecycle delegation to an
> admitted controller. A child is production only when the executing node
> verifies the delegation chain, controller generation, exact template,
> constraint snapshot, reservation, plan, audience, expiry, and replay state.

The controller is not a fleet issuer and cannot choose physical placement or
mint node-verifiable authority.

Distributed control and mailbox traffic may use mediated node/control-plane
routing before general guest cross-node L3 exists.

### 15. Parser, admission, and launch authority are separate roles

The guest-facing process parses bounded encrypted frames and derives caller
identity. It holds no signer key, reservation authority, `VmBackend`, or VMM
handle.

A separate admission role verifies the snapshot, lifecycle grant, template,
generation, and budgets; reserves resources; and records the durable intent.

A launch role accepts no guest connection and no arbitrary launch config. It
executes an exact local launch permit that binds workflow, controller boot,
generation, template digest, child plan digest, reservation, idempotency key,
expiry, and nonce.

External AT/CAR/CBOR/DID parsing is isolated in another keyless process that
cannot launch workloads.

### 16. Guest-host workflow channels are encrypted and boot-bound

Lifecycle and mailbox requests use authenticated encrypted sessions with no
plaintext fallback. Sessions bind protocol, channel purpose, tenant, workflow,
boot ID, plan digest, controller generation, sequences, and key generation.

The cryptographic mechanism is selected in a follow-up ADR and must use an
established primitive, explicit replay protection, version downgrade refusal,
strict frame bounds, rotation, and teardown zeroization.

### 17. AT Protocol surrounds the system; it is not the scheduler

`mvmd` should first implement an AT-shaped internal semantic log over its own
transactional database and durable outbox:

```text
namespaced typed records
URI-plus-digest strong references
replayable streams
cursors and gap detection
snapshot/resync
idempotent AppView-style projectors
```

Full PDS/repository/MST/CAR/relay compatibility is optional and isolated.

No boot, packet, child spawn, secret release, local audit verification, or
immediate capability decision depends on a PDS, relay, AppView, online DID
resolution, external OAuth server, external repository write, or eventually
consistent semantic state.

Repository signatures prove publication authorship, not truth or
authorization. CIDs identify bytes, not principals or permissions. The local
chain-signed audit remains authoritative forensic evidence.

### 18. Host-mediated tool calling is broker dispatch, and the catalog derives from the plan

Two different things get called an agent's tools, and only one of them is
this project's to govern.

**In-guest tools run inside the workload's own microVM**: a shell, a browser
driver, a test runner, an interpreter, whatever the image carries or the agent
installs. These are processes in the agent's own sandbox. mvm does not build
them, catalog them, enumerate them, or permission them. An agent may choose
freely among them, and the set is unbounded and mostly third-party by design.

That is safe because of what the tier already is rather than because of any
new control. A workload microVM has no NIC, its rootfs is dm-verity sealed,
and it reaches no host filesystem beyond its explicit shares. A browser driver
inside that VM can render, script, and drive an engine all it likes, and none
of it leaves. Governing the toolbox would add ceremony without adding
containment, because the boundary already contains it.

**Host-mediated tools cross that boundary**: outbound network, secrets, audit,
memory that outlives the VM, and — under section 3 — spawning another VM.
These are the boundary, so they are the entire subject of this section, and
there are on the order of half a dozen of them rather than an open registry.

The distinction the design rests on is that authority attaches to *effects*,
not to *tools*. An agent's choice of browser driver is its own business; that
driver's outbound request is admitted or refused by destination at the
per-VM substitution endpoint. The tool stays unrestricted and its effect stays
governed, which is why nobody has to predict the toolbox in advance.

Section 8 governs what a *controller's planner* may do to the workflow graph.
It does not govern either category above. The host-mediated surface is not a
new plane: it is the host services broker of ADR-020, and it stays there.

Every host-mediated tool an agent may call is a `ServiceId`
(`host.<name>.v<n>`) bound in
`ExecutionPlan.services` and enforced before handler dispatch (claim 12).

The direction of derivation is the decision:

```text
ExecutionPlan.services  ->  the tool catalog presented to the model
```

never the reverse. An agent does not register, declare, or negotiate a tool
into existence. A model emitting a call to an unbound name meets the existing
binding gate, and the refusal is audited — a planning signal rather than an
error condition.

An agent may implement whatever internal capability-negotiation pattern it
likes: a permission prompt, a self-issued scope, a tool-use policy of its own
design. Those are planner heuristics. They terminate at the `Requestable`
class of section 8, where a request is not a grant and a grant requires a
replacement signed constraint snapshot. **An agent's model of its own
permissions and the host's binding of them are separate objects, and are never
unified.**

Dynamic tool namespaces — Model Context Protocol and equivalents — are
admitted host-side only:

- The host runs the client; no guest speaks the protocol outward.
- Each upstream tool compiles to a `ServiceId` at admission, inside the plan
  digest.
- Discovery verbs are served from the plan binding, not proxied upstream.

An upstream server that adds, renames, or redefines a tool mid-session
therefore cannot widen a running guest's surface. A guest-side client speaking
outward would reintroduce an unaudited egress path and a mutable namespace,
which the vsock-only posture of ADR-001 claim 10 and ADR-003 exists to
prevent.

What this does **not** restrict is a tool server running entirely inside the
guest — a local subprocess an agent talks to over its own stdio or loopback,
which is how much of that ecosystem is packaged. That is an in-guest tool: it
is the image's business, it is unrestricted, and any outbound request it makes
is admitted by destination like every other. The rule is about a guest
originating connections to a remote server, not about the protocol.

A host-mediated tool surface is fixed for the lifetime of an admission. It
changes at an epoch boundary, by re-admission, or not at all. A mid-epoch
mutable namespace is unauditable by construction: there is no finite set to
have checked. The in-guest toolbox has no such rule and needs none — it is
bounded by the VM, not by a list.

### 19. Tool results are data, and injection cannot widen the action set

A tool result is attacker-influenced content — a fetched page, a repository
issue, a sibling's message, a file written by an earlier untrusted step. It
arrives as data on the stream and mailbox planes of section 11, under the rule
that section already applies to stdout and stderr: untrusted data, not a
control protocol.

That yields a bound worth stating plainly:

```text
worst case under prompt injection
  = the agent selects a different action from its bound set
 != the agent obtains an action outside that set
```

An injected instruction may change which bound tool is called, with which
arguments, in which order. It cannot mint a binding, widen egress, raise a
ceiling, or reach a `Requestable` or `Invisible` action. The blast radius is
the section 5 intersection, and it is the same bound whether the agent is
honest, confused, or wholly steered by its input.

Two consequences the implementation must not erode:

- Argument values drawn from a tool result remain untrusted. Binding gates the
  *tool*; per-tool argument policy — destination allow-lists, path scoping,
  size bounds — constrains the *call*, and is host-side. A bound tool with an
  unconstrained argument is an unbound tool wearing a name.
- A tool result is never a channel for authority. Approvals, capability
  grants, and constraint snapshots arrive as signed host-side records under
  section 8, never as content an agent reads and acts upon.

## Security invariants

The implementation must preserve all of the following:

```text
1. Every microVM runs exactly one workload.
2. Direct workloads have no workflow lifecycle binding or workflow state.
3. A controller's launch authority is explicit, exact, boot-bound, and
   non-transferable.
4. Every child launch selects an exact template digest.
5. Every child capability, egress, secret, filesystem, and tool set is a subset
   of every applicable parent/root ceiling.
6. A controller manages only descendants in its workflow and authority domain.
7. Workflow, tenant, and host budgets never become negative.
8. One idempotency key has at most one live effect.
9. A stale controller generation cannot mutate lifecycle or graph state.
10. Every live attempt has a verified signed plan.
11. Every attempt has one authority parent/root.
12. Dataflow is acyclic per committed revision.
13. Every stdin has at most one writer.
14. Message sender identity is channel-derived.
15. Every security effect has a prior durable intent.
16. A released reservation implies no remaining live host effect.
17. Every artifact is attributable to one attempt and boot.
18. Information classification cannot decrease without an admitted
    declassification capability.
19. Unknown schema, ontology, or ruleset versions cannot widen authority.
20. Semantic assertions cannot widen a live constraint snapshot.
21. A used workload VM never reenters shared warm capacity.
22. Guest-visible handles do not expose physical host routes or authority.
23. Every host-mediated tool is a plan-bound service; the catalog presented to
    a model derives from that binding and never the reverse. Tools running
    inside the guest are out of scope, and the microVM boundary is what
    bounds them.
24. No guest speaks a tool-discovery protocol outward; upstream tools compile
    host-side at admission, inside the plan digest.
25. A host-mediated tool surface is fixed for the lifetime of an admission.
26. Tool results are data on the stream and mailbox planes, and carry no
    authority.
```

## Consequences

### Positive

- Preserves the single-workload security model while enabling genuinely
  autonomous workflows.
- Gives AI controllers meaningful power without making a model a policy engine
  or allocator of host capacity.
- Makes a controller compromise bounded and measurable.
- Reuses signed plans, host-service bindings, streams, warm pools, grants,
  audit, and backend lifecycle instead of implementing a second VM runtime.
- Supports local and fleet workflows through one guest-facing contract.
- Allows clean capacity to scale to zero without reusing mutated children.
- Provides a path to formal proofs and deterministic counterexamples for the
  hardest authority and concurrency properties.
- Enables AT-compatible semantic/provenance federation later without placing
  external infrastructure in the trusted launch path.

### Negative

- A guest-reachable lifecycle API is a new high-value parser and authorization
  surface even with process separation.
- The workflow transaction journal and reservation ledger introduce durable
  state and crash-recovery complexity.
- Multidimensional host accounting must include resources that ordinary
  workload grants do not currently model, such as VMM processes, FDs, sockets,
  channels, warm parents, snapshots, mailbox bytes, and external cost.
- Dynamic warm capacity complicates the current replenish-on-release behavior.
- AI planning introduces prompt-injection, model-provider data, token/cost,
  model-supply-chain, and planner-loop risks, though those risks remain inside
  the workflow envelope.
- Production controller delegation requires a precise refinement of ADR-037.
- Encrypted sessions require a follow-up cryptographic decision and migration.
- `mvmd`, mailbox, semantic projection, and optional AT compatibility span
  multiple repositories and operational roles.

### Neutral but important

- A workflow receipt is intended to attest admitted configuration and recorded lineage, not
  semantic correctness of the AI result.
- Redaction cannot prevent all semantic or steganographic exfiltration.
- The host remains trusted under ADR-001 unless a separate confidential
  computing decision changes the threat model.

## Alternatives rejected

### Give the controller a host VMM or hypervisor API

Rejected. It expands authority from exact lifecycle verbs to arbitrary host
execution and makes host safety dependent on guest correctness.

### Run nested virtualization inside the controller

Rejected. It is unnecessary for composition, weakens portability and
observability, complicates resource accounting, and enlarges the escape
surface.

### Treat every direct workload as a one-node workflow

Rejected. It imposes graph, journal, mailbox, and resident-service cost on the
ordinary path and obscures the user's execution intent.

### Let the controller submit arbitrary `VmStartConfig`

Rejected. Host paths, mutable images, backends, resources, policy, and secret
bindings become attacker-controlled launch inputs.

### Let the AI dynamically authorize semantic classes at launch time

Rejected. Mutable ontology state, semantic similarity, and model output are not
suitable authorization inputs. Semantic classes are compiled into a finite
exact candidate set before the planning epoch.

### Use one live-VM limit as the resource control

Rejected. It does not bound warm parents, snapshots, churn, disk, descriptors,
network, or external cost.

### Return a used child to the shared warm pool

Rejected. Workload, secret-derived, filesystem, model-context, flow, and
kernel state could cross workload boundaries.

### Make the AppView or AT firehose the scheduler

Rejected. Materialized views and event streams do not provide transactional
claims, reservation, fencing, or authoritative current state.

### Replace chain-signed audit with an AT repository

Rejected. Authenticated repository state and optional history do not provide
the same append-only forensic properties, and publication deletion/rollback
must not erase the local source of evidence.

### Fully opaque guest-to-guest communication by default

Rejected. It prevents host-side routing authorization, schema validation,
redaction, classification, and audit attribution. End-to-end opaque payloads
may be a separately admitted feature where those services are intentionally
forgone.

### Permit recursive delegation in the first slice

Rejected for the initial rollout. Depth-one controllers with non-delegating
workers provide the required product proof with a much smaller authority state
space.

## Follow-up decisions and amendments

Before implementation reaches production:

1. Amend ADR-001 with the controller, workflow, mailbox, resource-amplification,
   semantic-planning, and cross-node threat model and preview claims.
2. Amend or supersede ADR-037 with the precise `mvmd`-rooted delegation rule.
3. Write a guest-host encrypted-session ADR reconciling ADR-008 and ADR-020.
4. Write or finalize the mailbox transactional-storage and archive ADR.
5. Decide private actor checkpoint semantics and classification/declassification
   policy if not fully covered by existing checkpoint decisions.
6. Inspect the actual `mvmd` repository and record the issuer, journal,
   reservation, placement, routing, semantic outbox, and projector boundaries.
7. Keep true AT Protocol compatibility behind a separate optional ADR after the
   AT-shaped internal model turns out to be useful.
8. Settle per-tool argument policy (section 19) as a typed, host-side schema
   per `ServiceId`, rather than per-handler validation that each new service
   reimplements.
9. Decide whether a controller's own planner tools and a workload agent's
   tools share one catalog derivation, or stay two surfaces with one rule.

## Acceptance boundary

This ADR is not considered implemented merely because contract types exist.
The first shipped claim requires:

- A real single-host controller caller.
- Exact template-bound launches through the ordinary single-machine path.
- Atomic resource and attempt accounting.
- Host safety reserve enforcement.
- Parser/admission/launch process separation.
- Structured mailbox result delivery.
- Used-child destruction and dynamic clean-capacity reconciliation.
- Crash injection across every lifecycle transaction boundary.
- Stale generation, replay, cross-workflow, and mass-launch refusal tests.
- Direct-path absence and performance witnesses.
- Formal/reference-model vectors for authority, budget, and graph validation.

Implementation is planned in
`specs/plans/2026-08-18-capability-secure-intelligent-workflows.md`.

Sections 18 and 19 are implemented in
`specs/plans/2026-08-18-agent-tool-and-memory-planes.md`.

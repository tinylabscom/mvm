# ADR-064 — Critical-systems profile: sealed topology, core placement, standby pairs and host-held state cells

Backing: preview
Validation: none — this is a proposed design; no code implements it and no
test exercises it.

**Status:** Proposed
**Date:** 2026-11-17
**Owner:** `mvm` maintainers
**Extends, if accepted:** ADR-062 (workload actors: epochs, residency,
supervision, cryptographic agility) and the
[host interface contract](../contracts/host-interface-distributed-execution.md).
**Complements:** ADR-001, ADR-014, ADR-022, ADR-025, ADR-042, ADR-052,
ADR-057 and ADR-059.
**Related issues:** #5097 (host interface), #5544 (workload actors), #5292
(shared mailbox scheduler), #5510 (density), #5676 (disconnected host
authority, open), tinylabscom/mvmd#256 and tinylabscom/mvmd#260.
**Tracked in:** #5686. Nothing here may be described as shipped, and no
ADR-001 claim changes, until the evidence listed at the end exists.

## Context

MVM is being evaluated for safety-critical and resource-constrained systems:
vehicles, medical devices, industrial controllers. Those systems make demands
the product does not meet today:

- A supervisory controller and each critical function are bound to named
  processor cores, and the binding is part of the reviewed configuration.
- Every critical function has a standby that takes over within a known time,
  and the standby is itself replaced.
- Exactly one unit may write a given piece of shared state. Others may read it.
- Nothing about a running system changes after it is admitted.
- The same model must hold on an 8-core device and a 64-core host, on Linux
  with KVM, on a hypervisor MVM does not own, and on a microcontroller that
  cannot host a VM at all.
- The cost of running MVM itself must be published as measurements, and idle
  power draw must be low.

What exists (2026-11-17):

- ADR-062 (proposed) already decides host-applied restart policy from the
  signed plan, one execution epoch per VM lifetime, residency as a condition,
  and the order of post-quantum work. This ADR does not restate them.
- The host interface contract (#5097, proposed) already decides that a launch
  fails closed, that local and remote implementations share one contract, and
  that a disconnected node runs only under a signed, preloaded lease.
- Warm standbys exist on Firecracker and HVF as a launch-speed mechanism. No
  code restarts a failed VM except one HVF health probe.
- No code binds a VM to a core. No memory is shared between VMs, and several
  ADRs make vsock the only guest data path.
- The plan envelope names no signature algorithm. Only x86_64 and aarch64 are
  guest architectures.
- `mvmd` runs one controller with no failover and places work on a host by
  node or label, never on a core.

## Decision

### 1. A profile is a set of signed requirements, not a mode

There is no "critical mode" switch. A deployment states requirements, each
optional and independent: core placement, standby class, recovery bound, state
cells, minimum isolation tier, cryptographic suite. A deployment that states
none behaves as it does today.

Every requirement is enforced or refused. Under this profile a backend may not
record a requirement as merely declared (the tier claim 18 uses for a CPU grant
the host cannot enforce). A backend states, in the resource-controls matrix,
what it enforces for each requirement; admission compares the two and refuses
with the unmet requirement named.

### 2. The topology is one signed document

Standby pairs, core maps and write authority span several workloads, so a plan
per VM cannot express them. A **topology** names the whole system:

| Element | Content |
| --- | --- |
| Units | Workload ID, role (controller or worker), recipe hash (the image or bundle digest, never a plan ID), resources, and which of sleep, wake, pause and checkpoint it permits (none by default), and an optional liveness period |
| Placement | A set of host core IDs with an exclusive flag, or floating |
| Standby | Class (resident, warm, cold or none), its placement, recovery bound |
| State cells | ID, size, the one writer unit, the reader units |
| Edges | Every mailbox route, stream edge and egress destination |
| Supervision | The ADR-062 restart policy, plus the controller succession order |
| Suite | Signature and key-establishment algorithms |

Each unit still boots from its own signed plan, as claim 8 requires. The plan
carries the topology digest and the unit's name in it; admission refuses a plan
whose topology is absent, differs, or does not name that unit. Locally the host
signs the topology; in managed mode `mvmd` does, and carries it to each node
inside the signed placement lease it already uses for plans.

The topology is a new signed format, so it names its algorithms from its first
version (section 12).

### 3. Sealed after admission

Admission is the signing stage. After it, a unit's configuration does not
change. Under this profile the host refuses, and audits the refusal of:

- balloon target changes and any other change to configured memory;
- volume mount or unmount after boot, and any refresh of an attached volume;
- idle-timeout updates;
- sleep, wake, pause and checkpoint, unless that unit's entry in the topology
  declares them;
- any grant or verb-grant change;
- policy rollover onto a running unit, should live rollover be built. Today a
  policy generation activates only on an idle host.

The refusal is made by the host. Several of these requests are ordinary
production verbs of the guest agent, so the agent's own request classes do
not stop them.

Stopping a unit is not reconfiguring it. Revocation, quarantine, termination
and the wall-clock kill act on a sealed unit exactly as they do today, and a
sealed unit never becomes harder to stop.

A critical unit is not parked for being idle. ADR-062's residency rules apply
to it only if the topology declares a residency policy for that unit.

A change to anything in the topology is a new topology generation: a new
signature, a new admission, and new epochs for the units it touches. The
topology carries its generation number and a validity window; a host refuses a
topology outside its window and a generation lower than the last one it
admitted. Promotion of a standby is not a change. The standby, its plan and its
authority were admitted with the topology; promotion selects among admitted
alternatives.

A warm standby is created before it has an identity: today its verb grant,
seccomp tier and volumes are delivered when it is claimed. Under this profile
that delivery is part of admission. Every value handed to the standby at claim
time comes from its plan, which was signed with the topology before the
standby existed. Nothing is chosen at claim time, and a claim that would
deliver anything else is refused.

### 4. Core placement

A unit's placement is a set of host core IDs. The core that hosts the
controller is a value in the topology, not a constant in the code; core 0 is a
convention the deployment may follow.

- **Exclusive** placement gives the unit's vCPU threads those cores and admits
  no other unit to them. A failover standby may share its active unit's cores,
  because only one of the pair runs. While a topology with exclusive cores is
  admitted, the host confines every floating unit and MVM's own host processes
  to the remaining cores. Processes MVM does not start are the host's
  configuration, covered by the isolation check below.
- **Floating** placement leaves scheduling to the host. This is today's
  behaviour and the default.

Enforcement, by host:

| Host | Mechanism | Read back |
| --- | --- | --- |
| Linux, Firecracker | Allowed-CPU set on the spawn scope that already carries the CPU, memory and task bounds | Effective cpuset of the scope |
| Linux, in-house VMM (does not exist yet; section 8) | The same scope, plus per-vCPU thread affinity | Thread affinity |
| macOS, HVF | None exists | Refused |
| Third-party hypervisor | The hypervisor's own partition schedule | What it reports |
| Microcontroller | One task per core as the runtime allows | What it reports |

The spawn scope exists only on a host with a systemd user session, and the
cpuset controller must be delegated to it. Without either, the other bounds
fall back to declared; a placement requirement is refused instead. `mvmctl
doctor` reports both conditions.

The achieved placement is read back and recorded in the same audit entry as
the other enforced bounds. MVM does not reconfigure the host kernel. Whether
the named cores are isolated from the general scheduler is a host property that
`mvmctl doctor` reports and that admission checks when the topology requires
it.

### 5. Standby pairs and failover

A unit declares a standby class and a recovery bound in milliseconds. "Standby"
here means a failover standby for one named unit. It reuses the warm-start
machinery but is not the anonymous launch-speed pool of ADR-025.

| Class | What exists while the active unit runs | Typical use |
| --- | --- | --- |
| Resident | A booted, admitted standby under its own epoch, idle | The controller; functions with the tightest bound |
| Warm | A preloaded or snapshot standby, not running | Most critical workers |
| Cold | Nothing; rebuilt from the recipe | Functions that tolerate a restart |

A resident standby runs beside its active unit, which ADR-062 does not allow
for: it has one current epoch per workload and every broker refuses the rest.
This ADR adds a **standby epoch**: admitted with the topology, accepted by
brokers for cell reads only, and refused for writes, mailbox receipt and
egress. Promotion makes it the current epoch. That is an amendment to
ADR-062 section 3.

Epoch authority is decided in one place. A single gate answers whether an
epoch may perform an operation, and every host service calls it: the mailbox,
the egress gate, the cell service and the host-service broker. No service
compares epochs itself, and a build check fails if one does. The gate's rule
is one table with a default of refusal: a current epoch may do what its plan
grants, a standby epoch may read its unit's cells, and every other epoch is
refused. Fencing a failed epoch and promoting its standby are therefore one
update to the gate's input, not a message to each service.

Two epoch types exist today, the mailbox contract's and the host interface's,
and about thirty production sites compare epochs inline, most of them in
mailbox code. They become one type, owned by the gate. That work lands with
the state cells of section 6, which are the gate's first new caller.

Failure is detected by the host, never by the guest, in two layers.

The first is always on and costs nothing while a unit is healthy. The host
process that owns a unit learns from the operating system when the unit's
process exits or a vCPU faults, and the wall-clock bound fires from the same
process. No message, timer or wakeup is involved, and nothing waits for a
missed beat.

The second detects a unit that is alive but stuck, and is opt-in. A unit may
declare a liveness period in the topology. The host holds one deadline for
that unit and resets it on any traffic the epoch gate accepts from the unit's
current epoch: a cell write, a mailbox send, or an explicit liveness signal.
A unit sends the explicit signal only when it has had nothing else to say for
a period, so a busy unit pays nothing extra. When the deadline passes, the
host applies the same failover sequence as for a crash. A unit that declares
no period has the first layer only.

The rules that keep this safe:

- Only traffic on the unit's own vsock channel, under its current epoch,
  resets its deadline. A standby epoch, another unit and the controller
  cannot.
- The deadline is held by the host process that owns the unit, not by the
  controller, so a failed controller does not blind detection. Detecting a
  failed host is the fleet's job, through the host lease.
- The period is part of the sealed topology and cannot change after
  admission.
- The deadline runs on a monotonic clock. A host that can suspend refuses a
  liveness period, because every deadline would expire at once on resume.
- An early expiry on a loaded host fails in the safe direction: the old epoch
  is fenced before the standby is promoted, so there are never two writers.
- Expiry and promotion are audited. Individual liveness signals are not.
- A recovery bound shorter than the liveness period plus the measured
  promotion time is refused at admission.

Liveness here means the unit can still send. Whether what it sends is correct
is the application's concern. On the microcontroller tier the deadline maps to
the hardware or task watchdog, and on a third-party partition hypervisor to
its health monitor. This is separate from the host interface's per-node
heartbeat.

Failover is one host-applied sequence, each step a host-witnessed event:

1. Fence the failed epoch. Every broker, cell and mailbox refuses it from this
   point.
2. Promote the standby: its epoch becomes the unit's current epoch, the
   unit's mailbox is delivered to it under ADR-057's epoch fencing, and it
   gains write authority over the unit's cells. No resolver is involved; a
   unit has one mailbox address before and after.
3. Provision the next standby of the declared class.

The crashed guest's memory is never resumed (ADR-062 section 4). A failover
that cannot complete step 3 leaves the unit running without a standby; that is
a reported condition that goes to the escalation mailbox, not a silent state.

The recovery bound is checked twice. Admission refuses a bound when the
performance budget registry holds no measured failover figure for that host,
backend and standby class, and a bound tighter than the figure it holds. At
run time, a failover that exceeds its bound is recorded as exceeded.

MVM does not claim that a unit never fails. It claims that failure is detected
by the host, that recovery is bounded by a measured figure, and that an
exhausted standby chain is reported.

### 6. State cells: one writer, held by the host

No memory page is mapped into more than one VM, and no memory is shared
between a guest and anything else outside vsock. "Only the leader writes"
is built on the host:

- The topology declares each cell: an ID, a fixed size, one writer unit and
  its reader units.
- At admission the host reserves and locks the cell's memory. If it cannot,
  admission fails.
- The writer updates the cell through a host service on its vsock channel.
  The host accepts a write only from the current epoch of the declared writer
  unit, and only with a version greater than the stored one.
- Readers read the cell through the same service. They cannot write.
- A failover standby reads the cell once, when it is promoted. Nothing is
  delivered to it before that, so a standby costs no cell traffic and no
  wakeups, and resident and warm standbys behave alike. The read is part of
  the recovery bound.
- A unit whose standby must track state to be useful at once may declare
  **follow**. The host then signals that the cell changed and the standby
  reads the latest value when it next runs. Signals coalesce: a slow standby
  skips intermediate values, and there is no queue to fall behind on.
- On failover, write authority moves in step 2 of section 5.

The controller's cell follows the same rule. A backup controller gains write
authority only by promotion; there is no separate recovery-mode write path.

Authority changes are always audited. Per-write audit is a topology setting.
The default is a periodic signed digest of the cell. A topology may ask for an
entry per write, and admission refuses it when the declared write rate exceeds
what the host's measured audit budget sustains. A cell costs one copy per
update, and its update latency is part of the published report (section 9).

This uses the host-service broker, so claim 12's rule applies unchanged: a
cell is reachable only through a binding in the signed plan. Three things are
new. The plan's binding names only the service, so the cell ID and the
writer or reader role come from the topology. The broker's call context
carries no epoch today and gains one. And the existing key-value service
stores per workload, so a cell, which several units address, needs its own
store.

A topology belongs to one tenant, and so does every cell in it. A cell is a
fourth state class beside the three of ADR-062 section 2: it survives an epoch
because the host holds it, and it does not move between hosts.

### 7. The controller is a role, not a privilege level

A controller is the unit whose job is to decide when to start, stop and fail
over other units. It may be a small host process or a VM. In both forms:

- Its only authority is a mailbox capability to send launch, stop and promote
  requests for units the sealed topology names.
- The host interface admits each request through the fail-closed preflight. A
  controller cannot introduce a unit, alter a plan, or reach a hypervisor.
- Requests for units on another host travel over `mvmd`'s transport, which
  ADR-057 makes the owner of cross-host delivery.
- A controller VM is as isolated as any guest. Compromising it yields the
  ability to request admitted transitions, which the host audits.

The topology lists the controller succession in order. For a deployment with
core-bound units there is no election: the backup is resident, and it takes
over by the failover sequence of section 5. Election is permitted only when
every affected unit is floating and the topology asks for it; the commit
authority is then `mvmd`'s replicated store, never gossip.

If every controller in the succession is gone, the host applies the topology's
static restart policy itself. Supervision does not depend on a controller
being alive.

### 8. One profile, several isolation mechanisms

A **unit** is what the topology names. What isolates it depends on the host:

| Tier | Isolation | Hosts |
| --- | --- | --- |
| VM | Hardware virtualization | Linux/KVM through Firecracker; the in-house VMM on HVF, on KVM, and later on bare metal |
| Partition | A hypervisor MVM does not own | A driver that maps a unit to that hypervisor's partition |
| Task | Memory protection without virtualization | Microcontrollers |

All three verify the same signed topology and plans, apply the same admission,
use the same mailbox and cell semantics, and emit the same evidence. For the
task tier that requires the plan and topology verifiers to live in
`mvm-contract`, which is free of the standard library. Today it holds the
audit-log and Merkle verifiers; plan verification is in `mvm-core`, and the
32-bit microcontroller build of `mvm-contract` is compiled but never run
(ADR-022). A topology may require
a minimum tier, and the tier a unit actually ran under is recorded.

A microcontroller does not host a VM and this ADR does not pretend it does.
Its driver maps a unit to a task and reports the task tier.

Guest architectures become x86_64, aarch64 and riscv64. The in-house VMM's
device tree, interrupt controller and boot header code is arm64-only today and
splits by architecture. On Linux the in-house VMM needs a KVM implementation
of the hypervisor traits that only HVF implements; that implementation is the
shared step toward both RISC-V and bare metal.

Order of work: Linux/KVM through Firecracker, then the in-house VMM on KVM,
then a third-party hypervisor driver and the task tier.

### 9. Published resource report

`mvmctl` produces a measured report, per backend and architecture, of what MVM
itself costs:

- fixed host cost with no units: memory, idle CPU, wakeups per second, disk;
- per-unit cost by residency (running, idle, parked) and by standby class;
- cold launch, warm launch and failover latency, with percentiles;
- state-cell update latency and mailbox round-trip latency.

It extends the existing launch benchmark and footprint measurement instead of
adding a second harness. Its figures feed the performance budget registry, and
a fit check compares a topology with a host inventory and answers whether the
topology fits, naming the first resource that does not.

The report is the first deliverable, because sections 4 to 6 each admit
against a measured figure.

### 10. Power

Idle wakeups are the proxy MVM can measure everywhere; energy is reported
where the host exposes a counter.

- No host component of an idle unit polls on a timer. Today the HVF supervisor
  wakes every 5 ms and several host loops wake every 500 ms; under this
  profile they become event-driven or are refused.
- Guests boot with tickless idle.
- A warm standby holds no vCPU and no timer. A resident standby is the
  expensive class and is chosen per unit for that reason.
- The report of section 9 includes wakeups per second per unit.

No power figure is claimed until it is measured on the target class of
hardware.

### 11. A static, derivable data path

The topology lists every edge. The complete data-flow graph of a deployment
is therefore computable from one signed document, before boot:

- an edge absent from the topology is refused at the host;
- queues on every edge are bounded, with the bound in the topology;
- `explain` renders the graph and marks each edge with its observed traffic.

This adds no path. It is the existing single vsock flow path (ADR-042,
ADR-052) with its allowed endpoints fixed in advance.

### 12. Cryptographic suite

ADR-062 section 7 sets the order: algorithm-explicit formats, then hybrid key
establishment, then hybrid signatures on long-lived artifacts. This ADR adds:

- The topology names its signature algorithm from version one.
- A topology selects a suite. A CNSA 2.0 suite uses ML-KEM-1024 and ML-DSA-87
  with AES-256 and SHA-384 or SHA-512, always in hybrid with the existing
  classical algorithms; a suite without the classical half is refused. ADR-062 proposes ML-KEM-768 and ML-DSA-65 as
  the general default; both parameter sets must be selectable, and admission
  refuses a suite the build does not implement.
- An algorithm identifier provides no protection by itself. None of this is
  implemented, and the build gate that fails when a post-quantum dependency
  appears before the claims are updated stays in force.

### 13. `mvmd`

- Carries the fleet-signed topology and binds its digest into each placement
  lease.
- Treats a unit's core set as a hard placement constraint on a named node.
- Runs a fixed primary and backup controller for deployments that forbid
  election (tinylabscom/mvmd#256, tinylabscom/mvmd#260).
- Relocates a unit to another host only when it is floating, with the fencing
  the host interface already requires. A core-bound unit fails over on its own
  host only.

## Consequences

- The plan gains a topology binding, and a new signed topology format exists.
  Both are schema changes that old verifiers refuse.
- The resource-controls matrix gains a core-placement answer for every
  backend, and the gate that requires an explicit answer applies to it.
- The host-service broker gains a cell service. The vsock-only rule and its
  build gates are unchanged.
- Under this profile, balloon-based reclaim is unavailable, so a critical unit
  is charged its configured memory for its whole life. Density comes from the
  floating units that share the remaining cores.
- ADR-062's restart policy gains failover to an admitted standby as a
  strategy, its section 3 gains the standby epoch, and its section 2 gains
  host-held cells as a state class.
- Plan and topology verification move into `mvm-contract`.
- HVF on macOS cannot satisfy exclusive core placement and will refuse it.

## Alternatives rejected

- **A memory region mapped writable into one VM and read-only into others.**
  It is faster, and it ends the property that vsock is a guest's only data
  path. Isolation between VMs is the product.
- **A region mapped into the writer VM only, served to readers by the host.**
  No page is shared between VMs, but it is still a host–guest memory surface
  outside vsock, with its own device and its own audit story.
- **The controller as a privileged VM that drives the hypervisor.** A guest
  with hypervisor authority is a second trusted computing base.
- **A periodic heartbeat from every unit.** It costs a wakeup per unit per
  period whether or not anything is wrong, which works against section 10,
  and it detects a crash only after a missed beat. Exit events detect a crash
  at once for nothing, and a deadline reset by ordinary traffic covers hangs.
- **Election among core-bound units.** A unit that cannot move cannot be
  elected elsewhere, and a partitioned device must not produce two writers.
- **A single "critical" switch.** Deployments differ in which requirements
  they need, and an all-or-nothing switch would force refusals on hosts that
  could meet the subset asked for.
- **Claiming zero downtime.** It cannot be witnessed. A measured bound can.

## Open decisions

- The shortest liveness period each backend can hold without false failovers
  under load. It needs the failover measurements; until then a period is
  refused wherever no measured figure exists.
- The partition driver's contract with a third-party hypervisor, which needs a
  concrete target before it can be written.
- When, if ever, the CNSA 2.0 suite may run without the classical algorithm.
  It is hybrid-only until that is decided.

## Evidence before acceptance

Each item needs a test or CI lane named in the implementing issue:

- A plan whose topology digest is absent, differs, or omits the unit is
  refused.
- Each refused post-admission mutation in section 3 is refused and audited.
- A unit admitted with exclusive cores runs only on them, and a second unit is
  refused those cores; a backend with no mechanism refuses the requirement.
- A write to a cell from a fenced epoch, from a reader, from a standby epoch,
  or with a stale version is refused; after failover the promoted standby
  reads the last committed value and can write.
- No host service other than the epoch gate compares epochs, enforced by a
  build check.
- Killing an active unit promotes its standby within the declared bound, and a
  next standby is provisioned; an exceeded bound is recorded as exceeded.
- With every controller killed, the host applies the static restart policy.
- A controller's request for a unit the topology does not name is refused.
- An edge absent from the topology is refused.
- The resource report reproduces within a stated tolerance on a second run,
  on at least one x86_64 and one aarch64 Linux host.
- An idle unit under the profile produces no periodic host wakeups.

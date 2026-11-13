# ADR-111: Host-trusted evidence freshness across workload transitions

Backing: preview
Validation: none

## Status

Proposed for review in [#5386](https://github.com/tinylabscom/mvm/issues/5386).
The operator has selected the separate, automatically managed local lifecycle
coordinator described below; the other transitions remain proposed. This
record defines a design boundary, not a shipped re-attestation capability
or an amendment to the claims in ADR-001.

## Context

MVM is a verifiable, secure execution platform. Its backends run workloads,
while the signed plan, policy admission, host enforcement, and audit evidence
determine what a particular execution was authorized to do and what can be
checked later. Validating an old signature does not establish that its policy
is still in force, that its workload is still running, or that a resumed guest
is in the state the signature once described.

The current paths have different semantics. A durable agent-session resume
verifies its resume point, synthesizes and admits a new plan, and advances the
session generation. A checkpoint revert launches a fresh, re-admitted VM. A
paused instance's snapshot resume verifies its snapshot and replay epoch and,
on the sealed Firecracker path, waits for post-restore reseeding before marking
the guest admitted; this is not the same operation as creating a new signed
plan. The `trust attest` export is a host-signed identity report with a zero
boot-measurement sentinel, and its verifier checks signer trust and signature,
not the freshness of a measured workload state.

These are useful but distinct kinds of evidence. Treating any one as a
universal "currently attested" result would strengthen the guarantee without
a corresponding enforcement path or witness.

## Proposed decision

### Name the claim before checking its freshness

Every verifier-facing result must state what it checked:

| Evidence | What it can establish today | What it cannot establish by itself |
| --- | --- | --- |
| Signed execution plan and admission record | A trusted host admitted a particular plan, at that decision point, under the then-applicable policy | That later actions remained authorized after revocation or policy change |
| Digest-pinned artifact and snapshot integrity | The checked bytes match an authenticated identity, with the snapshot replay and restore checks appropriate to its backend | That those bytes are currently admitted, running, or ready |
| Chain-signed audit entry or evidence archive | The recorded event is attributable to the trusted host; full-chain archive coverage is verifier-derivable where available | An event that the host never recorded, or a missing tail of the host's log |
| Host attestation identity report | A trusted host key signed the report body | Measured guest boot, verifier-challenged freshness, or protection from a malicious host |

Do not infer one row from another. In particular, a newly signed report over a
sentinel measurement is not fresh proof of the running workload, and a verified
build is not an admitted replacement.

### Freshness is an operation-specific decision

The local admission owner remains authoritative. The party requesting an
effect presents the relevant plan or capability; the host resolves current
policy and checks expiry, revocation, generation, and required backend
enforcement before granting that effect. A cached artifact or successful
signature check cannot renew authorization. Managed cross-host transport may
convey evidence, but does not create a second local authority. There is no
single default duration that turns every signed artifact into authority.

The following is an inventory and intended review boundary, **not** a claim
that every transition is already enforced end to end:

| Transition | Prior evidence that may become stale | Required review before protected effects | Failure and recovery |
| --- | --- | --- | --- |
| New launch or replacement | Prior workload's image, plan, generation and grants | Resolve the replacement's exact artifact and current policy; sign and admit its own plan; verify backend readiness before cutover | Keep the old workload only while its own enforcement remains trustworthy and authorized; do not promote a built candidate on verification, admission or readiness failure |
| Durable agent-session resume | Prior residency's plan, approval head and checkpoint | Verify checkpoint integrity and current approval head; admit a new plan for the next session generation | Refuse without advancing the session on a failed check; a repeated identical transition does not admit a second plan |
| Paused-instance snapshot resume | Prior snapshot epoch, guest entropy state and any authority that expired while paused | Preserve snapshot/replay and reseed checks; separately determine whether the original plan and effect grants remain authorized before permitting their use | Refuse or isolate effects when authority cannot be established; stop an unadmitted restored guest and make interrupted recovery unambiguous |
| Applied policy change, lease expiry or revocation | Earlier grant or admitted policy projection | Withdraw the old authority from affected running instances; use the existing policy owner and applicable per-effect gate, not network reachability or an old signature, to authorize later effects | Stop an instance if its changed permissions cannot be enforced in place; record the decision without exposing payloads or secrets |
| Workload termination | Any evidence of a live instance | No new effect under the terminated instance's identity; a successor needs its own admission and epoch where applicable | Distinguish termination from a lost heartbeat or unknown state; do not infer physical erasure |

Each implementation must name its transition owner, durable audit evidence,
decision deadline, cancellation behavior, crash recovery, and typed refusal.
Rechecking only when an operator asks to export evidence cannot substitute
for enforcement before a protected action. A versioned format migration is
required if the signed plan or wire meaning changes; [#5158](https://github.com/tinylabscom/mvm/issues/5158)
owns the separate decision on a plan-borne execution epoch.

### Trust boundary and witnesses

This first track protects against an untrusted workload and stale or replayed
authorization on a **trusted host**. The host holds the signing keys and
controls launch material. Neither host signatures nor optional host TPM
measurements provide an independently qualified malicious-host boundary.
Verifier-issued challenges, genuine boot measurements, hardware key custody,
and remote verification against a compromised host require separate
contracts and witnesses before such claims can ship.

For the first implemented transition, tests must witness a successful renewal
or refusal at the production admission/effect boundary, not merely validate
a declaration. Include stale policy or epoch, replay, incorrect principal or
artifact, missing enforcement, cancellation, and recovery as applicable to
that transition. Keep mock evidence labeled mock; a live-backend claim needs
a live-backend witness. Preserve end-to-end launch and readiness measurement
including admission.

## Consequences and next review

The current signed-plan, snapshot, lease, and mailbox contracts remain the
sources of authority. This proposal adds no new independent verifier, extra
guest network path, or mandatory TPM.

### Atomic policy apply

The operator chose an atomic apply boundary. Editing an authoring file is
staging, not publication of a policy in force. A proposed
`mvmctl policy apply` operation would validate the complete candidate and
its dependencies before changing any running authority. Launch and restore
must consume the committed policy generation, not whichever authoring bytes
happen to be on disk. The operation cannot report success until every
affected live instance is replaced or safely bound to the new signed
admission and the new generation is durable.

The host-side admission owner must serialize apply with launches, resumes,
and other applies. It needs a durable binding from each live workload to
the policy inputs and effective generation it was admitted under. An apply
that cannot identify or fence every affected workload refuses publication;
it must not guess from a VM's name or re-read a mutable policy file and
call that the already-admitted policy. A default or project policy, a
named profile/group, and a tenant bundle are different input sources,
but must resolve through the same policy owner. An unsupported source
cannot silently opt out of live policy updates.

This owner is local to MVM, not `mvmd`. Today the CLI calls
`mvm-hostd::plan_admission` and the selected backend directly rather than
handing the whole boot to a resident supervisor (ADR-014). `mvmctl policy`
only resolves, shows, validates and compares authoring inputs; a
`ResolvedPolicy` lists contributing files but carries no committed
generation. The per-VM network endpoint creates a static egress projection.
The supervisor's `hot_revision_replaces_firewall_for_same_workload` is a
mock test that resets its state machine between two launches; it is not
a production policy-cutover caller. None of these is already the
single-owner apply transaction. Implementing a policy-generation type
without connecting launch, effect fencing and recovery to that owner
would add a dormant control, not this capability.
The local host-interface adapter also loads
`<mvm_home>/host-interface/policy.json` directly at admission; that
host-level policy is distinct from a workload's `mvm.toml`, named profiles
and groups. Versioning that one file alone would not stage or apply the
policies that ordinary workload launches resolve. The first production
slice must identify which authoring source it covers, and unsupported
sources must not be reported as covered by its atomicity claim.
The current local admission path already records an `AssetKind::Policy`
identity for the resolved network policy in the signed plan. Reuse that
effective-policy evidence; it is not a committed generation or a digest
of every contributing project/profile/group file. Neither new source
binding nor an apply transaction can be inferred from that asset alone.
Hashing authoring files *after* resolving them is not enough: a concurrent
edit could bind a digest of bytes the resolver never used. Capture and
verify one exact source closure at the resolution/commit boundary, then
admit from that immutable closure rather than re-reading loose files.
The closure must include the project's manifest as parsed, every profile
and group document actually inspected (including an excluded group's
`required` bit), the resolved identity of built-in and verified-pack
references, the selected default and explicit policy references, and the
backend/platform predicates used for conditional layers. Record the bytes
at each parser read, not a later read of its path. A missing user file
whose absence selected a built-in must not later shadow that committed
selection. A path, digest, and effective policy alone are insufficient
if launch still follows mutable names or filesystem links. The first
versioned format must preserve these identities and refuse unknown
fields or an incomplete closure; its concrete encoding and migration
belong to the implementing contract.

The selected owner is the existing **local host-service boundary**:
move lifecycle policy admission and cutover coordination behind
`mvm-hostd`, exposed to CLI and SDK through the existing client contract.
The authored workload-policy parser and composition rules belong in one
shared `mvm-policy` library, below both `mvm-client` and `mvm-hostd`.
`mvm-client` owns caller-facing policy selection and launch folding;
`mvm-hostd` must independently validate the immutable committed closure
with those same rules. Moving the resolver alone does not commit policy
or move authority out of the current CLI launch path.
Keep backend-specific prepare, stop and handoff under their existing
backend contracts. A one-shot CLI process with a file lock cannot fence
an already-running endpoint or recover an interrupted handoff after it
exits; delegating local authority to `mvmd` would break standalone
execution. The remaining transaction and backend contracts still need
their own implementation and witnesses before this can ship.
`mvmctl` must start or connect to the local coordinator automatically;
operators must not run a second daemon-start command. A coordinator
failure refuses an unsafe apply instead of falling back to one-shot
authorization.
The resident `mvm-host-agent` currently registers VMs and serves host
services; it does **not** own their launches or policy cutovers. Use a
distinct local lifecycle coordinator
within the `mvm-hostd` boundary, auto-started or contacted by `mvmctl`.
Do not grant the per-tenant, keyless `mvm-host-agent` authority over host
launches merely because it is already resident: it parses guest traffic
and runs under tenant containment. The coordinator must preserve the
separate broker and signer key-custody boundary, keep durable local state,
and recover after CLI exit. It is not a new cloud service or a dependency
on `mvmd`.

This coordinator is an implementation of [#5097](https://github.com/tinylabscom/mvm/issues/5097)'s
local host-interface responsibilities, not a second authority alongside
`HostInterface`. Local mode resolves and applies locally without central
admission or mandatory hardware attestation; managed mode must accept only
the policy, epochs and lease authority its authenticated `mvmd` provider
supplies. The same client operation may drive both without making `mvmd`
a prerequisite for local launch. A managed node that is disconnected
cannot claim a newly published remote policy took effect immediately:
its signed offline lease bounds already-authorized operations and expiry,
and reconciliation is required before fresh authority is granted.
Atomicity here is **per local host transition**, not an instantaneous
fleet-wide commit across unreachable nodes.

### Prepare, then roll over

Prefer a prepared replacement to a cold stop. The old workload may continue
under the old committed generation **while the candidate is being built**.
The candidate can have its image and runtime verified. If it initializes
early, its own signed launch preflight and isolation must already hold; it
has no egress, secrets, writable volume, mailbox authority, or
production-readiness claim before its applicable admission checks complete.
Preparing it is not publishing the new policy. The old and new workloads
must not both hold active authority over the same identity, mailbox, or
effect route.

The transaction has one externally visible authority switch, after
preparation:

1. Parse, resolve and validate the candidate against the host ceiling;
   retain its exact source identities and digest. Prepare the replacement
   without granting external authority. If preparation fails, the old
   workload remains on its still-authorized policy; apply fails.
2. Lock the policy generation and the affected workload transitions.
   Reconcile running and paused instances; refuse if an affected instance
   cannot be identified or controlled.
3. Fence the old generation from *new* effects, then drain or cancel
   in-flight effects as the changed policy requires. A timeout or uncertain
   delivery is not a successful drain. Preserve accepted, still-authorized
   mailbox messages; acceptance, delivery and application acknowledgement
   are distinct. If the old workload's enforcement is untrustworthy, stop
   it rather than trying to keep it serving through cutover.
4. Complete the candidate's signed-plan admission under the new generation,
   check backend enforcement and readiness, and durably record the source
   digest, affected instances and outcome. Switch the host-owned route or
   mailbox owner to that candidate only when the old authority is fenced
   and the new authority is ready. Stop the old instance after ownership
   moves.
5. Release transition locks only after the committed generation and
   single active owner agree. On a crash, keep both sides' external effects
   fenced until durable state decides the owner; do not replay a success
   response from an incomplete transition.

Before the authority switch, candidate failure may leave the old workload
running only while its former policy is still authorized. After the new
generation is committed, restarting the old workload under its former
grant is not rollback: failure to activate the candidate must refuse
effects and report an unavailable/unknown outcome. This procedure aims
to minimize interruption, not promise zero downtime for stateful work or
on a backend without a safe handoff. The exact cutover must be witnessed
on each advertised backend.

The first implementation must connect three ownership edges before
advertising `policy apply`: (1) admission records the exact source closure
and committed generation for each affected instance, (2) every launch and
restore reads that committed generation rather than staged files, and
(3) the host can fence an old instance's already-open external effects,
transfer its host-owned route or mailbox, and reconcile an interrupted
handoff. A candidate's readiness is not merely a successful build or a
mock supervisor launch. A backend or policy source without those edges
must refuse apply, not pretend to roll over.

### Backend acceptance sequence

The first restricted implementation targets a local project `mvm.toml`
workload on Firecracker. HVF follows as the next claim-bearing workload
backend; libkrun follows under its own backend witness. QEMU's dev/test
tier and the explicit Wasm/browser portability tiers are also in the
eventual backend scope, but retain their existing tier limits: policy
rollover does not confer claim-10 egress on QEMU or microVM isolation on
Wasm. A backend without a safe live handoff must refuse that operation
until its own supported lifecycle implements the same atomic authority
switch; no backend may silently use an old grant or downgrade to another
runtime. Unsupported in the first release is an open delivery item, not
an acceptable final product state. Do not promote an all-backend claim
from a Firecracker or mock-only witness.

This is the *proposed* operation, not a description of current behavior.
If a direct edit could still be read on a launch before apply, or an
unobserved old endpoint could still forward after apply succeeds, the
atomic promise would be false. During migration, refuse an unsupported
affected launch or apply rather than silently accepting that gap.

The first candidate for #5386 is paused-instance snapshot resume. The local
client's `resume_sealed` verifies the snapshot and records the guest's
post-restore reseed, but does not itself re-resolve plan or policy authority.
The per-VM network endpoint constructs one egress gate from its admitted
policy at endpoint assembly. It checks each new destination against that
gate, not against a newly loaded policy file. A request-time destination
check therefore cannot by itself notice a policy change that happened while
the instance was paused. The `fc.admitted` marker means the restored guest
confirmed its reseed; it is not a newly signed plan.

The operator requires policy changes to affect **already-running** workloads,
not only their next admission. Recommend **both boundaries, for different
checks**: before restoring vCPUs, the existing admission owner must establish
that the prior instance's authority is still usable. For a running instance,
the host must withdraw affected authority on a policy change; the existing
network, secret and mailbox gates continue to decide each protected effect.
Rechecking a destination against the same static egress gate does not
refresh its authorization. If a prepared replacement or safe handoff is
unavailable, do not report a successful apply while the old workload can
still act under invalid authority. Stop it and refuse or report an
unavailable outcome; do not silently mutate the gate behind an unchanged
plan.

An offline lease is an explicit signed exception only for the operations
and expiry it already permits. The plan's short validity window gates
*launch admission*; checking its `valid_until` again on resume would
incorrectly turn it into a workload lease. Arbitrary external edits to
project `mvm.toml`, named profiles, and tenant bundles are currently read
at launch, without a common resident file-to-instance binding. A watcher
learns of an edit after it happens and cannot substitute for the atomic
apply owner. There is no current `policy apply` command or committed policy
generation; adoption requires a reviewed public command, provenance and
crash-recovery design before any security claim can change.

Before implementing the resume preflight, trace whether its endpoint and
signed plan survive pause on each supported backend, and which policy or
revocation sources actually declare mid-lifetime invalidation. Do not add a
second policy owner, mark an unverified guest ready,
or claim a revoked instance was contained while it could still act. If
the production path has no missing enforcement under its declared
contract, select another evidenced transition instead of adding a
redundant gate.

Promotion from proposed to accepted requires review of the selected
transition, its owner, its refused states, and its observable evidence.

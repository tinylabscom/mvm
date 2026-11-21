# Cold HVF entrypoint owner

Status: **Conditional architecture direction; prerequisite contract draft.
No launcher or positive factory is enabled by this document.**

Scope: [#4655](https://github.com/tinylabscom/mvm/issues/4655), under
[ADR-022](../adrs/022-target-architecture.md#cold-hvf-invocation-owner).
Issue comments own approval provenance, review revisions and delivery status.
This contract describes required behavior, not evidence that it is implemented.

## Maintainer decision: protected provisioner

The maintainer selected the production provider recommended in
[`ps06-builder-authority.md`](ps06-builder-authority.md): a signed, notarized,
root-installed provider with separate non-login `_mvm_authority` and
`_mvm_runtime` principals. `_mvm_authority` owns a fresh provider-internal
issuer, policy, one-shot grants, revocation and canonical audit;
`_mvm_runtime` owns original children, frozen inputs, quarantine and cleanup.
A root-owned deployment receipt pins the installed code cohort, role IDs and
issuer public key. CLI and Studio remain unprivileged authenticated clients.

This decision authorizes repository implementation of that boundary. It does
not authorize installing services or accounts, provisioning real credentials,
running a VM, signing or notarizing artifacts, or publishing a release on the
current host. Missing, corrupt or interrupted commissioning refuses; normal
startup cannot initialize an empty provider ledger or self-pin another issuer.
The legacy invoking-user host signer, caller registration and a signature-valid
grant alone cannot authorize an owner birth.

This amendment **supersedes** the invoking-user birth-owner and fixed
`mvmctl`-adjacent owner deployment described later in this document.
`_mvm_runtime`, launched from the protected provider installation, is the
original-child owner. The invoking user remains only an authenticated client
and never receives native custody, signer access or a lifecycle capability.
Requirements below for one owner per invocation, original custody from birth,
no PID reconstruction, bounded framing, hardened runtime, environment
allowlisting, final-byte verification, recovery possession and absorbing
quarantine still apply to the protected runtime component. Requirements that
derive its executable from `mvmctl`'s path, authenticate only a same-UID peer,
or place the owner under the invoking UID no longer apply.

The authority and runtime services mutually authenticate their immediate peers
using kernel audit tokens, expected protected role UIDs and pinned code
requirements from the deployment receipt. CLI and Studio authenticate to the
authority service as unprivileged clients; their enrollment/possession proof
authorizes only the exact retained operation. A successful XPC/launchd lookup,
same UID, socket path or signature-valid public grant is not authority.

### Closed source vocabulary

`mvm-contract::protocol::hvf_entrypoint_owner` defines public versioned bindings
for one fresh canonical admission, owner lifecycle audit and original-instance
HVF control. The vocabulary contains no path, PID, executable, argv, arbitrary
signing bytes or pre-birth native generation.

`FreshOwnerBinding` binds the operation, complete controlling principal,
installation, owner incarnation, tenant, workload, exact canonical-plan digest,
exact frozen-input digest, policy revision and finite expiry.
The owner incarnation is selected before admission and is not a fabricated
native generation. Provider epoch, connection challenge and request sequence
belong to the later authenticated provider envelope and durable journal; this
public record is not that envelope. `FreshAdmissionRequest` commits to
the complete exact plan bytes under the
`mvm.hvf-owner.fresh-admission.v1\0` domain: SHA-256 over that domain including
its NUL, compact typed `serde_json` serialization of `FreshOwnerBinding` in
declaration order, then the exact plan bytes. This is not JCS or `Value`
serialization. Decoding or hashing these values grants nothing. Any v1 encoding
change requires an explicit version and domain migration.

The protected verifier eventually returns a private, non-cloneable,
non-serializable `VerifiedOwnerGrant` after checking the provider signature,
deployment identity and complete independently retained request expectations.
It is not yet launch authority. A protected journal separately checks
revocation and durably consumes the exact grant before returning the private
`ConsumedOwnerGrant`. The key holder accepts only the exact closed operation
and independently recomputes its domain and binding. Neither the source
vocabulary nor an existing opaque `SignPlan` endpoint is that capability.

`OwnerGrant` is the provider-issued public one-shot envelope. It binds one
issuer, nonzero commissioning epoch and grant ID to the domain-separated digest of one exact
`FreshAdmissionRequest`, with finite ordered issuance and expiry. Its signature
is Ed25519 over `mvm.hvf-owner.grant.v1\0` including its NUL followed by compact
typed `serde_json` serialization of `OwnerGrant` in declaration order. It is
not JCS or a generic sign-bytes operation. The signature does not itself
authorize work. The protected runtime compares the issuer key
with the root-owned deployment receipt, re-verifies every retained expectation,
checks the exact request, checks durable revocation/consumption state, and
commits consumption before returning a private `ConsumedOwnerGrant`. A lost
response is reconciled by a protected locked read: a retained consumed or
revoked disposition cannot retry; proven absence means publication did not
occur and no consumed capability was returned, so re-verification may retry.
A corrupt or missing initialized journal refuses.
The journal is initialized exactly once under a stable digest of issuer label,
issuer public key and commissioning epoch; another provider generation cannot
reuse its grant IDs, revocations or consumption namespace.
The commissioning epoch identifies an installed issuer generation. It is not a
runtime session epoch and does not by itself invalidate allowances after an
authority-service restart; that freshness belongs to the later authenticated
provider envelope and durable restart transition.
The journal records the last accepted security time. Consumption and revocation
sample their injected provider clock only after acquiring exclusion; regression
before the grant's verification observation refuses. Expiry may durably advance
the time floor, but refuses before grant consumption or authority return.
Consumption does not extend expiry, and a later activation must check the same
or an earlier deadline again.
The protected journal covers ordinary crash recovery under the trusted
administrator boundary. It does not detect deliberate rollback of the complete
root-owned deployment receipt and journal by the trusted host administrator.

### Closed admission key-holder acceptance

After durable consumption, the authority key holder may sign only the exact
canonical `ExecutionPlan` bytes whose `FreshAdmissionRequest` digest appears in
that consumed record. The key holder binds its issuer key and commissioning
epoch to the journal's provider identity, rechecks canonical plan encoding, and
rechecks current expiry under the journal's serialized clock before signing.
It exposes no arbitrary bytes, legacy `SignPlan`, path, PID or native-control
operation through this API. Exact retries return the same deterministic
Ed25519 signature and create no additional authority or native effect.

The current library adapter opens no IPC endpoint and performs no peer
authentication. The future protected authority service must authenticate its
immediate runtime peer against the deployment receipt before invoking it.
Plan-signing acceptance does not append audit, bind a native generation,
authorize HVF control, create a process or return a launch capability.

### Refusal-only packaged process boundary

`mvm-hvf-run-owner` is first shipped as a refusal-only `mvm-client` binary. Its
only protocol is one 4-KiB length-prefixed bootstrap binding followed by the
typed `OwnerFactoryDisabled` response. Unknown versions/fields, zero identities,
truncation and oversized declarations refuse before output. Version 1 has no
success, start, signer, audit, native-control or VM-factory response.

The macOS release and exact-commit SourceHelpers archives include this binary.
After the final byte-changing hardened-runtime signature, packaging writes
`owner-component.json` inside the archive with the exact final SHA-256, package
version, target, source commit and bootstrap protocol. The outer keyless archive
signature authenticates both manifest and member. Final-package inspection
requires exact equality. The installer copies but never re-signs the owner.

This packaging does not make the adjacent user-owned executable the production
provider owner selected above. It supplies authenticated final bytes for the
future root-installed provider cohort. No current caller prepares, executes or
probes the owner, and existing HVF/Firecracker factory gates remain unchanged.

### Durable pre-birth quarantine

The protected grant journal also owns one absorbing birth record. After grant
consumption and before any native effect, the runtime durably records the exact
provider, grant, operation, owner incarnation, workload, request digest and
expiry as `Prepared`. Only the live non-serializable reservation returned by
that first successful publication can attempt birth. A retained observation,
retry, PID, name or reconstructed DTO cannot recreate it.
The grant journal rejects another consumed grant carrying either the same
operation ID or the same complete request digest, even under another grant ID.
One commissioned provider identity owns one journal; deployment must not create
parallel journals for that identity.
Journal schema v2 adds the retained operation identity and pre-birth record.
Any populated source-preview v1 journal refuses as incompatible; it is never
silently migrated to empty state. No production caller or commissioned provider
used v1.

The journal exposes no method that accepts a public `HvfInstance`. Its one-way
`Prepared -> Bound` transition borrows the opaque `ColdHvfOwner` retained by the
authenticated cold channel and derives the actual generation internally. The
borrow also carries the SHA-256 commitment of the exact canonical plan bytes
retained by that launch; binding refuses a different grant-plan commitment. The
terminal completion retains the same commitment for audit closure. The channel
permits this borrow only after activation and before dispatch. The
returned receipt is non-serializable and is neither stop proof nor a native
control capability. A retained observation, including `Bound`, cannot recreate
the reservation, receipt or owner.

Binding consumes the live reservation on every outcome. A failure returns only
an uncertain quarantine marker while the caller continues to own the borrowed
native owner. Publication uncertainty therefore cannot be retried by supplying
an observed generation. Process death or loss of the live reservation leaves
`Prepared` or `Bound` quarantined and returns no reusable capability. The
source seam remains disconnected from the refusal-only owner executable and
does not enable a positive factory.

The source-only API also has no retirement operation. Later work may clear
quarantine only from the original live owner after the complete terminal,
cleanup and audit proof. Merely reading `Prepared` or `Bound` never proves a VM
stopped.

## Process and authority

`mvm-hvf-run-owner` is the proposed binary in `mvm-client`, with a thin entry
point over the client library. One invoking-user process owns one cold HVF
invocation. It is separate from `mvm-hvf-supervisor`, the VMM process, and
from the existing signer/key-holder roles. No elevation, root service,
multi-tenant daemon, arbitrary executable/argv, shell or CLI replay is allowed.
The executable must be prepared and authenticated before launch; a path,
environment override or executable hash alone is not publisher authorization.

The owner performs fresh admission and creates the original VMM child through
the existing typed backend. It retains admission, effective configuration,
frozen inputs, file/runtime/volume leases, helper lifetimes, output and separate
boot/dispatch/flush/stop/cleanup/audit errors. A Rust owner or `Child` is never
serialized or reconstructed. Cross-process custody must begin before VMM
birth, not be attempted after uncertain execution.

CLI and Studio call the same typed client service. Library ownership types
remain internal to the owner. Public responses carry observations, not
`NativeCompletion`, `ConfirmedExit`, admission or cleanup capabilities.
No Firecracker process boundary or generic backend framework is introduced.

## Keyless lifecycle prerequisites

The inspected source baseline is
`fa9a8b53cb4c86510af6f4df6d0804758d423b97`:

- `AdmissionContext` contains a key-bearing `AuditEmitter`.
- `ConnectedInstance::connect_bound` calls `existing_operator`, which loads
  the operator signing key. Original-child adoption and stop reach this path.
- The existing signer protocol supports plan and telemetry-handshake signing;
  the inspected `HostSignerProxy` exposes plan signing. Neither supplies a
  complete audit/admission/HVF-control service.

Before any owner factory is enabled, all three paths need reviewed
signer-backed operations: admission, canonical audit closure, and native
adoption/control. An owner parser must receive neither private keys nor an
unrestricted sign-bytes oracle. The signer independently authorizes the
operation's closed verb, domain, role, freshness and allowed phase transition.
Admission binds the proposed canonical plan/request, controlling principal,
tenant and owner incarnation; it cannot require an already-admitted plan.
Later operations bind the actual admitted plan and, once created, the native
generation. Pre-birth requests never invent a generation to satisfy a wire
shape. Failure or an unavailable operation refuses; there is no local-key
fallback, replacement-key creation or borrowed signer purpose. Existing
completion/audit policy and parser/key-holder separation remain unchanged.

The source-only owner audit adapter now supplies the canonical-audit prerequisite
without opening an endpoint. It consumes a live `Bound` receipt, checks the exact
canonical admission and opaque `NativeCompletion`, then durably records
`AuditClosing` before appending the closed success sequence:
`plan.native_completed`, `plan.exited`, `session.sealed`, and the covering root.
No caller selects a category, payload, path, PID, instance or bytes to sign.

Append, seal, root-publication or journal-finalization ambiguity consumes the
closure capability and returns only uncertain audit custody. `AuditClosing` is
absorbing across restart in this slice; neither chain observation nor retry may
mint `AuditClosed`. The failure-audit vocabulary, protected IPC, positive
factory, retirement and native-control operations remain disabled.

The durable `AuditClosing` publication is the authority-time linearization
point. Expiry is rechecked immediately after that publication; once accepted,
the fixed terminal audit sequence may finish after the deadline because it
grants no execution or native effect. Clock regression or expiry before that
point refuses. Audit finalization never extends workload authority or permits a
new close attempt.

The source-only native-control signer completes the third closed key-holder
shape without executing a control operation. It accepts only a live `Bound`
receipt, the exact canonical admission, and an `OriginalHvfOwnerBinding`
borrowed from activated native custody. The journal lock, retained instance,
plan commitment, authority clock and expiry remain held through signing and a
post-sign freshness check.

The signer constructs only the existing connection-bound
`HvfInstanceControl::StopHvfInstance` request and returns the established
`SignedControl` envelope. It requires a non-serializable stop authorization
created only after the control connection's fresh challenge is verified and
its process-exit observer is armed. Challenge responses and finalization remain
with the native supervisor because they attest to exchange and terminal facts
that `Bound` admission alone cannot prove.

No caller supplies an instance, PID, VM name, path, socket, category or
arbitrary bytes to sign. `Prepared`, `AuditClosing` and `AuditClosed` refuse
before key use. This adapter opens no endpoint, performs no
stop/adoption/finalization, creates no retirement proof and does not make the
owner executable positive.

The native control seam now carries two explicit verifier roles. The native
supervisor signs challenge and finalization with its native-control key, while
it verifies owner stop requests only under the provider stop root. A
root-explicit connection retains no stop-signing private key; legacy
connections remain compatibility wrappers using the existing key in both
roles. The owner route never falls back from explicit roots to that legacy
loader.

This split is source-level wiring only. A strict read-only macOS loader now
loads the distinct native and provider-stop roots from the fixed protected
commissioning receipt, and a pure adapter can construct the typed control roots
without opening a connection. The open-only journal seam requires both journal
and lock to preexist and never creates or repairs either.
The source-only installer seam may create exactly one fixed
`/private/var/db/mvm/owner-commissioning-intent.json` containing bounded public
role and approved-code-cohort metadata. It walks the protected root by
descriptors, requires root-owned secure ancestry, exact deployment modes and no
extended ACLs, and uses exclusive descriptor-relative creation followed by file
and directory synchronization. Existing intent, deployment receipt,
commissioning completion, authority-ready, journal or lock artifacts refuse
before creation. An error after exclusive creation is publication-unknown and
the retained object is never repaired or overwritten by retry.
The matching read-only loader walks that same fixed protected ancestry by
no-follow descriptors, requires a root-owned single-link regular intent with
exact mode and no extended ACL, bounds the read before allocation, and strictly
decodes the original bytes. It exposes only validated public metadata and the
domain-separated digest of canonical compact typed bytes. Missing, unsafe,
oversized or corrupt state refuses without creation, repair or cleanup.
The source-only authority-root validator takes that loaded intent and walks the
fixed `/private/var/db/mvm/authority` path through read-only, directory-only,
no-follow descriptors. It requires root-owned secure ancestry, an exact
root-owned `0755` deployment directory, and an exact `0700`, no-extended-ACL
authority directory owned by the intent's authority UID and GID. Its opaque
result retains only the validated directory descriptor and exposes no public
descriptor, arbitrary-child or mutation API. A crate-internal seam opens only
the fixed `owner-commissioning-state.jsonl` child for the state loader below.
Validation creates no lock and proves only that this namespace matched at
observation time; it does not prove freshness, commissioning progress,
authority or an atomic snapshot. Future mutation must obtain separately
designed exclusion, then reload and revalidate the intent and root.

The source-only state loader observes a durable append-only v1 JSONL protocol at
that fixed child. The nonempty log starts at sequence one and advances exactly
once through `Prepared`, `KeyCreated`, `JournalInitialized`, `ReceiptPending`,
`CompletionPublished` and terminal `Ready`. Every compact canonical object
contains closed typed content plus its domain-separated SHA-256 digest. Content
binds the prior record digest (all zero only at sequence one), the exact loaded
intent digest, deployment ID and epoch, authority UID and GID, and a nonzero
future lock device/inode pair that remains identical throughout the log. Each
phase permits only its named optional 32-byte public evidence digest; those
opaque digests make no key-custody, journal-validity, receipt-publication,
completion-publication or readiness claim.

The loader opens the child descriptor-relative with no-follow, nonblocking and
close-on-exec flags, then requires a single-link regular file owned by the
intent authority identity with exact `0600` mode and no extended ACL. Both each
line (8 KiB) and the whole log (64 KiB) are bounded. Original bytes must have
one canonical compact object and LF per record, with no CR, blank line,
duplicate or unknown field, non-object, trailing form, missing final LF or
partial record. Missing is `Absent` only when that exact child is absent and is
not freshness or permission. Non-`Ready` retained logs are interrupted,
readiness-refusing observations; `Ready` is only terminal log observation.
The loader creates and changes nothing, acquires no lock, performs no transition
or recovery, and reads or reconciles no key, journal, receipt or completion
artifact.

A separate source-only validator observes the permanent installer-provisioned
`owner-commissioning.lock` child beneath the retained authority root. It opens
only that fixed name descriptor-relative with read-only, no-follow, nonblocking
and close-on-exec flags, and never creates or repairs it. The inode must be a
root-owned, root-group, single-link, zero-length regular file with exact `0444`
mode, no extended ACL, and either the SDK/libc user-immutable or
system-immutable flag. Missing and unobservable flags refuse. The validator
retains the descriptor and exposes only its nonzero device/inode identity; a
second fixed-name observation detects replacement during validation but does
not establish exclusion or an atomic namespace snapshot. A pure comparison can
classify a retained state log's lock binding as matching or mismatched without
granting mutation authority. The permanent inode's installer-only creation and
lifetime are a future deployment contract; validation proves neither the
installer transaction nor freshness.

Lock acquisition, stable installer deployment, the state writer and all
commissioning effects remain unimplemented.
The v1 preflight checks only these fixed sibling conflict names; it does not
claim to discover arbitrary state beneath a future authority-owned
subdirectory. Trusted installation and state mutation must be serialized across
preflight and publication. Exclusive create linearizes competing intent
publishers only.
These seams remain disconnected: no protected authority/runtime IPC, service,
native operation or positive factory consumes them in production.
The source-only commissioning-bootstrap vocabulary is versioned, strict and
bounded to 512 encoded bytes. Its in-memory session owns the existing
`VerifiedMacPeer`, binds one begin/challenge/confirm exchange to exact intent
and nonce values for at most 30 monotonic seconds, revalidates under the same
transition mutex, and can move the peer into one non-serializable permit.
Expiry is terminal; mismatches and peer refusals issue no permit. This adds no
endpoint, listener, binary, key, journal, receipt, durable state, VM effect or
positive factory, and it preserves the verifier's refusal on platforms without
the macOS primitive.
The macOS-gated connected adapter accepts only an already-connected
`UnixStream`, a trusted expected UID and exact designated requirement, and an
independently selected nonzero intent digest. It checks `getpeereid`, captures
the exact 32-byte `LOCAL_PEERTOKEN`, and gives `VerifiedMacPeer` an owned
duplicate of that same connection for recapture. It then drives exactly one
five-second-per-frame, 512-byte-capped begin/challenge/confirm/accepted exchange
and returns the effect-free permit only after the accepted frame is written and
the peer revalidates again. Oversize, truncation, binding, replay, timeout, peer
and wire failures close/refuse without a permit. Extra bytes already buffered
at transition checks refuse; the adapter never processes a second exchange,
but does not claim that a nonblocking queue peek rejects bytes arriving later.
The adapter still creates or discovers no socket, endpoint, service,
deployment, key, intent, receipt, journal or VM action and is not a
commissioning factory. Receipt of `Accepted` is not durable commissioning
evidence; a future effectful consumer must revalidate again immediately before
mutation.
The future initializer still owns intent authentication and consumption, lock
validation and acquisition, state-log writing, key creation,
deployment-receipt and completion publication, and journal initialization. It
must acquire installer-provisioned exclusion and then reload and revalidate the
intent before mutation; a loader result is not an atomic fresh-namespace
snapshot or a capability. This slice supplies none of those operations.
Root-owned live deployment remains untested in this source-only slice; hermetic
descriptor-root tests witness its filesystem and schema policy.

## Recovery authorization

Same UID, a private socket and a discoverable generation are necessary checks,
not sufficient recovery authority. The proposed initial rule is:

1. Start binds an explicitly enrolled controlling principal's public identity
   to the operation. Later control requires fresh proof by that same principal;
   delegated recovery principals are not supported in this first contract.
   `RecoveryBinding.controlling_principal` is the enrolled Ed25519 public-key
   bytes, not a fingerprint. Recovery possession additionally binds the full
   `EnrolledIdentity`, including its installation UUID, checked against the
   actually loaded credential and independently retained receiver enrollment.
2. Authenticate the actual connected peer and the original owner on that
   connection. A fresh challenge binds the operation, principal, tenant,
   request digest, plan/configuration binding, owner incarnation, native
   generation when present, verb and request sequence.
3. Proof generation uses a narrowly scoped operation of the authorized
   credential/key-holder subsystem. Existing caller-registration proofs cannot
   be repurposed as lifecycle proofs. Until this operation and its verifier are
   reviewed and implemented, recovery connections refuse.
4. Socket forwarding, a saved PID, endpoint discovery, an executable hash or
   knowledge of the challenge cannot authorize a different connection.

No bearer credential is written into logs, command arguments, environment,
discovery records or plaintext state. Losing access to the controlling
principal does not authorize a weaker recovery path. The trusted host remains
trusted; this does not claim protection against host administration.

## Operation states and linearization

These are semantic names, not an allocated wire version or shipped API.
The source-only request representation below does not allocate an active
endpoint or an authentication protocol.

| Request/event | Required effect |
| --- | --- |
| `Start` | Register one operation ID and exact bounded request digest before native effects. The owner freezes and admits inputs, then creates the native child. A repeated identical authenticated request observes this operation; a conflicting binding refuses without another admission or dispatch. |
| `Observe` | Return a bounded sanitized view of that same retained operation. Absence after owner loss is unknown, never evidence that start did not occur. |
| `CancelStop` | Serialize cancellation with activation/dispatch; use only the original owner to quiesce/stop. A cancellation cannot mint successful completion. |
| `AcknowledgeResult` | Acknowledge delivery of the exact terminal result revision. Early, stale or conflicting acknowledgements refuse. ACK neither stops a VM nor authorizes resource deletion. |
| Frontend disconnect | Request bounded cancellation/stop. Keep all uncertain custody in the live owner. Do not replay dispatch or infer successful detach from EOF. |
| Owner death | Quarantine the operation and resources. Never re-admit the old operation, replace its generation, reconstruct custody or turn observation into completion. |

One owner accepts one invocation. Its state progresses from registered to
prepared, active and stopping, then either terminal or recovery-required.
Failures after possible effects stay recovery-required until the original
owner proves the applicable terminal conditions. Preparation failures release
only resources proven child-free. Unknown state is never reset to prepared.
Every transition and cancellation race is serialized within this operation.

Cancellation has a reserved bounded signaling path independent of startup,
dispatch and output delivery. An active mutation cannot make `CancelStop`
return busy or wait behind guest I/O. Repeated authenticated cancellation
coalesces into one pending intent. Serialize application of that intent with
state transitions, not its acceptance behind the running operation.

The start acceptance point records the operation and controlling principal
before the first native effect. Returning an acceptance response does not
prove activation. Lost responses are resolved by authenticated observation of
that same operation, never a new start. A nonce collision with different
request bytes is a conflict; request sequences cannot wrap.

There is no detached execution request in the first HVF slice. The owner
outliving a disconnected frontend is recovery retention, not consent to keep
executing a detached workload. A future detach mode needs its own explicit
commit transition and lost-acknowledgement rules.

Successful completion requires the existing same-session completion/storage
barrier, original-generation authenticated finalization and lifetime exit,
and the required cleanup/audit outcome. A guest exit code, EOF, an OS exit
event or a signed finalization record alone is insufficient. Result delivery
and resource cleanup are independent; repeated delivery ACKs cannot repeat
cleanup or audit sealing. Native proof types are never rebuilt from IPC.

## Qualification profile and refusal

The following numbers are a **proposed qualification envelope**, not enabled
defaults, measured capacity or approved enforcement. Signed policy and operator
limits can only narrow it. Any request outside it refuses; zero never means
unlimited. Positive implementation requires review of each enforcement point,
including the executable's startup before untrusted parsing.

| Surface | Proposed ceiling | Enforcement obligation |
| --- | --- | --- |
| Bootstrap bytes | 256 KiB | Reject declared size before allocation; bounded input reader. |
| Control frame | 4 KiB | Length checked before allocation; reject unknown version/verb/fields. |
| One-shot stdin | 64 KiB | Count inside bootstrap budget; no streaming input in this slice. |
| Captured stdout plus stderr | 16 MiB | Aggregate counter; overflow stops admission of output and requests cancellation, never a success projection. |
| Output chunk | 16 KiB | Separate bounded output scheduling; slow readers cannot block stop. |
| Control connections | 4, including unauthenticated handshakes | Reserve before accepting work; one response buffer per connection. |
| Mutating operations | 1, plus 1 coalesced cancellation intent; no waiting mutation queue | Conflicting starts return busy; authenticated cancellation uses its reserved path even during startup/dispatch or blocked output. |
| Authentication/control exchange | 2 seconds monotonic | Covers incomplete/slow frames and signer response. |
| Request freshness | 30 seconds, no future timestamp | Fresh challenge plus sequence; wall-clock checks cannot extend monotonic deadline. |
| Preparation/startup | 30 seconds | Timeout does not prove child-free; retain any acquired custody. |
| Guest execution | 300 seconds maximum | Enforced by the native execution boundary, not a frontend timer. |
| One stop attempt | 15 seconds | Deadline exhaustion retains uncertainty; no automatic retry loop. |
| Owner OS resources | 256 MiB memory; 60 CPU seconds; 128 FDs; 32 threads | Hard per-process enforcement before request parsing, not sampling or guest-memory configuration. |
| VMM OS resources | At most 4 vCPUs and 2 GiB guest RAM; 2560 MiB host memory; 1200 CPU seconds; 256 FDs; 64 threads | Hard native enforcement established before VMM birth. CPU time is not a scheduling-share claim. |
| Process graph | One owner, one VMM, at most 8 required supporting role processes | Exact closed role graph; each supporting role also needs reviewed per-role limits. No generic spawn operation. |

Code-enforced frame/output/concurrency bounds are not OS containment.
`RLIMIT_NOFILE` or CPU-time limits alone cannot establish memory, thread or
per-VM process bounds. A per-UID `RLIMIT_NPROC` is not a per-VM mechanism.
Limits applied after an unbounded child has started do not qualify.

At this source baseline, no complete reviewed macOS enforcement mechanism for
this envelope is established. In particular, owner/VMM hard memory and
thread/process containment cannot be asserted from existing spawn-scope
degradation. The profile is therefore **not launchable**. Qualification must
name each native mechanism, its pre-birth installation point and exhaustion
behavior, and prove both owner and child bounds. If macOS cannot enforce a
required bound, implementation stops for an explicit product/security decision;
it must not silently downgrade the requirement or add privilege.

## Owner death and input custody

A generation-bound quarantine record must be durable before any VMM effect.
All relevant volume reuse, image deletion, generation replacement and
automatic-restart paths must honor it. A lock disappearing or an endpoint
closing cannot clear quarantine. The record is a refusal condition, never
evidence of live custody, successful stop or permission to reap a numeric PID.

Only the original live owner may retire its matching generation's quarantine
after the compound terminal proof and required cleanup/audit have succeeded.
Retirement must be durably committed before reuse is allowed; absence alone,
a stale generation, a partial write or uncertain retirement durability keeps
reuse refused. Do not delete the refusal record before committing its
replacement decision. Result ACK cannot retire quarantine. Owner loss has
no quarantine-clearing recovery path in this slice, including a crash after
writing quarantine but before VMM birth or during retirement.

Owner-death execution containment is a separate prerequisite. An inherited
owner-liveness channel may trigger VMM abort, but its race handling,
inheritance, watcher failure and actual bounded cessation require review and
platform evidence. EOF is only a containment trigger, not terminal proof.
No existing HVF owner-death mechanism is claimed by this draft. Without
qualified containment, the owner launch refuses. Killing execution cannot
mint successful finalization, release quarantined inputs or seal success.
Recovery after loss of the original owner is not implemented by this contract.

The owner freezes the exact kernel, rootfs, verity, metadata, root-hash and
runtime selection, holding the relevant files and leases throughout uncertain
use. Only explicitly allowlisted internal startup descriptors may be inherited;
other descriptors stay close-on-exec. There is no public FD-passing operation.
Descriptor numbers and caller-authored hashes are not verified image authority.

Installed publisher-authenticated applications retain their existing path.
Locally built entrypoint/pack-health inputs require a separate typed route
bound to actual local-build admission and frozen bytes. `BuiltPackBootCheck`
currently requires a registry-pack identity; do not fabricate one or add an
unchecked `FrozenBootImageBytes` constructor. Production sealed posture,
signed runtime verification and ADR-023 host-only secret substitution remain.
Health success cannot permit signing/export while stop or cleanup is uncertain.

## Implementation and evidence boundary

First deliver this contract and independently reviewed refusal/state-machine
tests, without a binary target, spawn factory or production wiring. Required
negative cases cover wrong peer/principal/tenant/plan/configuration/incarnation/
generation; replay and conflicting nonce reuse; malformed, oversized and
truncated frames; early ACK; disconnect at each state; unavailable signing or
enforcement; and each half of the compound terminal proof being absent.
Exercise cancellation while startup/dispatch is busy and output is blocked,
and crashes between quarantine creation, VMM birth and durable retirement.

Next close the keyless admission/audit/control and native enforcement
prerequisites in separately reviewable changes. Only then wire one cold
installed-application invocation and verify executable packaging/identity.
The local-built frozen-input route is a separately scoped and reviewed
follow-up, still required for the two #4655 documented-build witnesses.
Child creation, backpressure, owner death, quarantine and recovery need
behavioral tests, not symbol or source-text assertions. CLI and Studio
exercise the same library service.

The two documented-build scenarios remain counted and Firecracker-only until
their actual HVF witnesses pass. Host-only tests, gated compilation, component
observations and diagnostic foreground runs are not that evidence. Snapshot
capture exclusion and completion/audit policy retain their separate ownership.
Native execution, credentials/trust changes, signing and publication each
require their own authorization; this contract grants none.

## Source-only recovery request representation

`mvm-contract::protocol::hvf_owner`, re-exported by `mvm-core::protocol`, defines
an unauthenticated version-1 request representation for `Observe`, `CancelStop`
and `AcknowledgeResult`. There is no `Start`, detach, signing or process-adoption
verb. Its decoder rejects inputs above 4096 encoded bytes before serde
allocation, non-object top-level JSON, unknown/duplicate/missing fields, unsupported
versions, mismatched public bindings and early/stale result acknowledgements.
An eventual transport must separately reject oversized declared lengths before
allocating the receive buffer; a slice decoder cannot establish that property.
Nested records retain serde's positional-sequence representation as well as
objects; this parser does not establish canonical signed JSON representation.

Bindings distinguish before-admission, admitted and native phases. Proposed
plan digest precedes admission; actual plan and effective-configuration digests
are required afterward; native phase additionally binds the existing
`HvfInstance`. Public operation/request/principal/tenant/incarnation fields
are compared against retained context, not trusted as credentials.

The decoder always returns `UntrustedRecoveryRequest`. It does not authenticate
a peer, principal, signer or owner; enforce replay/freshness; serialize running
operations; perform stop; mint terminal evidence; or clear quarantine.
The supplied terminal-result revision only controls acknowledgement parsing,
not completion or cleanup. These omissions are positive-activation blockers,
not optional checks for callers. No production receiver consumes this shape.

## Recovery possession (source-only)

`mvm-core::crypto::recovery_possession` supplies a separate
`mvm.controlling-principal.recovery-possession.v1` Ed25519 possession purpose.
The signed message is the domain (including its trailing NUL) followed by
`serde_json` serialization of the fixed typed `RecoveryChallenge` schema in
declaration order. This is not JCS: integer fields retain exact decimal `u64`
values, including request sequences and result revisions above $2^{53}$.
It binds the complete typed request, full enrollment, receiver-issued fresh
per-connection nonce and issuance time. Verification compares against the
receiver's independently retained complete expectation. Labels are bounded
before signing; the proof decoder checks its 4-KiB slice limit before parsing.
A transport must bound declared receive lengths before allocation and enforce
its separate monotonic deadline. Challenges expire after 30 seconds and refuse
future issuance times.

`CallerCredential::prove_recovery` reuses the loaded credential without changing
enrollment or exposing a key/sign-bytes operation. Its output is possession
evidence only: it does not authenticate the actual connected peer or original
owner, consume nonce/sequence, admit work, stop execution, prove completion or
authorize cleanup. A public nonce or digest alone does not defeat forwarding.
There is no receiver or production wiring, and existing registration proofs
remain a different purpose.

## Lifecycle table (source-only)

`mvm-contract::protocol::hvf_owner_lifecycle::OwnerLifecycle` is the pure
transition and refusal table for one retained operation. It holds no process,
key or socket and is created only by the owner before the first native effect;
nothing deserializes it. It makes the identity, generation and staleness rules
above executable:

- **Identity and generation.** A request is applied only if its whole
  `RecoveryBinding` equals the retained one: operation, request digest,
  controlling principal, tenant, owner incarnation and phase, including the
  native `HvfInstance` generation. Any difference is `BindingMismatch`.
- **Stale and repeated requests.** The sequence must be strictly newer than the
  last accepted one; equal or lower is `StaleSequence`. A refused request does
  not consume its sequence. Repeated cancellation coalesces into one pending
  intent; a repeated result acknowledgement is `AlreadyAcknowledged` and repeats
  no cleanup or audit.
- **Transitions.** `Registered -> Prepared -> Active -> Stopping -> Terminal`.
  `Terminal` needs all three halves of the compound proof (completion barrier,
  original-generation finalization, cleanup and audit); with any half missing the
  operation is `RecoveryRequired` and no result revision exists. A preparation
  failure releases only when proven child-free. `RecoveryRequired` never returns
  to `Prepared` or `Active`, but it is not an end: the child may still run. A
  cancel or frontend disconnect there is retained as cancellation intent (only
  `Terminal` makes cancellation moot); the owner may move it to `Stopping` once if
  no stop was attempted yet (never a second attempt); and it reaches `Terminal`
  only through the same three-halves proof.
- **Disconnect and owner death.** A frontend disconnect records cancellation
  intent and keeps custody. Owner death is `Quarantined`, which is absorbing:
  every later request and transition refuses.

The table authenticates no one. A receiver authenticates the connected peer and
principal before calling `apply`, and the rest of this document's blockers
(keyless operations, native resource and owner-death containment, the
local-built frozen-input route) are unchanged. No launcher consumes this type.

## Maintainer decision: in-process bound and owner death

The maintainer decided, for the cold-HVF owner envelope and owner death
(relayed by the cleanup coordinator on #4655):

- The accepted resource bound is the in-process one: the same summed vCPU
  CPU-time bound the HVF run loop enforces for claim 18, plus the existing
  guest-memory ceiling. This replaces the requirement above for hard
  per-process memory, thread and process containment on macOS; those rows of
  the qualification table are not enforced and are not claimed.
- Owner death is absorbing quarantine and nothing in this slice clears it. No
  separate owner-death containment mechanism is required.
- The concrete owner and receiver need review by a fresh independent security
  reviewer before merge. A live HVF run for the owner witnesses is authorised
  once the owner exists.

This decision does not authorise a launcher by itself; the keyless lifecycle
operations, authenticated recovery proof and the local-built frozen-input
route above remain prerequisites.

## Approved owner design: executable verification and peer binding

Status: **PROPOSED-APPROVED-NOT-IMPLEMENTED.** The maintainer approved the
design decisions below on
[#4655](https://github.com/tinylabscom/mvm/issues/4655#issuecomment-6938453523)
(2026-11-17): decisions D1 to D8 of the
[design proposal](https://github.com/tinylabscom/mvm/issues/4655#issuecomment-6904452438)
as recommended, except D4, which is rejected. The
[native probe results](https://github.com/tinylabscom/mvm/issues/4655#issuecomment-6938617195)
refine it. Nothing in this section is implemented, enabled or activated; no
claim in ADR-001 changes, and no claim-bearing statement here is shipped. It
exists so that implementation slices have one source. Where it names an
existing function, that function is shipped (claim 20 covers release
archives); its use for the owner is not.

### Executable verification (approved, not implemented)

1. **Verifier.** The owner is authenticated with
   `verify_release_archive_bytes_with_signer`, the byte-level verifier, with
   `ReleaseTrain::Cli` for a release and `ReleaseTrain::SourceHelpers` for a
   source build. The wrapper `verify_release_archive_signature` is never used on
   this path: it returns no result when `MVM_SKIP_COSIGN_VERIFY` is set and it
   fetches over the network. That variable is not read on the owner path.
   `aux_bin::resolve_verified` is not publisher proof either: it runs the
   helper's `--contract-version` probe before any publisher check and honours
   path overrides. The owner is never run, probed or asked its contract version
   before verification passes; the contract version is carried in the manifest
   and compared as bytes. No new cryptography and no new trust root.
2. **Manifest inside the signed archive.** The owner is a member of the existing
   macOS archive and of the per-VM binary inventory. After the last
   byte-changing macOS signing step, the release job writes `owner-component.json`
   into the archive: component name, SHA-256 of the final owner bytes, release
   version and target, and source commit. The archive signature then
   authenticates the manifest. A detached digest list is not accepted.
3. **No installer re-signing.** The owner is excluded from the installer's
   re-signing targets, so installed bytes equal the signed manifest digest. An
   owner whose signature or entitlements are wrong is refused, not repaired
   locally.
4. **Offline re-verification at spawn.** Install retains the verified bundle,
   the archive digest and the component manifest in a proof directory beside the
   install. Spawn re-verifies the retained bundle against the retained archive
   digest, with no network fetch, then compares the manifest digest with the
   owner file digest. A missing bundle or proof directory refuses; no "not
   verified" result is accepted as a pass.
5. **Fixed location, no parameters.** The owner path derives from the install
   directory of the running `mvmctl` (`std::env::current_exe()` parent), never
   from `PATH`, any `MVM_*_PATH` override or a caller argument. The preparation
   function takes no parameters.
6. **Retained identity.** Preparation opens the file read-only without following
   links and close-on-exec, checks it is a regular file owned by the effective
   uid and not group- or other-writable, hashes it from the descriptor, and
   compares to the manifest digest. The prepared value holds the descriptor, its
   device, inode, size and modification time, and the digest; spawn re-checks
   them against the descriptor and the path immediately before launch. Any
   change refuses. This detects accidental change and a different-UID writer; it
   is not a defense against a same-UID writer (below).
7. **Incomplete or mixed install.** The manifest version and commit must equal
   the running `mvmctl`. A mismatch, a missing file, a missing proof directory or
   a marker left by a partially completed update refuses with the existing
   `mvmctl env update` pointer.
8. **Source builds (D4 rejected).** There is no contributor-only unverified owner
   path, flag or posture. A source build is accepted only when it carries a
   `SourceHelpers` signed bundle for the exact current commit of a clean tree
   (no modified or untracked files) and the manifest commit equals that commit.
   That establishes "built by the same publisher workflow on `main`", not release
   authority, and must be documented as such. A dirty tree, an unpublished
   commit, a locally compiled or ad-hoc-signed owner, or a missing proof
   refuses with a typed error that names the missing proof. No environment
   variable or flag turns that refusal into a local build.

### Same-UID replacement (trusted-host boundary)

ADR-001's boundary applies: a process running as the invoking user is trusted
with that user's install files. Stated plainly:

- **Defended:** a stale, downgraded or foreign archive; a wrong component; a
  missing or skip-hatched proof; a mixed or partial update; `PATH` or `MVM_*`
  redirection; a writer under a different UID when the install directory is not
  writable by others; accidental corruption.
- **Not defended:** any process under the invoking UID that replaces the owner,
  the install directory, the proof directory or `mvmctl` itself before the check
  or between check and exec. It can replace `mvmctl`, which is the verifier. An
  open descriptor, no-follow open, two hashes and an owner/mode check are not a
  same-UID race defense and must not be described as one. Host administration,
  root and a compromised kernel are out of scope.

### macOS peer binding (approved; verifier prerequisite implemented)

Order on each recovery connection, each step refusing before any state change:

1. Accept under the connection and frame caps; `getpeereid` with the peer uid
   equal to `geteuid()`; capture the peer audit token with `LOCAL_PEERTOKEN`.
2. Resolve dynamic code through Security.framework's
   `kSecGuestAttributeAudit` attribute and check the exact bounded designated
   requirement source pinned by trusted commissioning. There is no path input,
   Team-ID-only mode or UID-only success fallback.
3. Issue the challenge. The signed `RecoveryChallenge` is unchanged (D5 is
   declined): the token stays owner-side, and the proof remains the existing
   recovery-possession proof of the enrolled controlling principal.
4. Read the request and verify the proof against the retained enrollment,
   operation, incarnation and generation.
5. Re-read the token through the connection-bound recapture operation, compare
   **(pid, pidversion)**, then repeat dynamic lookup and the SecCode requirement
   check immediately before the mutation commit.
6. Only then consume the nonce and sequence and apply the request.

A failure at any step returns a typed refusal, closes the connection, consumes
no nonce or sequence and does not move the lifecycle state. A peer failure is
audited as a peer refusal, separately from a proof failure. The peer check says
who is on the socket; the proof says who is allowed. The pid alone is not
compared at step 5 because the probes showed that `exec` changes `pidversion`
and leaves the pid and `LOCAL_PEERPID` unchanged.

The source-only verifier prerequisite exists under
`mvm-hostd::caller_identity::macos_peer`, and the connected source-only adapter
under `mvm-hostd::commissioning_bootstrap_connection`, when
`native-caller-identity` is enabled. The verifier returns a non-cloneable
observation with private fields and a `revalidate()` operation. The adapter
accepts one already-connected `UnixStream`, obtains UID and token only from that
connection, owns a duplicate for recapture, and drives one bounded exchange.
Native diagnostics are mapped to payload-free typed refusals. Other platforms
refuse explicitly. This is not a listener or deployed receiver: it does not
bind or discover a socket, commit a mutation, initialize state, hold a key,
write a journal, start a VM or construct a factory.

**Stops:** a different UID (refused at accept, independent of socket mode); an
unrelated same-UID process without the enrolled key (proof) and without the
client code identity (requirement); a socat-style relay (its code does not
satisfy the pinned designated requirement); a replayed proof on another
connection (the per-connection nonce); a replaced client binary that does not
satisfy the pinned designated requirement.

**Does not stop:** a same-UID process that can debug or inject into the verified
client, read the controlling key and run inside the real client, or replace
`mvmctl`; a legitimate client that deliberately passes its connected descriptor
to another process (the token still names the original connector, and nothing
detects it); exec-after-connect and pid reuse beyond what the (pid, pidversion)
re-check observes, so the window is narrowed, not closed; root, host
administrators and a compromised kernel.

### Probe-derived requirements (approved, not implemented)

From the native probes recorded on
[#4655](https://github.com/tinylabscom/mvm/issues/4655#issuecomment-6938617195):

- **Hardened runtime.** The owner is built with hardened runtime. Default
  ad-hoc and hardened builds refused same-UID attach and task-port access in the
  probe; a build carrying `get-task-allow` allowed both, so that entitlement is
  never present. Hardened runtime also makes the dynamic loader ignore its
  environment overrides unless a specific entitlement allows them; ad-hoc
  binaries, with or without the hypervisor entitlement, honored them.
- **Environment allowlist.** The owner's spawn environment is scrubbed to an
  explicit allowlist; no inherited loader variable passes.
- **System libraries only.** The owner links only system libraries. A hardened
  ad-hoc binary cannot start if it links an ad-hoc library (library validation),
  and a non-system library would widen what is loaded.
- **Residual exec-by-path window (D7 accepted).** macOS has no descriptor-pinned
  exec: `posix_spawn("/dev/fd/N")` was refused in every probe run, with the
  descriptor close-on-exec or not. Replacing the path after the descriptor is
  opened changes what runs. The window between the final check and exec is
  therefore documented and not closed; it falls under the same-UID statement
  above.
- **Post-exec self-hash handshake (D8, defense in depth).** After spawn, the
  child reports its own path and code-directory hash before the parent sends any
  bootstrap bytes; the parent compares with the retained digest and kills the
  child on mismatch. This runs after exec, so it cannot prevent execution; it
  only detects replacement. **Exact limit:** SecCode validates the signature the
  kernel loaded, not the bytes now on disk. A binary patched on disk and not
  re-signed still validated in the probe until the kernel faulted the bad page,
  so a code-directory check does not catch an on-disk patch that was never
  faulted in. The handshake is not a substitute for the checks above.

### Status of the approved design

| Item | Status |
| --- | --- |
| Byte-level verifier with the two trains, no skip hatch | PROPOSED-APPROVED-NOT-IMPLEMENTED |
| Manifest inside the signed archive | PROPOSED-APPROVED-NOT-IMPLEMENTED |
| Owner excluded from installer re-signing | PROPOSED-APPROVED-NOT-IMPLEMENTED |
| Retained bundle and archive digest, offline re-verification at spawn | PROPOSED-APPROVED-NOT-IMPLEMENTED |
| Exact-commit clean-tree bundle or typed refusal; no unverified path | PROPOSED-APPROVED-NOT-IMPLEMENTED |
| Peer binding: `getpeereid`, `LOCAL_PEERTOKEN`, SecCode, connection-owned re-check | SOURCE-ONLY-CONNECTED-ADAPTER-IMPLEMENTED; no bind/listen, deployment or mutation commit |
| Security.framework dynamic lookup and exact designated-requirement check; no UID-only fallback | SOURCE-ONLY-IMPLEMENTED |
| Bounded commissioning-bootstrap vocabulary, one-use peer-bound permit session and one connected-stream exchange | SOURCE-ONLY-IMPLEMENTED; no endpoint creation, durable mutation or positive factory |
| Recovery-possession proof unchanged (D5 declined) | Existing source-only proof; receiver not implemented |
| Hardened runtime, environment allowlist, system libraries only | PROPOSED-APPROVED-NOT-IMPLEMENTED |
| Post-exec self-hash handshake | PROPOSED-APPROVED-NOT-IMPLEMENTED |

Native probe status, run once on one macOS 27.0.1 arm64 host with SIP enabled,
five runs per racy probe, which cannot bound a rare race:

| Probe | Result |
| --- | --- |
| 1 token pid equals the connector's | VERIFIED |
| 2 exec changes `pidversion`, not pid; old token fails the lookup | VERIFIED |
| 3 dead connector: token read fails, pid calls report the dead pid | VERIFIED; pid reuse not forced |
| 4 `cdhash` requirement accepts the client, rejects a re-signed copy; ad-hoc hypervisor-entitled binary validates | VERIFIED; on-disk patch not detected |
| 5 relay refused | VERIFIED for same UID |
| 6 same-UID attach against the client | VERIFIED for default and hardened builds |
| 7 exec by descriptor path | REFUTED; no fd-pinned exec |
| 8 loader environment | VERIFIED; ignored only under hardened runtime |

Still needed before any positive factory: a different-UID connector (needs a
second account), a forced pid reuse, Developer ID or notarized artifacts, other
macOS versions, anything needing root or a debugger-entitled caller, and the
native test results recorded by an independent reviewer. The eight native tests
are run and recorded before any positive factory is enabled.

### Conditions that stay in force

- Nothing activates without a fresh security reviewer who is neither the author
  nor the implementer of the PS-06 key-holder operations.
- The keyless operation set
  ([#3716](https://github.com/tinylabscom/mvm/issues/3716)) remains out of scope
  here and blocks the positive path; recovery connections refuse until it exists.
- Both `@firecracker` documented-build gates stay until the real macOS HVF
  scenarios pass.
- No VM runs without an explicit slot authorization. Implementation proceeds in
  small reviewed slices, starting with the native tests.

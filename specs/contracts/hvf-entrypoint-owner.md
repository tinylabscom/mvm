# Cold HVF entrypoint owner

Status: **Conditional architecture direction; prerequisite contract draft.
No launcher or positive factory is enabled by this document.**

Scope: [#4655](https://github.com/tinylabscom/mvm/issues/4655), under
[ADR-022](../adrs/022-target-architecture.md#cold-hvf-invocation-owner).
Issue comments own approval provenance, review revisions and delivery status.
This contract describes required behavior, not evidence that it is implemented.

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

## Recovery authorization

Same UID, a private socket and a discoverable generation are necessary checks,
not sufficient recovery authority. The proposed initial rule is:

1. Start binds an explicitly enrolled controlling principal's public identity
   to the operation. Later control requires fresh proof by that same principal;
   delegated recovery principals are not supported in this first contract.
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

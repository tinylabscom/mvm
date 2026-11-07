# PS06 canonical-builder authority

Status: **B implementation acceptance contract under review. No installed
provider, commissioned issuer, enabled owner factory or native qualification
is claimed by this document.**

The maintainer selected the B direction: protect authority and writable resources
from an attacker-controlled, unconfined process under the developer's UID.
The one-week native target is the designated Mac/HVF demo host. The separately
approved disposable setup covers two non-login principals, private roots, reviewed
launchd jobs, a new demo issuer/pin receipt and bounded native HVF tests. It does
not cover production keys, existing VM state or live Linux execution. Exact host
effects and rollback are reviewed before privileged actions.

Accountable design and integration owner: the PS06 builder-authority delivery
lane in the [maintainer-assigned completion session][ownership]. This lane owns
the design, review corrections and integration; an unanswered request to another
lane does not transfer responsibility. Execution assignments remain separate.

Scope: [PS06][ps06] and the builder prerequisite of [#4655][hvf-issue].
Inspected source: `85336a3c30570bbecd78e2044c32aef6e31a313b`, whose code matches
main `b81235e7fe4ac2b0a57a1cef575b77e9ba7d7485`.
The [earlier delegation approval][direction] did not authorize provisioning or
activation. The concrete deployment and issuer choices below are recommendations
for review, not a claim that the earlier no-new-service constraint allowed them.

## One-week acceptance and backend contract

Qualify one exact canonical-Flake build invocation with protected B authority and
original-owner completion on the designated Mac using HVF. Demonstrate the real
boundary and tamper/replay/crash refusal, not merely a mocked policy response.
Manual reviewed demo provisioning may precede the distributable app/package UX;
it must use the same protected role/code/state boundaries, not root execution
for ordinary builds or same-user helper fallback.

The authority state machine, admission, single-use grants, audit and quarantine
are backend-neutral. Host-OS provisioning/peer identity and hypervisor native
ownership are independent adapters. Mach audit tokens and SMAppService belong
only to the macOS host adapter; HVF instance records belong only to the HVF
execution adapter. A Linux host adapter must establish its own protected
principals and authenticated peer boundary.

Reuse `BuilderVm`, `DriverBuilderVm<D: VmmDriver>` and `VmmDriver` rather than
introducing a second general driver framework. The owned-execution facet must
retain a backend-native owner and terminal evidence through launch, cancellation
and completion. Evidence is constructed only by the trusted native adapter,
bound to the original backend/instance/lifetime, and is not deserialized from an
RPC response, public PID or claimed success status. Trait erasure must not erase
uncertainty, turn missing evidence into success, or widen admission purpose.

An adapter must supply exact-object read-only/writable input custody,
original-child lifetime ownership, bounded stop and backend-native finalization.
Gate missing capabilities before launch; never fall back to generic boot,
path reopen, detach/attach or another backend. A caller-supplied capability flag
is not evidence that the implementation satisfies those requirements.

| Backend | Acceptance boundary |
| --- | --- |
| HVF on the designated Mac | Native positive build and negative security/lifecycle witnesses are required for the one-week demo. Existing `OwnedInstance`/`ConfirmedExit` semantics remain intact. |
| Firecracker on Linux | Shared trait/adapter and conformance source work; live native acceptance is deferred and must be labeled unqualified. Current `FcRunningVm` is detached/PID tracked, so its successful `wait` does not supply original-owner evidence. |
| Other backends | Use the extension contract; explicitly refuse the protected operation until the required native custody and evidence adapter exists. Generic builder support alone is insufficient. |

Compilation, mocked trait tests and Linux adapter unit tests are distinct from
native Firecracker qualification. No SSH or live Linux work follows from this
Mac-only scope. Artifact reproduction, release signing/publication and the full
released PS06 consumer/demo acceptance remain separate from this one build.

## Boundary and alternatives

The host administrator, operating system and protected installation path are
trusted. Arbitrary developer-UID processes are not. Workload-adjacent parsers,
network endpoints and VMM children must not gain authority-key access.
Administrator compromise, a malicious trusted installer and restoration of an
entire older host by an administrator are outside this boundary.

| Approach | Disposition |
| --- | --- |
| A: same developer UID, confine every attacker role | Not the selected outer boundary. An unconfined same-UID sibling can still attack named state directly. |
| B: one protected service UID for authority and all runtime work | Smallest deployment experiment, but a runtime compromise reaches that UID's key and policy unless complete confinement prevents it. |
| B: separate authority and runtime UIDs, with confined workers | Recommend for the production design. More provisioning and IPC work, but preserves key-holder separation and limits runtime compromise. |
| Root daemon accepting arbitrary paths, programs or signing bytes | Reject. Root is needed for reviewed installation, not routine build execution. |

Retain two candidate custody routes against the same unconfined same-UID
attacker: the separate-principal reference boundary below, and an existing-holder
route only if native evidence establishes equivalent protection of issuer,
mutable state, writable resources and independently expected identity. The spike
found no existing complete mechanism for the latter; it is not a second backend
to build speculatively or a reason to delay the reference-boundary recommendation.
Both routes have the same admission, restart, quarantine and adversarial gates.
Commission at most one qualified route per host. Route selection and issuer
identity are protected state; failures never switch routes, keys or legacy
signers. Changing routes requires separate commissioning and preserved exclusion
of all uncertain old resources.

Use two non-login principals, proposed names `_mvm_authority` and `_mvm_runtime`.
Numeric IDs are allocated and recorded by the trusted installer, never assumed
or taken from a client request. Refuse an existing account/name collision unless
its protected installation receipt proves that it is the intended managed role.

The authority owns policy, issuer custody, grant/revocation state and canonical
audit. The runtime controller owns original-child lifetimes, writable images and
per-invocation resource quarantine. Only confined workers parse guest results or
perform workload-adjacent work; they cannot read the authority root or modify the
runtime controller's journal. Sharing the runtime UID does not provide that
last separation: mandatory worker confinement and closed handle transfer do.

The CLI, Studio and SDK remain unprivileged clients. They submit bounded typed
requests and copy input bytes in; they receive bounded results and copy outputs
to user-selected destinations themselves. The provider never becomes a
privileged arbitrary-path reader, output writer, shell or program launcher.

## Deployment and protected bootstrap

Recommend a signed/notarized installer package containing a protected,
code-signed registrar application and its launchd helpers:

```text
/Library/Application Support/MVM/MVM Provider.app
  Contents/MacOS/
  Contents/Library/LaunchDaemons/
/private/var/db/mvm/authority
/private/var/db/mvm/runtime
```

These are proposed installation paths, not existing installed components.
Use the canonical macOS `/private/var` ancestry rather than silently exempting
the system `/var` symlink from installer path checks.
The administrator owns the application, deployment receipt and every code-path
ancestor. Neither caller nor runtime UID can replace them. Each state root and
its ancestors exclude the caller UID; runtime cannot read or modify authority
state. Validate actual ownership, ACLs, modes and symlink-free ancestry, not just
the final file's owner. On the inspected host `/Applications` was caller-writable;
placing a root-owned executable there alone would not establish this guarantee.

Use `SMAppService` for the app-contained LaunchDaemon lifecycle and status,
with fixed `BundleProgram` paths and explicit `UserName`/`GroupName` roles.
The package provisions the accounts and private roots; ServiceManagement does
not. The registrar must actually execute within its protected main app bundle.
The existing guest `mvm-host-agent` is not elevated or renamed into this role.

Apple documents code signing, notarization and administrator approval in System
Settings for LaunchDaemons. Package installation authorization and service
approval may be separate steps; two roles may have separate approval states.
Do not promise a single dialog until the complete supported-platform flow is
qualified. `Enabled` is not proof that authenticated provider readiness holds.

The installed SDK and [SMAppService documentation][smappservice] establish the
lifecycle API, not this product's complete deployment. Apple's
[package migration example][package-example] supports an app contained in a
package; its LaunchAgent example does not qualify this LaunchDaemon composition.
There is no current repository implementation of this installation lifecycle.

### Issuer and expected identity

Recommend a fresh provider-internal issuer, separate from user caller enrollment
and the legacy user-readable host signer. Importing a previously user-readable
key cannot recall earlier copies. Generating a new issuer is a concrete new
provisioning decision, not an action performed by this spike or inherited from
the earlier delegation approval.

Proposed trusted setup sequence:

1. The installer validates the signed code cohort and provisions the two role
   identities, protected roots and a root-owned initialization intent.
2. A fixed initialization entry point runs as the authority UID, exclusively
   locks the authority namespace and creates the issuer only for that intent.
   It exposes no secret and accepts no caller-selected key or key path.
3. Over a private installer-created bootstrap channel, the installer obtains
   the public identity and records it with the deployment identity, role IDs
   and approved code requirements in the root-owned deployment receipt.
4. The installer retires the initialization intent before public request
   acceptance. Normal startup compares the loaded issuer's public identity to
   that receipt. Missing identity, state, receipt or interrupted commissioning
   refuses; startup cannot recreate an empty ledger or self-pin a replacement.

Installation crash recovery is an explicit administrator setup action, not an
API available to the requesting developer. No production key is generated,
imported, retired or read here. The exact installer-to-initializer authentication
and intent-consumption protocol needs implementation review before commissioning.

Legacy keys remain outside this provider's authority domain. Neither callers nor
legacy `SignHost`/`SignPlan` endpoints can produce signatures under the new
provider identity. Consumers must explicitly trust that identity for the closed
provider purpose; trust is not copied from an old key's self-attestation.
Prior extraction of any issuer would invalidate its custody assumption.

## Authenticated operations and durable state

Public Mach/XPC service registration is discovery, not authentication. Bind each
accepted message to kernel-supplied sender evidence, validated release code and
the retained process lifetime. Use Security.framework audit-token-based dynamic
code validation, not request PIDs, Team ID alone or socket path ownership.
The runtime-to-authority channel additionally authenticates the installed runtime
role. Authentication is bidirectional: runtime validates authority responses
against the protected receipt's role UID, code cohort and connection lifetime,
and authority applies the corresponding checks to runtime. Successful service
lookup alone establishes neither. An audit token identifies the immediate sender;
it does not prove that an authorized process has not relayed attacker-controlled
data.

An invocation binds full caller enrollment including installation identity,
tenant, exact canonical request/plan, frozen-input and job digests, policy
revision, owner incarnation, provider epoch, fresh challenge and sequence.
Possession proof does not itself admit policy. New builder-session proofs have
their own closed purpose; registration, telemetry and recovery proofs cannot be
reinterpreted as builder-birth permission.

The authority maintains a serialized durable grant/reservation/revocation/audit
journal. The runtime maintains its resource/quarantine journal. Use fixed
provider-private lockfiles, kernel-held last-close locks and crash-safe durable
replacement; no caller-selected lock domain or network-port lease is needed.
Acquire exclusion before any read-modify-write or commissioning. No worker
inherits the holder lock or has a path that can unlink or replace its inode.

Only the protected installer initializes a journal. A missing, corrupt or
inconsistent journal is not an empty namespace. Commit and synchronize state
before acknowledging authority or dispatching effects. Cross-process transitions
use durable operation IDs, consume-before-effect and refusal on unknown results,
not an assumed atomic transaction across two journals and an OS process spawn.
The exact journal format and crash protocol remain implementation work.

Restart creates a fresh session epoch, invalidates old unconsumed allowances,
retains spent reservations and quarantine, and never reconstructs an original
native owner. Automatic service restart is availability, not recovery authority.
The supported attacker cannot rewrite protected state; this is not a claim of
hardware monotonic rollback resistance against a trusted administrator.

### Closed operation vocabulary

Names below describe proposed typed operations, not existing public APIs.
Provision/revoke administration is separate from delegated builder requests.

| Operation | Independent checks and result |
| --- | --- |
| `ReserveBuilder` | Verify the installed grant, authenticated caller, exact request, input custody and policy. Durably consume one reservation before endpoint/VMM effects; create an internal connection-bound session. |
| `ObserveBuilder` | Return a bounded authenticated observation, including uncertainty. Never reserve again, recreate an owner or redeliver a birth allowance. |
| `AdmitBuilderPlan` | Derive/verify and sign only the canonical plan independently admitted for this reservation. No forwarding to legacy `SignPlan`. |
| `PrepareBuilderEndpoint` | Construct the exact fixed FlowMux builder role/configuration from retained admission. No arbitrary registration or raw host key. |
| `CommitBuilderBirth` | Separately consume one `Endpoint` or `OriginalVmm` allowance for the exact admitted backend, serialized against revocation/expiry, with a finite per-role activation deadline. |
| `BindOriginalInstance` | Bind the backend adapter's actual original supervisor/native incarnation and retained connection evidence. No caller-authored PID, cross-backend substitution or pre-birth native generation. |
| `AuthorizeOriginalStop` | Authorize only the bound original instance's closed stop request and fresh connection challenge. No signal-by-PID, adoption or replacement. |
| `AppendBuilderAudit` | Construct phase-correct canonical events from retained admission and verified evidence, never arbitrary bytes or caller-selected event names. |
| `CloseBuilder` | Check the entire compound native/guest/output/audit completion policy before durable terminal success. A response is not `ConfirmedExit`. |

Internal reserved sessions and birth allowances are non-cloneable and have no
public unchecked or deserializing constructor. Public grant IDs and RPC replies
are observations, not transferable launch authority.

Retain the cold-owner 4-KiB control/possession ceiling and bounded exchange
deadline; canonical plans retain their separate 64-KiB bound. Bulk media uses a
separate bounded transfer. Reject unknown/duplicate fields, versions, unexpected
handles, truncated messages, stale challenges, sequence wrap and cross-purpose
signatures. Specify exact full-width typed encoding and domain separation before
implementing signatures.

For a lost mutating reply, the attempted birth is non-launchable unless the
original live owner already retained its allowance. Observation cannot redeliver
it. A durable consumed record stays spent; already retained resources remain
owned. Reconnect can observe/drain the same original operation, not resurrect
it after owner or holder death.

Birth commitment is the authorization linearization point, not physical spawn.
Revocation before commitment wins. Revocation after commitment cannot atomically
undo later kernel process creation: record cancellation, serialize local
activation against it, enforce the finite deadline and stop through original
custody if birth already linearized. Endpoint and VMM have independent allowances;
committing the endpoint never authorizes an indefinitely delayed VMM.

## Reuse and required adapters

Source links below are pinned to the inspected code, not an assertion that
the referenced paths already implement a protected provider.

| Existing source | Reuse and boundary |
| --- | --- |
| [Signer helper](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-hostd/src/bin/mvm-signer-helper.rs#L26-L73) | Adapt closed dispatch/key-holder internals. New authenticated provider bootstrap is required; launchd parentage must not be confused with orphaned user-helper execution. Do not globally remove orphan protections or expose legacy signing. |
| [Host-agent launch](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-vmm/src/host/host_agent_spawn.rs#L119-L198) | Reference bounded readiness and worker supervision only. Its invoking-user home, raw-key loader and buildable/overrideable executable discovery are not provider authority. |
| [Caller proof adapter](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-hostd/src/caller_identity/mod.rs#L28-L72) | Reuse purpose-separated possession verification where selected; not provider custody, authenticated IPC or grant issuance. |
| [Local host interface](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-core/src/host_interface/local.rs#L69-L112) | Policy/preflight vocabulary only. Default readiness, in-memory node state and permissive resource/secret checks cannot stand in for protected admission. Node-state quarantine is not invocation quarantine. |
| [Driver custody seam](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-vmm/src/driver/traits.rs#L140-L206) | Reuse the backend dispatch and fail-closed `boot_custodied` pattern. `RunningVm`'s generic status/wait and currently HVF-shaped `KernelStopOutcome` do not already define a backend-neutral original-owner proof. |
| [Firecracker disk custody](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-backends/src/driver/fc.rs#L1318-L1404) | Reuse held disk validation/handoff, but add real native-owner retention before protected Firecracker launch can be supported. Detached/PID-file tracking and workload-sidecar wait cannot implement that contract by renaming a type. |
| [Original HVF child](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-backends/src/driver/hvf.rs#L567-L752) | Retain actual child, descriptor inheritance, readiness and rollback mechanics. Add the builder-specific validator/owner composition; do not weaken cold-entrypoint admission. |
| [Restore-file custody](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-vmm/src/host/restore_image.rs#L212-L353) | Reuse read-only file validation, unlinking and child-only descriptor inheritance once preparation is protected from all attacker roles. Current helper alone explicitly does not provide hostile same-user isolation. |
| [Writable disks](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-vmm/src/driver/prepared_disks.rs#L260-L399) | Preserve exact held backing/sidecar identity, alias rejection and last-close exclusion for output/store disks. |
| [Builder media](https://github.com/tinylabscom/mvm/blob/85336a3c30570bbecd78e2044c32aef6e31a313b/crates/mvm-build/src/builder_vm_transport.rs#L528-L549) | Keep fixed input/output disk protocol. Current arbitrary builder input attachment is path-based, not already descriptor-backed. |

The new minimum data-plane adapter is an exact-slot **read-only data-disk FD
table**. The current four fixed boot-image roles cannot carry arbitrary builder
input. Do not overload them or claim this adapter already exists.

Preparation copies bounded input into provider-private staging inaccessible to
caller and worker roles, independently verifies the packed canonical tree/job,
closes every writer, opens the exact regular file read-only and unlinks it
before export. No writable FD/mapping is exported or inherited. Input admission
hashes that final object; the VMM receives the same retained object. The receiver
validates unlinked read-only regular files, exact disk-slot coverage, size/digest,
and no aliases; it cannot reopen a fallback pathname.

Distinct UIDs plus enforced staging ancestry/profile rules prevent preparation-
time attacker writer aliases. Unlinking alone still does not revoke them.
Worker task/debug access and descriptor inheritance must preserve this boundary.
The authority signs independently verified measurements, not an arbitrary
caller's pathname/hash; complex media parsing stays in constrained verifier
work, outside the minimal key holder.
That verifier receives read-only custody of the exact object without staging
mutation or journal access. Its authenticated result binds object identity,
measurement, invocation and code cohort; confinement alone does not establish
measurement correctness. Define and review that result protocol before admission.

This replaces the earlier same-UID Mach-memory disk and TCP lease proposals.
Their primitive experiments are historical feasibility evidence, not required
production mechanisms. Keep output/store disks on `PreparedWritableDisks`.
Use the existing disk format and guest device contract, not a new block backend.

## Original ownership and completion

The runtime controller hosts the thin client-library original-owner role;
the untrusted CLI does not retain privileged children on the provider's behalf.
Before creation, one owning aggregate retains the store lock, input/output
transport, staged job, endpoint and original HVF resources. Startup errors retain
typed uncertainty/custody rather than flattening it into a string.

Only canonical Flake and the approved `FrozenFlakeDiagnostic` route are admitted,
with actual frozen inputs, expected revision and graph-observation checks.
No arbitrary shell job, Raw, Stage0, Install or implicit bootstrap fallback.
Pre-resolution input is not an invented root lock or narHash.

The guest adapter must bind job, actual consumed input and completion to an
authenticated transport/session and storage-flush barrier. A result file, EOF,
console halt or observed `Stopped` is not that evidence.

No writable-output extraction precedes authenticated guest flush, original-
generation native finalization and original writer lifetime exit. Then confirm
endpoint exit, validate and durably finalize bounded outputs, close canonical
audit and commit terminal success. Preserve separate build, flush, native stop,
endpoint, output and audit failures. Useful bytes do not turn cleanup failure
into success. RPC observations cannot reconstruct native `ConfirmedExit`.

Owner death, partial native evidence or lost state preserves absorbing resource
quarantine. Names, paths, copies and replacement inodes cannot bypass the
provider resource index. Only the original live owner's complete terminal
evidence plus durable authority/runtime accounting can retire matching
quarantine. No automatic adoption, cleanup or resurrection on service restart.

Preserve the final cold-owner resource decision: summed vCPU time and the
existing guest-memory ceiling, not superseded hard macOS memory/thread/process
limits or additional owner-death containment. Do not increase the builder wait.
Local-built health admission remains a distinct internal constructor bound to
verified outputs and the intended health invocation, never fabricated registry
identity. Health, signing, export and publication are not implicit build powers.

## Setup, upgrade and failure UX

Setup is explicit and guided; ordinary admitted builds do not run `sudo`.
Report distinct missing-provider, approval-required, code/identity-mismatch,
unavailable and quarantined states. No automatic invoking-user helper, temporary
issuer, unscoped signer or weaker backend fallback.

Upgrade drains owners before unregistering a service. Apple documents that
unregister terminates a running daemon without waiting for reaping; it is not
graceful owner completion. Observe actual exits before code/state replacement.
Forced disable/crash preserves uncertainty and quarantine. Reject mixed code
cohorts; a schema mismatch never resets state to empty.

Uninstall separates stopping/removing code from destroying authority/state.
Default removal preserves uncertain resources and their role identities;
destructive purge requires a separate reviewed administrator action. Account
IDs cannot be recycled into a different owner while retained resources exist.

## Qualification and evidence limits

The static spike exercised two proposed plist shapes and negative ownership-plan
checks, not installed jobs. `plutil` acceptance does not prove account existence,
launchd execution, XPC authentication, entitlement compatibility or approval UX.
Earlier synthetic probes ran on macOS 27.0.1/SDK 27, not macOS 26/HVF qualification.
They disproved generic-password trusted-read ACLs as mutable-state integrity and
same-UID named-file sealing. They accessed no production issuer.

Before any positive factory, review and qualify:

- Installer provenance, account collisions, complete ancestry/ACL checks,
  interrupted setup and protected issuer-pin delivery.
- Per-message peer/code/lifetime authentication, authorized-relay exclusion,
  exact enrollment and policy bindings, and every legacy signing ingress.
- Journal crash points, concurrent reserve/revoke, lost replies, expiry on both
  sides of role commitment, sequence wrap and restart without resource reuse.
- Caller and confined-worker read/write/rename/link/delete/task/FD attacks on
  issuer, journals, input preparation and old writable resources.
- Read-only input descriptor coverage, preparation aliases, original-object
  VMM consumption, child inheritance and absence of pathname fallback.
- Every missing native/flush/endpoint/output/audit terminal half, wait errors,
  full disk, failed synchronization, output overflow and blocked result readers.
- Real signed/notarized setup, denied/revoked approval, mixed-version upgrade,
  active-owner drain, forced service stop and retention-preserving uninstall.

Source review and static checks do not prove any of those native compositions.
Installation, commissioning, native execution, artifact reproduction, genuine
release signing/publication and consumer acceptance remain separate gates.
The delivery lane retains responsibility through review and implementation;
component reuse is not a handoff or completion claim.

[ownership]: https://github.com/tinylabscom/mvm/issues/3716#issuecomment-6668167338
[direction]: https://github.com/tinylabscom/mvm/issues/4839#issuecomment-6505157542
[ps06]: https://github.com/tinylabscom/mvm/issues/3716
[hvf-issue]: https://github.com/tinylabscom/mvm/issues/4655
[smappservice]: https://developer.apple.com/documentation/servicemanagement/smappservice
[package-example]: https://developer.apple.com/documentation/servicemanagement/updating-your-app-package-installer-to-use-the-new-service-management-api

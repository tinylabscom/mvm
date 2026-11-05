# PS06 canonical-builder authority

Status: **Proposed implementation contract; not an installed delegation or
an enabled owner factory.** Native qualification and operational permissions
remain separate from design review.

Accountable design and integration owner: the PS06 builder-authority delivery
lane in the [maintainer-assigned completion session][ownership]. This owner
owns the packet, review corrections and integration; an unanswered request to
another lane does not transfer that responsibility. The existing runtime,
artifact and consumer lanes retain their [execution assignments][delivery].

Scope: [PS06][ps06] and the builder prerequisite of [#4655][hvf-issue].
Inspected source: `e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9`.
The [approved direction][direction] is default-deny delegation to an already
enrolled principal for one tenant, operation, exact plan/input identities and
policy revision. It did not authorize commissioning or activation.

## Decision and alternatives

Use the existing `mvm-signer-helper` role for narrowly typed, independently
authorized builder operations. Keep the original-child owner in the client
library, hosted by the proposed thin `mvm-hvf-run-owner` executable from the
[cold-owner contract](hvf-entrypoint-owner.md). Neither the CLI nor a general
host-agent service becomes a signing or native-spawn oracle.

| Approach | Disposition |
| --- | --- |
| Reuse entrypoint registration or canonical `SignPlan` as builder permission | Reject. Possession and canonical syntax do not authorize a builder, local inputs, audit closure or native control. |
| Add a new generic signer/lifecycle daemon | Reject. It adds another receiver and authority boundary without solving independent authorization. |
| Add a closed delegated profile to the existing key holder and compose it with original-child custody | Recommend. Reuse framing, native identity custody and consume-before-effect patterns, but implement the missing authorization and protected state explicitly. |

This is not an assertion that the existing helper already enforces this
profile. New delegated requests must not reach its legacy dispatcher.
No new credential, privileged service, elevation or generic backend framework
is part of this first mode.

## Existing pieces and the gaps they do not fill

| Source at the inspected revision | Reuse | Missing behavior |
| --- | --- | --- |
| `mvm-contract::protocol::host_signer::SignRequest` and `mvm-hostd::host_signer::plan_payload` | Closed request vocabulary, canonical plan validation, bounded framing | `SignPlan` explicitly does not authorize a principal or admit policy. |
| `mvm-hostd::audit_signer::helper` and the host-agent helper supervisor | Existing key-holder process and restart supervision | No provider-owned builder grant store, revocation or authenticated builder session. |
| `mvm-hostd::caller_identity` and `mvm-core::crypto::recovery_possession` | Existing full enrollment and purpose-separated possession | Possession is not grant issuance, peer authentication, admission or cleanup authority. |
| `mvm-hostd::supervisor::caller_registration` | Independently expected binding and durable consume-before-launch pattern | Its consumed capability is entrypoint-only; its replay marker is not a grant or revocation registry. |
| `mvm-build::pipeline::frozen::FrozenInputs` | Actual filtered staging, tree digest and before/after verification | A supplied digest or mutable pathname is not independently admitted input custody. |
| `OwnedEndpoint`, `OwnedInstance` and `ConfirmedExit` | Actual child retention, sticky wait failure and compound native exit proof | The generic builder still uses a detached endpoint and extracts output even after its wait expires. |
| `AuthenticatedBootImageExpectations` and `FrozenBootImageBytes` | Verified fixed-role boot bytes | Registry authority cannot be fabricated for a local build; a separate local-build admission constructor is required. |

The current host-agent launcher also reads the software host key. Therefore
“one helper process exclusively owns all signing authority” is not a valid
claim about the inspected system. Delegated-owner startup must remove that
read from its own reachable launch path, not merely omit it from a new DTO.

Pinned source anchors:

- [Signer request semantics](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-contract/src/protocol/host_signer.rs#L43-L73)
  and [canonical syntax check](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-hostd/src/host_signer/plan_payload.rs#L1-L55).
- [Existing helper signing](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-hostd/src/audit_signer/helper.rs#L211-L233)
  and [launcher key loading](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-vmm/src/host/host_agent_spawn.rs#L119-L128).
- [Existing entrypoint consumption](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-hostd/src/supervisor/caller_registration.rs#L700-L779)
  and [owned frozen staging](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-build/src/pipeline/frozen.rs#L8-L63).
- [Current generic builder loop](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-runtime/src/builder_runner/runner.rs#L233-L306)
  and [caller-local store lock](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-runtime/src/builder_runner/driver_builder.rs#L299-L384).
- [Native control key loading](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-vmm/src/host/hvf_stop.rs#L74-L111)
  and [original-child exit and stop](https://github.com/tinylabscom/mvm/blob/e78c96f5e6c73fe1134b8ccf50d19221a8e09fa9/crates/mvm-vmm/src/host/hvf_stop.rs#L272-L369).

## Provisioning and protected state

The provisioner is an **explicit operator commissioning action in the existing
key-holder role**, not the builder, CLI request parser, enrollment routine or
`SignPlan`. It installs one exact delegation after independent authorization
of that action. It is not a network service and has no general sign-bytes API.

### Selected custody proposal and the decision it requires

The issuer is the existing Ed25519 host key currently loaded from
`mvm_keys_dir()/host-signer.ed25519`, not the enrolled caller key and not a
new key pair. The selected proposal is to commission those same 32 key bytes
into a macOS Keychain generic-password item owned by the existing signer-helper
role. Use Security.framework `SecItemAdd`/`SecItemCopyMatching`/`SecItemUpdate`
with a `SecAccess` trusted-application requirement restricted to the verified
signer-helper application. This is software Ed25519 held in the helper's
memory after native retrieval, not a claim of Secure Enclave Ed25519 support.
Do not combine this ACL model with an assumed data-protection access-group
entitlement or the caller store's current default generic-password access.

**Explicit custody decision required before implementation of a positive path:**
approve or reject importing the existing issuer into this protected item,
retiring owner-readable software copies and adapting that issuer's existing
readers. The earlier default-deny design approval did not approve this migration.
The packet selects the mechanism for review; it does not execute or authorize
the migration. If rejected, this topology needs a different reviewed isolation
mechanism, not a software fallback advertised as native custody.

### Exact-grant commissioning ceremony

A proposed operator-only command, `mvmctl trust builder-authority commission`,
uses the existing client library to prepare a bounded commissioning candidate.
This command does not exist at the inspected revision. It selects actual source
and published builder inputs independently of the delegated owner's request,
creates the sealed transport described below and supplies its read-only handles
through the internal trusted bootstrap. It is not exposed on the delegated
control channel and accepts no arbitrary signing payload.

Inside the signer-helper commissioning path, recompute the candidate digest
from the fixed typed grant and actual sealed-object measurements. A fixed native
confirmation view presents the tenant, full controlling identity, mode,
operation, input/media digests, policy revision, resource limits and expiry.
The helper obtains its own LocalAuthentication device-owner authorization
context after presenting that immutable candidate; it never accepts a frontend
boolean or forwarded authorization context. A change to any candidate field
invalidates confirmation and starts a new ceremony. Cancellation installs
nothing; headless invocation without this explicit commissioning authority
refuses. Do not add an unattended `--yes` bypass.

Only after confirmation may the holder import an explicitly approved existing
key, create the protected grant record and acknowledge durable installation.
Key import, grant installation and issuer retirement have distinct receipts;
failure cannot silently generate a replacement key or activate a partial grant.
Native authorization authenticates the operator; the fixed candidate digest
binds the exact action that operator approved. Neither alone is sufficient.

The first implementation is macOS/HVF only. A native-custody qualification
must prove that the delegated owner cannot read the issuer key, alter protected
policy/replay state, or invoke a legacy signing path, directly or through a
proxy. Same UID, private directories, `0600`, a public key, a pathname or a
bare executable hash do not establish that boundary. If the platform mechanism
cannot meet it, this profile remains disabled; do not replace it with a
requester-writable file store.

One installed grant contains:

- Format version, issuer identity, random grant ID and issuance epoch.
- Full enrolled controlling identity: installation UUID and Ed25519 public key.
- Tenant, one operation ID and one owner incarnation.
- Mode `CanonicalFlakeOneShotV1` or `FrozenFlakeDiagnosticOneShotV1`.
- Canonical proposed-request/plan digest, staged input-tree digest, job digest,
  expected MVM revision and selected policy revision.
- Verified builder/kernel/runtime identities and exact finite resource,
  execution and output limits.
- Not-before and last-birth times; the authorized native graph has one
  endpoint child and one fresh VMM child, not arbitrary program/argv.
- The closed operation set below, with one original birth.

The issuer derives these fields from its independently validated commissioning
input. A request cannot supply the trusted issuer, expected policy revision,
eligible-principal list or grant contents that are used to authorize itself.
The native confirmation must identify the operation and exact binding being
installed. Enrollment alone never creates a grant.

### Authoritative state and restart policy

For the first mode, permit one commissioned builder operation per holder
incarnation. Store policy revision, issuer identity, grant, reservation,
revocation and resource/terminal decisions in one bounded native Keychain
state item, separate from the issuer-key item. The state item is at most
64 KiB and has the same restricted application ACL. The holder serializes
mutations, increments its state revision and replaces the whole item with one
`SecItemUpdate`; a readback must match before it acknowledges. No distributed
transaction across separate grant/revocation files is assumed.

At each holder start, generate a fresh unpredictable issuance epoch in memory.
**Every previously installed grant and session is invalid after any restart.**
New commissioning is required; neither a record readback nor an old signed
grant restores authority. An existing record can preserve refusal evidence but
cannot reactivate the old epoch. A second holder must not share an active
operation; exclusive startup and one holder per commissioned namespace are
part of the native qualification, not a best-effort process-name check.

All writable resources of that operation live in the fresh epoch's managed
namespace and are registered before any child effect. Reuse from a prior epoch
refuses even if its record is absent or appears terminal. Restart therefore
does not depend on reconstructing which pre-crash write reached disk. A new
operation uses newly created writable images, with held `create_new` custody
and distinct actual file identities; it cannot rename an old image into the
new namespace. Read-only published inputs remain separately authenticated.
This intentionally gives up cross-restart writable-store cache reuse in the
first mode; it does not introduce per-worktree builder VMs.

The supported rollback adversary is an untrusted owner/frontend that can alter
its own files, submit old protocol records or restart/disconnect, but cannot
modify the native-custody items or the trusted OS. It is not a defense against
an administrator restoring the OS/keychain from backup. Within one holder
incarnation, reject any revision below the in-memory high-water state and any
native readback mismatch. After restart, the fresh volatile epoch invalidates
all old positive authority regardless of the restored record. Missing/corrupt
state never clears resource refusal. Stronger host-administrator antirollback
would need a separate hardware/remote freshness decision and is not claimed.

Grant records and operation records have different identifiers even though
their authoritative transition is in that one item. Signed grant bytes alone
do not prove currency or non-consumption. Reservation, birth authorization,
revocation and terminal replacement each require native update plus readback
before their corresponding acknowledgement or effect.

Replacing a grant first durably revokes its predecessor. It cannot authorize
a second launch for the predecessor's operation, clear resource quarantine or
extend an active invocation. Replacement after uncertain birth requires a
distinct, independently authorized operation with disjoint permitted resources.

## Closed provider operations

These are proposed typed operations, not existing public API names.
Every request has a version, grant/operation binding, fresh connection
challenge, nonzero monotonic sequence and its phase-specific typed payload.
No operation accepts arbitrary signing bytes, an executable, shell text or
caller-selected audit event names.

| Operation | Independent checks and result |
| --- | --- |
| `ReserveBuilder` | Verify the installed/current grant, exact enrolled principal and actual authenticated owner process; independently validate the proposed request, frozen inputs and policy. Durably consume the one-use reservation before any endpoint/VMM creation. Return one connection-bound session, not a serializable launch capability. |
| `ObserveBuilder` | Authenticate a fresh observation connection and return a bounded view of the same operation. Never create another reservation, return a new birth capability or turn absence into permission. |
| `AdmitBuilderPlan` | Derive/verify the canonical plan from that reservation and independently resolved policy. Bind the actual plan ID/nonce and effective configuration. Sign that admitted plan only; this alone permits no process birth and cannot forward to ordinary `SignPlan`. |
| `PrepareBuilderEndpoint` | Derive the exact existing FlowMux builder identity/control configuration from the admitted plan, tenant, boot/session binding and fixed role graph. No raw host key, arbitrary host-agent registration or unrestricted identity mint is exposed. |
| `CommitBuilderBirth` | For the closed role `Endpoint` or `OriginalHvfVmm`, recheck expiry/revocation, admitted plan and phase; durably consume that role's one birth allowance. Each role has its own finite activation deadline. A second commit, role substitution or VMM commit after revoked endpoint preparation refuses. |
| `BindOriginalHvf` | Bind the actual original supervisor instance and authenticated native connection to the retained session. Check expected boot/configuration identity and native incarnation. A caller-authored PID, generation or status file is not sufficient. No native generation exists in pre-birth requests. |
| `AuthorizeOriginalStop` | Authorize only the exact closed HVF stop request for that bound instance and its fresh native connection challenge. No signal-by-PID, attach, adoption or replacement operation exists. |
| `AppendBuilderAudit` | Construct canonical, phase-appropriate audit events from the retained plan and verified evidence. Enforce the existing chain identity and event order; no arbitrary audit payload signing. |
| `CloseBuilder` | Verify matching original-instance finalization, the armed lifetime observation, session-bound guest completion/flush, endpoint exit and durable output/audit result. Record success only when the entire existing completion policy holds. This response is not `ConfirmedExit` or permission to reconstruct one. |

Provision/revoke actions are absent from this delegated operation set.
Grant IDs, public bindings and RPC responses are observations, not bearer
authority. Only the provider creates its internal non-cloneable
`ReservedBuilderSession`; only the trusted owner integration can create the
corresponding internal `BuilderBirth` after admission. Neither implements
`Deserialize` or has a public unchecked constructor.

Retain the existing bounded Unix control transport for frontend observations.
The new key-holder channel below uses bounded typed message bodies, not an
unmodified request-per-connection helper session. Plan payloads retain the
existing 64-KiB ceiling in a separately bounded bootstrap transfer.
Control/possession messages retain the cold-owner 4-KiB ceiling and monotonic
exchange deadline. Bulk inputs/output never ride in control messages.
Unknown fields, versions,
verbs, duplicate fields, truncation, future issuance times and sequence wrap
refuse. New grant signatures use a distinct domain and a fixed typed encoding
that preserves full-width integers, not caller-provided JSON or a borrowed
registration/telemetry/recovery purpose.

## Connection and process-host binding

The client library prepares the exact released owner executable through the
existing verified-artifact path and retains its actual `Child` from birth.
The owner is a thin client-library entry point, not a hidden CLI subcommand,
resident host-agent replacement or new privileged daemon.

Before untrusted startup parsing, establish the bounded bootstrap and the
fixed role's authority restrictions. For the new delegated key-holder channel,
select an anonymous Mach receive right in the existing helper, supplied only
through the verified internal bootstrap; do not register a new global Mach
service or reuse the helper's legacy UDS as an authenticated session.

Each received message requires a kernel-supplied audit trailer, requested with
the Mach audit-trailer receive option. Authenticate that message's sender
audit token, not a PID copied from the request or a one-time socket peer
snapshot. Resolve its dynamic code through Security.framework
`SecCodeCopyGuestWithAttributes` with the audit token and validate the exact
role/designated requirement using `SecCodeCheckValidity`. Requirement
provenance is the verified publisher-authorized owner executable, not a hash
or Team ID supplied in the request. Bind the observed process lifetime before
accepting the role, revalidate the code identity at authenticated transitions,
and refuse identity/lifetime/exec ambiguity.

An internal session additionally binds the provider epoch, actual sender,
owner incarnation, enrolled controlling identity, operation, fresh challenge
and sequence. Native principal proof uses a new closed builder-session purpose
that covers this full transcript. Do not reinterpret the existing recovery
possession signature as including an audit token it does not contain.
The credential operation itself authenticates the same sender/transcript
against the installed grant; it cannot sign an arbitrary forwarded challenge.

Mach send rights may be transferred, but a forwarded message has the
forwarder's kernel audit trailer and therefore fails the retained sender
binding. Reconnect authenticates again with a fresh challenge; it can observe
or stop the original retained operation, never create another birth permit.
Unexpected port/descriptor transfers and out-of-line payloads refuse. Verify
these properties on the supported macOS release, including exec/PID-reuse and
authorized-proxy races, before enabling the channel.

For this first mode, a lost mutating reply before the owner has retained its
local birth allowance makes that attempted birth non-launchable. Observation
does not redeliver or reconstruct the allowance. The durable provider record
stays consumed; the owner retains any already acquired child/resources and
drains only their existing stop/accounting obligations. This deliberately
chooses refusal over exactly-once launch continuation after an unknown reply.
If the original live owner already retained and consumed a birth allowance,
reconnect can service that same native operation but cannot return it to a
pre-birth state. Holder restart never supplies reconnect authority.

The delegated profile cannot reach the local-key loader, the unscoped
`SignHost`/legacy `SignPlan` path, host-agent control signing, or a proxy that
forgets the original peer/session. This is enforced at every key-holder ingress,
not by trusting the frontend not to call an older API. The first source slice
must establish that cut before adding a positive builder factory.

| Ingress | Required enforcement |
| --- | --- |
| Raw host-key reads, including `host_agent_spawn::load_host_signing_key` | No issuer key file is readable in the commissioned profile. Replace its required fixed builder-control signing with `PrepareBuilderEndpoint`; never backfill the file. |
| Direct `SignHost` / `SignPlan` on legacy UDS | Do not start a legacy signing listener for this commissioned issuer. Protected issuer state, not a caller-selected config flag, selects the closed profile. |
| `mvm-host-signer` compatibility proxy | It cannot obtain this issuer or bridge to the commissioned channel. No ephemeral replacement key or alternate key path is allowed. |
| Host-agent control or another authorized proxy | No operation may relay a delegated signing request while substituting the proxy's own authority. Builder registration is constructed from the retained session's fixed plan/role, not caller bytes. |
| Owner process filesystem/exec access | Apply a reviewed deny-by-default native owner profile before parsing; allow only the fixed verified child roles, bootstrap handles and invocation state. Deny key/policy stores and unrelated executables, including alternate legacy readers. Supporting children must not regain those rights. |

This proposes an additional authenticated channel and a restricted owner
profile within existing roles. Their review and explicit design approval
precede production wiring; the older generic design-direction approval is
not treated as approval of these concrete new mechanisms.

The owner and key holder are separate processes. The owner parses startup,
retains native children/resources and drives the build. The holder receives
only bounded closed protocol claims, independently checks authority, constructs
signing payloads and retains protected grant/audit state. Neither process sends
private keys to the other. No request to run a program is delegated to the
signer helper.

## Original-owner custody and local inputs

Before the first child effect:

1. Restage through `FrozenInputs` at the approved tree digest. Independently
   check actual selected bytes, canonical request, policy and verified
   builder/kernel/runtime identities; retain the staging and all read leases.
2. Consume the delegation reservation and durably establish operation/resource
   quarantine. Index it by both logical resource and actual held image identity,
   so a different VM name or replacement pathname cannot bypass exclusion.
3. Put the Nix-store image lock, input/output transport, staged job and endpoint
   custody in one owning aggregate. Startup failures retain that aggregate,
   rather than formatting a typed uncertain error into a string.
4. Spawn the endpoint with `spawn_network_endpoint_owned`, then create the
   original HVF child through a distinct builder-only validator. Do not weaken
   `require_cold_config` or erase the native owner behind generic `VmmDriver`.

### Sealed consumed-input object

`FrozenInputs` alone is not immutable and is not the consumption capability.
The trusted commissioning preparation uses the existing staging/packing rules
to make the exact job/input transport in a private temporary file. For this
first mode, reject external symlinks, special files and any source filtering
that changes the approved tree; do not widen the source allowlist.

After packing, flush and synchronize the complete transport. Open a separate
read-only descriptor, close every writable description, unlink the temporary
name and retain only the read-only description plus its measured size/digest
and canonical tree/job manifest. Finish this before spawning any child that
could inherit a writable alias. The provider independently hashes the actual
read-only object against the commissioned measurements. A descriptor number
or a claim that a path was frozen is not verification.

The proposed internal `AdmittedBuilderTransport` owns this object and its
read leases; it has no public path-based constructor. The original VMM receives
that same object through the fixed bootstrap descriptor allowlist and attaches
it read-only. It does not rebuild the input disk from `FrozenInputs::path()`
after admission. No writable copy is released to the owner, endpoint or guest.
Any transport regeneration requires new measurement/admission.

This selects macOS anonymous, unlinked read-only file custody, not Linux
`memfd` sealing. Native qualification must prove that received handles cannot
be reopened with write access through `/dev/fd`, resurrected by a pathname or
modified through an inherited alias. If those checks fail, stop for a different
custody mechanism; before/after rehash alone is not an acceptable substitute.
The separately admitted kernel/runtime and local-built health files retain
their own fixed-role verified read handles.

Only the approved canonical Flake job is accepted. Diagnostic mode also binds
the expected revision and existing actual-graph/input-observation checks.
There is no shell-job, Raw, Stage0, Install or implicit-bootstrap fallback.
Pre-resolution input is not an invented root lock or root narHash: resolve and
validate the actual graph inside the qualified builder, using the approved
input rules.

The guest completion adapter must bind the existing authenticated builder
transport/session to job identity, actual consumed inputs, completion and a
storage-flush barrier. An output file, result sidecar, console halt, EOF or
observed `Stopped` does not mint that barrier.

Do not read/extract the writable output disk until authenticated guest flush,
original-generation native finalization and original writer lifetime exit are
confirmed. This writer-stop gate is not yet successful invocation completion.
Confirm endpoint shutdown, then copy, validate and durably finalize the bounded
output set, then close canonical audit and commit the provider's terminal
result. Only that whole sequence permits successful invocation completion and
quarantine retirement. Retain separate build, flush, stop, endpoint, output and
audit errors; useful bytes never turn failed cleanup into success.

Locally built health-boot inputs need a sibling internal admission route bound
to that build's admitted operation, verified output bytes and intended health
invocation. It must not call an unchecked expectations constructor, claim a
publisher signature or synthesize a registry-pack identity. Source design and
tests for that route are prerequisites to enabling the full builder/health
composition; later health/signing/publication powers are not implicit in the
first build grant.

Preserve the final maintainer decision in the cold-owner contract: summed
vCPU CPU time and the existing guest-memory ceiling, not the superseded hard
macOS memory/thread/process envelope. Use the grant's approved finite builder
profile; this packet approves no new numeric native profile. The existing
builder wait bound is not increased. Owner death is absorbing quarantine,
with no additional owner-death containment requirement.

## Failure, revocation and durability rules

| Event | Required outcome |
| --- | --- |
| Reserve response lost | Observe the same authenticated operation. Never reserve again or infer absence means no effect. |
| Expiry/revocation before durable birth authorization | `CommitBuilderBirth` refuses. The consumed reservation stays spent; no endpoint/VMM creation is authorized. |
| Expiry/revocation after durable birth authorization | Record cancellation; no additional dispatch or renewed admission. The owner serializes activation versus cancellation locally. An already linearized birth may still occur and must be stopped through original custody; remote revocation is not an atomic undo of OS process creation. |
| Frontend disconnect | Record cancellation through the reserved control path, independently of output backpressure. Retain custody. |
| Holder unavailable | No local-key or legacy signing fallback. Preserve uncertainty, leases and quarantine; timeout does not prove no effect. |
| Owner death or holder restart | No owner/session resurrection, old-VM adoption, operation replay or quarantine clearing. Recovery observations cannot authorize cleanup. |
| Partial write, full disk or failed fsync | Do not acknowledge reservation, result durability or quarantine retirement. Retain evidence and refuse reuse. |
| Any writer-stop proof absent | No output-disk extraction. Retain the writable resources and uncertainty. |
| Output valid but any later completion condition absent | No export-success, successful audit closure, health authorization or quarantine retirement. |

Only the original live owner, after the full compound terminal result and
provider/audit durability, may retire the matching resource quarantine. Commit
the terminal replacement decision before allowing reuse; deleting a marker or
receiving a result ACK is not retirement.

The grant's last-birth field means last **birth-authorization** time. It is not
a claim that the kernel's later process creation is atomic with a remote clock
or revocation write. Endpoint and VMM each have a separate consumed allowance
and finite activation deadline. Recheck policy for the VMM allowance even if
the endpoint already exists; a revoked operation stops that endpoint instead
of authorizing the VMM. The owner checks each retained allowance's deadline
immediately before effects and serializes that consumption with cancellation.
Revocation after commitment cannot undo an already linearized effect, but
cannot authorize an uncommitted role or extend its deadline. The original
retained session keeps its bounded stop/failure/terminal-drain rights after
grant expiry, not another birth, generation or unbounded cleanup.

## Implementation boundaries and review gates

This is one composition, delivered in dependency order, not independent
positive facades:

| Boundary | Source ownership and exit condition |
| --- | --- |
| Native provisioning/isolation | Existing caller-custody and signer-helper owners implement protected commissioning, code/peer checks and legacy-route exclusion. First prove native access controls against a same-UID owner/proxy; a synthetic unit pass is not native qualification. Failure keeps the profile disabled. |
| Provider admission and durability | `mvm-hostd::audit_signer` owns typed closed operations, current protected policy, reservation/revocation serialization and canonical audit. `mvm-contract` carries bounded DTOs only. Test durable crash boundaries before signing or birth. |
| Input admission | `mvm-build::pipeline::frozen` remains the staging source of truth; trusted admission independently binds actual inputs. `mvm-core`/`mvm-hostd` own a distinct admitted local-build health identity without widening registry authority. |
| Native owner | `mvm-client` owns the thin process-host/library lifecycle; `mvm-runtime::builder_runner` owns aggregate builder resources; `mvm-backends::driver::hvf` owns the separate builder validator and retained original child. |
| Completion | Builder guest/transport owners add the session-bound flush adapter; native proof constructors remain in `mvm-vmm`. Output finalization and audit close cannot precede it. |

The named delivery owner coordinates these source reservations and resolves
review findings. This table identifies responsibilities, not an assertion that
other owners have accepted new assignments.

Required adversarial cases:

- Wrong full enrollment, same key/wrong installation, tenant, mode, operation,
  plan, actual inputs, policy revision, owner incarnation or native generation.
- A canonical but unauthorized plan; fresh possession without a grant; an
  owner-writable/replaced grant store; stale protected epoch or policy rollback.
- Same-UID wrong process, forwarded connection/proof, wrong released code
  requirement, and direct/relayed legacy signing or raw-key access.
- Concurrent reserve/revoke/replace, lost response, duplicate requests,
  sequence wrap, expiry before/after birth and holder restart.
- Crash before/after durable reservation, endpoint/VMM birth, guest flush,
  output finalization, audit closure and quarantine retirement.
- Timeout while the guest may write; failed child wait followed by later zero
  exit; each missing terminal half; output overflow and blocked result reader.
- A quarantined store reused under a different name, image deletion or
  replacement, automatic restart, and ACK attempting to release resources.
- Unsupported native custody and denied commissioning: no fallback and no
  positive factory, not skipped evidence.

The implementation-ready review must resolve any unspecified authority edge
before code enables it. Native-custody feasibility is the first bounded
implementation experiment: accept the mechanism only if the existing key,
protected state and closed profile survive the negative cases above without
new credentials, elevation or a general signer service. Otherwise return the
specific mechanism failure for an explicit decision, not a weaker default.

Design review does not prove implementation, native qualification, a genuine
signed release, independent artifact reproduction or PS06 consumer acceptance.
These remain separate recorded gates. No activation is authorized here.

[ownership]: https://github.com/tinylabscom/mvm/issues/3716#issuecomment-6668167338
[delivery]: https://github.com/tinylabscom/mvm/issues/4764#issuecomment-6503894291
[direction]: https://github.com/tinylabscom/mvm/issues/4839#issuecomment-6505157542
[ps06]: https://github.com/tinylabscom/mvm/issues/3716
[hvf-issue]: https://github.com/tinylabscom/mvm/issues/4655

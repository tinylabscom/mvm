# PS06 canonical-builder authority

Status: **Blocked architecture decision packet; not an implementation-ready
positive-path contract, installed delegation or enabled owner factory.**
Native qualification remains separate from design review.

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
Security-scope decision: an attacker-controlled, unconfined same-UID frontend
remains in scope (option B). Independently enforced custody must protect the
issuer identity, mutable state and writable resources. No particular mechanism
or new privilege is approved by that choice.

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

### Custody evidence and supported threat model

The issuer is the existing Ed25519 host key currently loaded from
`mvm_keys_dir()/host-signer.ed25519`, not the enrolled caller key and not a
new key pair. It is currently a software file, not an already protected native
identity. Importing its bytes, retiring readable copies and adapting existing
readers require separate explicit authorization; none is implied here.

**Reject generic-password trusted-read ACLs as mutable-state integrity.**
Authorized synthetic probes on macOS 27.0.1 used an explicit temporary Keychain
and a `SecAccessCreate` trusted-application requirement. A different ad-hoc
signed same-UID program could not read the item (`-25293`), but legacy update
and delete returned success. With the correctly scoped `SecItemUpdate`
`kSecMatchSearchList`, both trusted and untrusted updates returned success.
Trusted effect readback confirmed the synthetic bytes changed from 17 to 51
under the trusted control, then to 68 under the untrusted update; after the
untrusted deletion, trusted lookup returned `-25300`. Changing the state API
does not remove the legacy mutation path.

Legacy ACL replacement timed out after 25 seconds and its owned process was
killed; a modern ACL-change attempt with UI failure requested returned `-128`.
Neither result proves resistance to all ACL overrides or private-key
extraction. The enumerated search lists and available domain defaults were
unchanged and temporary Keychains were deleted. These are bounded synthetic
observations, not macOS 26/HVF qualification or authorization to migrate a key.

The adversary includes arbitrary code in an untrusted same-UID owner/frontend
or its proxies: file modification, old protocol records, disconnect/restart,
holder termination and native item update, deletion, replacement or ACL
changes. An unconfined instance of such a role remains in scope. Do not assume
it cooperates with library locks or a sandbox applied to a different process.

The cold-owner contract keeps the host and its administrator trusted; it does
not claim universal defense against unrelated unconfined host malware.
That is distinct from assuming an untrusted frontend is trusted host software
merely because it runs unconfined. Any program the attacker role can launch,
modify or proxy through is part of that role's attack surface. Administrator
backup restoration is outside the claimed antirollback boundary. Holder code,
bootstrap provenance, memory and expected identity need independent protection
against the stated roles. A pathname, `0600`, same UID, requester-supplied code
hash or singleton exclusion supplies none. Absent an enforced boundary, the
positive profile stays disabled.

### Issuer integrity and independent expected identity

Before any issuer operation under either custody option, derive its public
key and compare all 32 bytes with an independently expected host public
identity. Missing, ambiguous, substituted or mismatching material refuses;
never enroll the retrieved key as the new expectation or recreate a missing
key. A prospective native item may hold the same software Ed25519 bytes, but
that alone makes it neither non-extractable nor exclusively held.

For the native-item option, unexpected ACL changes refuse, and neither a
software file nor another item/legacy proxy is a fallback. For the confined
software option below, the one designated provider-owned key file may remain;
every attacker role must be denied that file, alternate copies and all legacy
signing ingress. Native import and native ACL guarantees are not prerequisites
of an option that does not use native storage.

The required source of trust is the trusted host administrator, independently
of the delegated requester, using an existing independently authenticated
deployment path with requester-nonwritable bootstrap custody to the verified
holder. The expectation cannot come from the commissioning candidate, adjacent
owner-writable public-key file, item attributes or a self-signature made by
the retrieved key. This packet has identified neither such a protected path
nor its independently recorded host-specific public identity. Identifying and
verifying both is a blocking design decision, not a new CLI field or permission
inferred from operator authentication.

Pinning detects replacement with a different private key; it does not stop an
attacker extracting the expected key and signing elsewhere or replacing it
with the same bytes. The starting trust assumption is that the existing issuer
has not already been extracted by an attacker. Neither migration nor a new
profile recalls a previously extracted copy. If that assumption cannot be
accepted without rotation, refuse: generating or rotating an issuer is outside
this mode.

The native-item option must retire attacker-readable software copies, adapt
its readers and independently exclude unauthorized read, export and ACL
replacement. The confined software option may retain the designated protected
provider copy and trusted host administration, but must deny every attacker
role direct or proxy access. Neither option permits a legacy signing bypass.
No Secure Enclave Ed25519 support or already entitled native access group is
assumed.

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

Only after confirmation and resolution of the custody/resource decisions below
may the holder establish the selected custody option, install the exact
current-epoch grant and acknowledge installation. Native-item custody additionally
requires explicitly approved existing-key import/retirement; confined software
custody retains only its designated protected provider copy. Those custody
transitions and grant installation have distinct receipts; failure cannot
generate a replacement key or activate a partial grant. Native authorization
authenticates the operator; the fixed candidate digest binds the exact action
that operator approved. Neither establishes the issuer pin or resource isolation.

The first implementation is macOS/HVF only. Fresh commissioning is mandatory
after **every** holder restart, even a clean shutdown. Operator approval never
reauthorizes an old epoch's writable resource, clears quarantine, restores a
session or overrides a failed custody check. There is no unattended recovery
or commissioning fallback.

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

### Authenticated epoch state: evaluated candidate, not a complete model

The concrete volatile-authority candidate below avoids trusting native-item
mutability for policy/replay integrity. It is **not selected as a complete
restart model or sufficient to enable a positive factory**: the independent
issuer and resource boundaries below are missing. It presupposes the
host-global exclusive holder lease, acquired before authority access and held
through retirement. Its singleton property excludes competing holders; it
authenticates neither callers nor stored state.

Permit one commissioned operation per holder incarnation. Before commissioning,
generate an unpredictable 256-bit epoch and independent 256-bit HMAC-SHA-256
key with the OS CSPRNG. Keep both, the full current state and its high-water
revision solely in protected holder memory; never export, persist, inherit or
derive the MAC key from the readable record or issuer. This ephemeral
symmetric integrity secret is not a new enrolled or signing identity. Memory
isolation and verified holder bootstrap are prerequisites, not consequences
of using HMAC.

Use one at-most-64-KiB canonical typed record containing format/domain, epoch,
independently pinned issuer identity, policy revision, distinct grant and
operation IDs, grant, reservation, both role-birth consumptions, revocation,
resource identities, quarantine and terminal decisions, and state revision.
The MAC covers the domain-separated complete encoding and its length; reject
noncanonical encodings, unknown fields, duplicates, overflow and oversize.
The persisted record, including a Keychain item if used, is attacker-mutable
evidence, never the source from which active authority is reconstructed.

Serialize every transition in the holder. Validate it against the retained
state, irreversibly consume/revoke/quarantine in memory, advance the checked
revision, authenticate and persist the complete replacement, then require
exact-byte readback before acknowledging or releasing its corresponding
effect. Retain the expected record bytes as well as the high-water revision:
an old record at the same revision cannot substitute another state. Each
authority transition checks the retained current head; an old signature or a
successful item lookup never suffices. Any missing, changed, invalid-MAC,
wrong-epoch or stale record, or failed write/readback, latches refusal for
further positive effects in that incarnation. Do not reload, decrement,
retry an uncertain birth, or roll back revocation. Preserve only existing
original-custody stop/accounting obligations.

An external write after readback cannot create authority because only retained
state authorizes effects. Readback is not proof that a mutable native item
cannot later be deleted or proof of durable quarantine after a crash. Native
item update alone supplies no claimed filesystem synchronization guarantee.
The durable reservation/birth/terminal rules elsewhere in this packet remain
requirements; this algorithm does not certify a persistence implementation.

Every restart destroys the old epoch/MAC key and begins with no active grant,
session, reconnect right or admissible writable resource. Never recover those
from disk, even from a valid issuer signature or apparently terminal record.
Fresh independent commissioning creates only a new operation with new
resources. Absent/corrupt/restored records cannot mean "unused" or "safe".
Loss of the quarantine ledger must therefore be harmless to exclusion:
**all prior-epoch writable resources remain forever inadmissible**, including
ones whose existence or terminal state cannot be reconstructed. This gives
up cross-restart writable-store cache reuse, not the existing one-use,
revocation or absorbing-quarantine rules. It adds no owner-death containment.

Replacing a grant first commits revocation of its predecessor under this
transition rule. It cannot reset either consumed birth, clear quarantine or
extend an invocation. After uncertain birth, the one-operation incarnation
cannot commission a replacement; a new incarnation still cannot use any old
writable resource. Only the original live owner can supply the compound
completion evidence for a terminal transition; an ACK is not retirement.

### Resource interlocks and the remaining design decision

Epoch authentication prevents forged policy and rollback only while the
holder's memory is protected. It does not prevent resource reuse. Before any
positive path, one independently enforced custody boundary must cover:

- Creation: actual fresh writable storage, with no prior writable contents or
  aliases; register its actual held identity and operation before any child
  effect. `create_new`, a new inode or a random directory name alone is not
  protection against a same-UID writer.
- Consumption and mutation: every attach, open/reopen, writable descriptor or
  mapping, clone/copy/restore and child handoff must be mediated by that
  boundary. Bind actual objects, not supplied filenames. Deny external direct
  writes and copied old stores, not just a second cooperative provider call.
- Names and lifetime: rename, hardlink, unlink, replacement, truncation and
  deletion cannot escape quarantine or make a held object newly admissible.
  No alternate name, VM name, volume or lost record resets its provenance.
- Restart and retirement: without recovering any old grant or negative ledger,
  admit only resources freshly created inside the new protected boundary.
  Old objects, including still-writing orphaned objects, stay inadmissible
  through every attach, cleanup and cache path. Terminal retirement requires
  original-owner compound evidence and durable commit, never marker deletion.

No such writable-resource interlock is established by the current source or
the synthetic Keychain tests. A sandbox on the verified owner alone does not
restrict an arbitrary unsandboxed same-UID frontend. A held descriptor or
advisory lock does not deny that frontend direct access to named writable
images. Fresh commissioning plus HMAC therefore cannot presently meet the
cross-restart quarantine contract; do not adopt it as a complete solution.

### Alternative: mandatory role confinement on a trusted host

A concrete alternative OS boundary is macOS kernel Seatbelt enforcement:
install a fixed deny-default profile with the public `sandbox_init` entry
point before untrusted parsing in every untrusted frontend, owner and supporting
child role. The parameterized SPI is not selected: it was not declared by the
probe's public SDK header. The candidate uses a fixed trusted template, with
bounded validation/escaping and trusted canonicalization of bootstrap-derived
paths; the request cannot supply profile text or permission-bearing paths.
The probe checked a character allowlist and received canonical paths from its
trusted parent; it did not prove production path canonicalization or coverage.
Installation failure refuses before authority access. Verified
bootstrap controls launch/loading, installs the role profile and retains the
exact process lifetime; the holder admits only those bootstrap-bound
processes. Matching a signed executable that somebody launched unconfined
cannot satisfy that admission rule. Child inheritance and the fixed exec
allowlist must prevent leaving the profile; arbitrary helper/proxy execution,
task/debug access and inherited authority-bearing aliases must be excluded.
This names a proposed OS boundary, not an existing or qualified profile.

Under that model, a provider-only ordinary-file journal and expected-issuer
pin namespace can obtain integrity from kernel denial of access by all
attacker roles, not from mode bits. The same profiles must deny direct issuer
file access, Keychain/securityd mutation routes and legacy signing proxies.
Resource profiles must allow only each invocation's admitted objects and deny
old image opens, rename/link/delete/replacement and arbitrary descriptor
handoff; every trusted lifecycle path must consult the provider's journal
before attach, reuse or cleanup. Serialized journal replacement requires
file synchronization, atomic replacement and parent-directory synchronization
before ACK/effect; absent/corrupt/uncertain state refuses, never initializes a
fresh empty ledger. No owner death or missing journal clears quarantine.
The issuer could remain software under this different isolation model; this
does not authorize native import or establish its independent expected pin.

This alternative is not selected. It would require enumerating **all**
untrusted frontend/owner/child/proxy roles and making their preparse confinement
mandatory, leaving unrelated unconfined host software trusted. The selected
threat model retains an attacker-controlled unconfined frontend; Seatbelt on
other roles cannot protect same-UID named provider files from it. Keeping
that file-based model requires a distinct protected principal/provisioning
boundary; otherwise return a different demonstrated custody mechanism for
review. Neither is established here. No complete approved profile, bootstrap
coverage or resource/journal mediation is established either.

**Recommendation: keep the positive profile disabled. Retain the epoch
algorithm only as an incomplete candidate and resolve these authority
decisions before implementing a positive path:**

1. With the unconfined same-UID frontend in scope, identify and qualify an
   independently enforced principal/provisioning and resource boundary.
   File permissions, another role's Seatbelt profile and a different Keychain
   update API do not provide it.
2. Identify the independently recorded expected host public identity and an
   existing protected path delivering it to the verified holder.
3. For native-item custody, decide whether import, software-copy retirement,
   reader adaptation and ACL-override protection are feasible and authorized.
   For confined software custody, identify the designated retained provider
   copy and prove that all attacker roles lack direct/proxy access. A public-key
   comparison alone is not extraction resistance under either option.
4. Identify an existing enforced resource boundary covering every path above
   and, for the epoch candidate, prove old-epoch exclusion without a surviving
   negative ledger. The persistent-journal alternative instead refuses the
   affected managed namespace on lost/corrupt/uncertain journal state; it
   cannot rebuild an empty ledger or infer retirement. Without one of those
   complete boundaries, the stated threat model and no-new-privilege/service
   constraints do not yet have a viable positive mechanism.

An alternative persistent native-authority model is reviewable only with an
actual existing entitled role/provisioning path that denies unauthorized
read, update, delete, replacement and ACL override, independently protects the
expected issuer pin, and enforces resource quarantine across restart. An
assumed access-group entitlement or stronger state API is not that path.
Introducing credentials, services or privileges, narrowing the same-UID
adversary, allowing old-resource reuse, or weakening absorbing quarantine
requires a new explicit scope/authority decision; none is selected here.
Operational commissioning remains separately gated even if those design
decisions are later resolved.

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

Mach send rights may be transferred, but a message sent by a different,
unauthorized process fails the retained immediate-sender binding. An authorized
process relaying attacker-controlled data does not fail merely because a trailer
exists: preventing that proxy path is a separate trusted-code, authority and
confinement obligation. Reconnect authenticates again with a fresh challenge;
it can observe or stop the original retained operation, never create another
birth permit.
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

### Kernel-held single-holder lease

The first-mode proposal permits one delegated builder holder per host, not one
independent holder per caller-selected tenant or path. Before reading issuer
material, reading/modifying authority state or commissioning, acquire a
non-listening IPv4 TCP socket bound to `0.0.0.0:65056`. This tuple is a proposed
fixed implementation constant, not an enabled service or a caller option.
Set and verify `SO_REUSEADDR=0` and `SO_REUSEPORT=0`; do not listen, accept,
connect or send data. This is a kernel exclusion lease, not an RPC endpoint.

The native profile must approve that exact tuple. Any bind failure refuses,
including collision with an unrelated program. Never select another address,
family or port, terminate an occupant, unlink a file, or infer that a PID is
safe to replace. Filesystem and Mach-bootstrap namespace substitutions do not
change this host-global tuple. Privileged modification of the host's kernel
network domain remains outside the trusted-host threat model.

Keep the original socket description until the holder has stopped serving
authority and its retained session has reached terminal or absorbing
quarantine. Set close-on-exec before other threads or children can run; never
export this descriptor or use a public descriptor number as authority.
Inherited aliases may keep the port busy after a process exits: that is
fail-closed unavailability, not permission to force-release it. A new holder
must itself acquire the same tuple and then start a new issuance epoch.

This lease supplies only single-holder exclusion. It supplies neither caller
authentication nor journal integrity, and cannot replace original VMM/endpoint
custody. The actual production tuple, socket options, dual-stack interactions
and inherited-description behavior need native qualification.

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

### Immutable consumed-input object

`FrozenInputs` alone is not immutable and is not the consumption capability.
**Reject the named-file/unlink construction:** another same-UID process can
open a writer before unlink and retain it after the preparer closes its own
writers. Read-only receiver descriptors do not revoke that alias.

The replacement candidate is an anonymous, read-only Mach memory-entry object.
Commissioning still uses the existing canonical staging/packing rules and
rejects external symlinks, special files or filtering that changes the approved
tree. Before admission, the holder copies the bounded raw transport into its
own private anonymous VM allocation. This is a fixed copy/hash operation, not
a Nix/filesystem/archive parser or a general memory service in the key holder.
The source may be mutable; its pathname or sender's “read-only” claim is not
authority. Only the resulting frozen object can be admitted.

The custodian sets `VM_INHERIT_NONE` before filling the allocation and never
creates or exports a writable memory-entry right. Logical length and page
rounding are overflow-checked against an explicit finite input-media budget
before allocation; padding is initialized and never exposes host memory.
After the bounded copy completes, reduce the original mapping's maximum
protection to `VM_PROT_READ`, create only a `VM_PROT_READ` memory-entry right,
and unmap the original writer. No child, mapping or right may retain writable
access. Native hardened-runtime/task-access restrictions must exclude
untrusted debugger/task-port access to this custodian.

The commissioned media digest is computed from the final logical bytes.
The trusted keyless commissioning verifier derives the tree/job manifest from
that frozen object and checks the independently selected source and job
identities; before/after hashes of a different staging pathname are not enough.
The holder independently hashes the same frozen object against the exact
operator-authorized media measurement. Grant confirmation precedes admission
and cannot silently replace those measurements with a caller's new hashes.

The proposed internal `AdmittedBuilderTransport` owns the exact memory-entry
send right, logical size, digest and retained read leases. It has no public
path-based constructor. The holder retains its original right and supplies
that same object through the authenticated original-VMM bootstrap, rather
than accepting an owner-supplied replacement object. Only fixed startup
transfers admit this right; ordinary control messages still reject unexpected
port/descriptor transfers.

The HVF block-input adapter must read directly from the read-only mapping,
respect logical length and reject writes. Do not convert it back to a named
file, accept a writable mapping, rebuild it from `FrozenInputs::path()`, or
accept a private writable copy as the original object. Any regenerated
transport requires new measurement and admission.

This is not an assertion that the current path/FD-based disk adapter consumes
Mach memory entries. That adapter and the exact authenticated bootstrap are
required implementation work. Native qualification must test cross-process
transfer, write/derivation attempts, preparation-time aliases, fork/debug
access, whole-media bounds and actual VMM reads. A one-page primitive pass
does not qualify that composition. The separately admitted kernel/runtime
and local-built health files retain their own fixed-role verified custody.

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

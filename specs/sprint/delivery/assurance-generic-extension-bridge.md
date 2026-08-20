# Assurance sessions: generic optional-extension bridge

Plan: `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md`
(W8.1–W8.5)

MVM now treats assurance executables as independently signed optional
extensions rather than products compiled into MVM. The strict
`mvm.extension-pack/v1` contract declares the extension identity, version,
MVM/protocol range, placement, mountable artifact, entrypoint, typed capability
maximum, resource budgets, revocation identity, and permission delta. Existing
pack provenance, SBOM, trust, expiry, signature, and revocation verification
remain the enclosing authority.

Admission resolves and re-verifies the exact content-addressed pack, intersects
capabilities across publisher maximum, requested operation, host policy,
short-lived grant, and explicit approval, narrows every budget, and writes the
result into the signed execution plan. Launch re-verifies the same pack again,
requires signed `run-extension` and `cancel-extension` guest verbs, checks the
artifact size, and attaches only that admitted filesystem read-only. Ordinary
plans carry no extensions and do no extension discovery.

The guest validates the manifest-selected executable after mounting, holds its
file descriptor to close the validation/use race, and accepts a generic typed
dispatch containing identities plus a bounded input document. There is no
program, argv, environment, host path, socket, destination, policy, observer,
credential, or cleanup field. Payload, output, wall time, step, concurrency,
artifact, CPU, and address-space limits are enforced; the CPU/address-space
path is Linux-only because production guests are Linux.

Assurance dispatch assembles the injected envelope only after signed admission,
claims the plan/idempotency pair durably before execution, stores only a prompt
digest, and treats stdout as an untrusted candidate. The short-lived grant now
binds tools, scopes, expiry, nonce, step and output budgets, and its complete
identity is vouched for by the chain-signed session-open audit record.

Crash recovery is fail-closed and non-reexecuting. The strict durable marker
joins the plan, session, campaign, trial, source, artifact, policy, grant,
extension and payload identities. A duplicate claim that matches exactly is
completed as signed `INCONCLUSIVE / execution_interrupted`, with audit and
receipt references committed back to the marker so later retries return the
same evidence. Malformed, extended or mismatched markers emit nothing.

The typed host broker is also the observer evidence source. After extension
dispatch it snapshots only the probe decisions MVM mediated, rejoins the exact
session/plan/campaign/trial/source identity, cites the exact probe audit
records, and emits a signed `assurance.observer_completed` receipt. Neither the
extension nor its candidate response can set the observation or references.

Cleanup evidence likewise cannot be asserted by the extension or controller.
Assurance admission rejects a target that is not declared disposable. The
cleanup path verifies the exact admitted backend/plan/session, stops that VM,
requires authoritative `Stopped` read-back, and only then signs an
`assurance.cleanup_completed` audit record and receipt. A backend mismatch is
refused before teardown and a teardown request alone produces no evidence.

MVM now also owns a strict parser for the sibling's current
`mvm.security.campaign-request/v1` provider request. It enforces exact keys,
bounds, closed identifiers and digests, then joins each campaign to a separate
operator-authored strict session request by comparing every overlapping fact.
The sibling's missing trial/finding-detail/authority/synthetic fields are never
invented; without that operator document, projection cannot proceed.

The generic optional-extension controller transport is now implemented as the
shared `MVEX` v1 frame contract rather than a Scout-specific protocol. It is
byte-compatible with the sibling codec and bounds the announced payload before
allocation, verifies a SHA-256 payload digest, rejects unknown versions/kinds,
and enforces strictly increasing per-direction sequences. The host stream
adapter handles describe/start/cancel/shutdown and converts a typed handler
refusal into a bounded sanitized error frame. It does not interpret Scout rules
or choose an extension binary. A strict typed
`mvm.security.provider-response/v1` schema is emitted alongside the request.

The bound input now travels through a production `AgentSessionCommand::Prompt`
adapter with fsynced digest-only history. It reconstructs a `Running` request
after crash and re-enters only the durable at-most-once extension dispatcher;
a completed duplicate does not invoke the executor. Prompt and live output
bytes never enter the history. The host finalizer then consumes only typed
observer and confirmed-cleanup evidence, derives the verdict, signs trial
completion, and emits the exact sibling trial-evidence and trial-result shapes.
Missing cleanup is explicitly `INCONCLUSIVE / cleanup_missing`.

Cancellation is now a production-safe part of that bridge rather than a
journal-only state transition. The adapter fsyncs `Canceling` before transport,
then sends a separate identity-only guest request containing the admitted
extension/pack/contract, session/plan/campaign/trial, idempotency, grant, and
nonce identities. It cannot name a process, signal, command, path, destination,
or cleanup scope. The guest resolves only the matching active call, asks the
existing bounded process-group kill ladder to stop it, and acknowledges only
after the active call ends. A cancellation that arrives just before dispatch is
remembered and prevents the matching call from creating a child. The host
records a signed cancellation audit entry and receipt, atomically persists
those references before confirming the journal state, and returns the same
evidence after controller crash without a second transport call. Finalization
accepts the references only after an exact session/campaign/trial/source join.
Focused coverage includes a real child process that ignores TERM and is killed
within the bound, concurrent durable cancellation, pre-dispatch cancellation,
acknowledgement-after-stop, crash recovery, corrupt-marker and
mismatched-identity refusal, unknown wire-field refusal, and signed-plan
refusal when either extension verb is missing.

The controller-to-resident-broker process seam is now closed with a generic
typed-service proxy. Its optional binding is covered by the existing signed VM
registration and leaves ordinary registration bytes unchanged when absent.
The controller retains the authoritative session/evidence handler and audit
signing key behind a bounded host-only UDS; the resident broker checks that the
service and exact capability descriptor were admitted, requires capability
invocation, derives the session identity from the VM registration, and proxies
only that typed request. Direct calls, descriptor/session mismatches, oversized
frames, missing endpoints, controller failures, and unsigned bindings fail
closed. A post-start session-open failure now stops the VM rather than leaving
an admitted workload running with weaker assurance binding.

Terminal controller replay is also fail-closed. Before the admitted campaign
runner is called, the generic controller commits the strict request identity
and payload digest to a private journal. It commits the bounded typed provider
response before returning a `Complete` frame. Matching completed retries get
the same response without another runner call; running, failed, or conflicting
retries are refused. The journal contains neither request bytes nor a runner
diagnostic. The response's `certifying` bit is derived from complete joined
host evidence, including audit and receipt references, and cannot be supplied
by the runner.

This is not yet a demonstrated certifying campaign. Hardware attestation
evidence and the live KVM canary remain open. The
checked-in provider executable now injects the fixed lifecycle runner with a
strict operator-configured booter. It pins and re-verifies the exact signed
pack, workload/kernel digests, backend, policy, authority, budgets, and
destination map before plan admission. Its private config also pins the
existing global MVM home. The sibling launcher retains `env_clear`, restores
only the operator-selected `MVM_HOME`, and MVM refuses any mismatch so provider
boots cannot silently move host ceilings or aggregate charge accounting into a
per-provider ledger. The sibling checkout owns a static Linux guest `scoutd`, a
strict generic pack recipe and SPDX SBOM, and an independent signing producer;
MVM's product-agnostic ext4 materializer and verifier accept the resulting
guest-mountable pack. Its guest entrypoint now imports MVM's canonical
assurance client and contract, validates the bound envelope, selects only
declared destination labels within the admitted step budget, calls only
`campaign_probe.v1`, and returns a verdict-free candidate. MVM validates each
typed observation against the exact invocation before the host observer,
cleanup, and finalizer may use it. This closes the generic guest execution
wiring without claiming a live or certifying campaign. The sibling's framed
campaign request intentionally omits operator-owned trial/idempotency, detailed
finding, authority, canary, and destination-label facts. Those values now use a
separate strict operator-session bundle: the sibling joins it to the Scout
request, transfers it through `OpenSession`, and MVM refuses `Start` until it
has repeated the exact all-campaign join. Neither side invents missing values.

The sibling controller now has an explicit `--trusted-provider-id` pin. It no
longer unconditionally downgrades all framed providers, but a provider's own
`certifying` bit is accepted only when its descriptor identity matches the
operator pin; the evidence evaluator still independently requires identity,
observer, cleanup, receipt, policy and attestation evidence.

The sibling's earlier controller-only manifest remains distinct from the new
signed MVM guest pack. Its starter provider returns an explicit
broker-unavailable response and its fixture provider is non-certifying. The
MVM post-journal format, macOS workspace check/test, all-targets Clippy,
x86_64 Linux cross-target check, BDD required-feature compile, schema-emitter
checks, and the sibling assurance workspace tests pass. The native Linux
builder gate is blocked before test execution:
HVF refuses the six-disk builder layout (`TooManyDisks`, maximum five), while
libkrun reached no guest test process and was stopped after ten minutes without
progress. Embedded guest/host binaries also remain deliberately stale in the
development cache and must be refreshed before a live microVM validation.

The supplied x86_64 KVM/Firecracker lane was subsequently exercised: the
current provider built successfully, the sibling-owned x86_64 `scoutd` pack
was signed and promoted, and a direct MVEX fixture reached real Firecracker
startup. The cached protocol-v0 workload rootfs then failed closed in
`mvm-oci-init` while activating the extension user-volume (`path policy
denied`) before the guest agent started. The sibling planner also currently
uses a policy digest that is not MVM's canonical four-reference digest, so the
trusted sibling command is refused before boot. These are explicit
cross-repository handoff blockers, not a reason to weaken MVM admission.

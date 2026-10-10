# Diagnostic data protection and retention

Backing: preview
Validation: none — this contract defines required behavior, not a claim of complete runtime enforcement.

This contract belongs to [diagnostic confidentiality and retention](https://github.com/tinylabscom/mvm/issues/4184).
The issue owns implementation and verification status. This document defines the
data boundary and the rules implementations must satisfy.

## Trust boundary

Protection is against unintended persistence, disclosure to other local users,
and accidental export under a trusted host. It is not protection from the host
administrator, a compromised host, or a process already holding a decrypted
payload or an open descriptor. Private permissions are not encryption.

Encryption does not hide file sizes, traffic timing, or the existence of a
capture. Removing a file name is not secure erasure of storage blocks, snapshots,
backups, or data still reachable through an open descriptor.

## Classification

Classify fields by their contents, not by a filename or the word "metadata".
Unrecognized fields and free-form strings are sensitive by default.

| Data | Class | Required handling |
|---|---|---|
| Console output, supervisor stderr, exception text and command output | Sensitive diagnostic payload | Retained copies require protected capture; transient plaintext needs an explicit owner and lifetime. |
| Telemetry messages, attributes, span names and user-supplied labels | Sensitive diagnostic payload | Apply the same protection as console payload; a JSON encoding or a byte cap is not a confidentiality boundary. |
| Configuration values, environment values, command arguments and user-selected paths | Sensitive configuration | Do not copy into diagnostic metadata. Capture only when explicitly authorized as protected payload. |
| Fixed status codes, bounded counters, byte counts, timestamps and opaque generated identifiers | Operational metadata | May remain unencrypted in private managed state when the schema explicitly allows them. |
| Ciphertext digests, verification roots, wrapped data keys and opaque recipient identifiers | Integrity and key-envelope metadata | May accompany protected data in private managed state. Never include raw keys or plaintext digests of low-entropy secrets. |
| Audit event kinds and explicitly typed, payload-free verification fields | Audit metadata | Preserve independently of payload retention. An arbitrary audit label is not automatically allowed metadata. |
| Operator-selected decrypted exports | Intentional plaintext disclosure | Require verified decryption and explicit selection of the destination; disclose the export event without putting its payload in the audit record. |

Human-selected machine names and labels are not equivalent to generated opaque
identifiers. A metadata schema that exposes them must explicitly account for
their sensitivity. "May remain unencrypted" does not mean world-readable or
safe to publish.

## Protected capture

Reuse the existing transcript envelope rather than introduce another encryption
format: a per-capture data key, host-key wrapping, encrypted chunks, ciphertext
digests, and a sealed manifest bound to the admitted capture identity.

The capture owner must exist for the entire producer lifetime, including
detached runs. Creating an empty manifest or arming a sink with no producer does
not demonstrate capture. A plaintext console fallback is not an acceptable
substitute when the selected policy requires encrypted persistence.

Loss remains explicit. Queue saturation, storage refusal, eviction and a
reconstructed seal must not produce a manifest that silently claims a complete
recording. Capture must not introduce unbounded producer work or block workload
output while waiting for storage.

A new capture may initialize its required wrapping key through the existing
key-custody facility. Reading, verifying or exporting an existing capture must
load its existing key without creating a replacement. Missing keys, malformed
envelopes, incorrect keys or failed integrity checks refuse decryption; they
never authorize plaintext fallback.

### Cold entrypoint caller-registration prerequisite

An explicitly opted-in cold HVF entrypoint launch can install one immutable
caller registration in its existing supervisor-owned capture owner. The client
uses `EntrypointAdmissionBuilder::producer_identity` with a previously enrolled
public identity and a build enabling `native-caller-identity`. Admission loads
only that exact native-custody pin; it does not enroll, rotate, or select a
plaintext, mock, or generic keyring fallback during launch.

The trusted launcher derives a fresh concrete instance, run, producer, session,
and canonical registration challenge from the actual admitted plan. The cold
startup record carries this fixed expectation separately from the caller's
possession proof. Before publishing startup state or entering the guest, the
supervisor verifies the signed plan against the canonical local host public key,
checks its content identity and validity, and checks the proof against the
unchanged launch expectation. The caller-selected audit signing-key path is not
a trust root. Generic plan signatures and guest verb grants are not producer
registration authority.

The startup configuration remains part of the trusted authorized-launcher
boundary. Putting an expectation beside a proof is not an independent trust
anchor against replacement of both by a compromised launcher. Later producer
input cannot install or replace the owner's caller identity.

One private, create-only `caller-registration.used` slot in the managed VM
directory rejects concurrent consumption and replay across supervisor restart.
It contains only an opaque run identifier and is replay bookkeeping, not an
authorization permit. Failed setup remains spent; recovery requires normal
instance teardown and fresh admission, never deleting the slot to retry the
same launch bytes. The slot is bounded to one per managed instance and is
removed with that instance's ordinary state lifecycle.

Caller registration is currently cold-only. Opted-in standby preparation and
warm claims are refused before changing pool or guest state; no legacy standby
bootstraps a caller key from a supplied signed plan. Opted-out launch defaults
and handoff bytes remain unchanged.

Registration is a prerequisite, not producer ingress, producer readiness,
guest readiness, or evidence of protected entrypoint stdout/stderr capture.
It creates no readiness ACK. Any full startup measurement must begin before
resolution and include admission, native custody, verification, durable replay
bookkeeping, producer readiness, and guest readiness. Registration-only timing
cannot establish that full-readiness target.

## Private creation and replacement

Managed payload files and key material must be created at `0600`; managed
directories must be created at `0700`. Restriction must hold before publication
and before sensitive bytes are written, not after a permissive creation window.

Starting a fresh diagnostic capture replaces the managed file with a private
inode rather than following or modifying an existing symbolic-link target or
another hard link's inode. Failure must not damage the previous destination or
leave an exposed staging file. The caller remains responsible for a trusted
parent directory; safe replacement of the last path component alone does not
establish that trust.

Managed path-following readers reopen a replaced capture from byte zero and do
not replay bytes from the previous inode. A reader that encounters a missing
path may wait for recreation. Existing external descriptors are not revoked by
replacement and must not be described as erased.

## Independent retention dimensions

An admitted retention policy must distinguish these quantities:

- **Byte/chunk budget:** the maximum retained payload window, with a defined
  accounting basis. Plaintext lengths, ciphertext lengths and total on-disk
  allocation are different quantities; the policy must identify which is bounded.
- **Capture duration:** how long a producer may contribute to a capture.
- **At-rest age:** how long persisted payload remains eligible for retention.
  This is measured from an explicit persisted timestamp, not from the last read,
  collector restart, or key lookup.

A byte-bounded ring does not establish an age limit, and a capture-duration
field does not establish at-rest expiry. An implementation must not advertise a
deadline unless a lifecycle owner actually performs or reconciles expiration.
Expiry uses checked time arithmetic and must not delete payload on an invalid
clock reading or arithmetic overflow.

The numerical age policy must be recorded in the authenticated capture before
automatic deletion is enabled; this never retroactively enrolls existing captures.
New protected transcripts record the approved default of 604800 seconds after
terminal sealing, with active generation intervals no longer than 3600 seconds.
A computed integrity root is not terminal sealing. Finalization freezes the
writer; recovery after exclusive ownership is established preserves the original
generation deadline and marks the recovered record incomplete. It must not grant
a fresh retention period at restart.

Supported legacy v6 captures remain retention-ineligible and keep their original
root bytes. Formats v1–v5 are not supported. Reading or restarting never enrolls
existing captures. Operator-selected exports are outside managed retention;
capture cleanup must not traverse arbitrary export paths, backups or unrelated
files.

New workload-output generations can separately bind an aggregate
tenant/VM/workload-output-family budget, measured in retained plaintext envelope
bytes and chunks. The current defaults are 8 MiB and 65536 chunks across active
and retained enrolled generations, not per hourly generation. Unrelated forensic
captures and legacy captures do not join that pool. Early byte-pressure retirement
requires the original signed budget policy and checked accounting from signed
terminal manifests, with a bounded incoming reservation. Its signed reason is
distinct from age expiry. The family owner holds an exclusive lease through
accounting, reservation and durable enqueue; failure to reclaim requires explicit
loss rather than quota overshoot. Metadata and filesystem allocation are not
included in the plaintext payload budget.

The transcript control surface provides explicit one-capture reconciliation and
a callable supervisor maintenance API. Live producer rotation, startup and tick
invocation, reservation ownership, and typed stream-record reading are separate
capture-owner integration responsibilities. This boundary alone does not claim
unattended expiry or activate production capture.

## Audit preservation during cleanup

Payload expiry and audit-evidence retention are separate operations. Cleanup
must not rewrite a sealed manifest to conceal removed payload or present a
retained suffix as a complete run. Keep the immutable verification identity and
an authenticated record of intentional removal so verification can distinguish
expiry from corruption or unaccounted loss.

Audit-segment cleanup preserves the existing seal, continuation and deliberate
prune records and their chain linkage. If the required evidence cannot be
recorded, cleanup must not silently advance the deletion boundary. An expired
payload is not exportable merely because its audit metadata still verifies.

Transcript reconciliation verifies the original seal against the trusted host
audit chain, including rotated audit segments. Before any unlink it durably
records and re-verifies a signed, payload-free retirement event binding the
original capture, root, policy, deadline and reason. Exact existing evidence
permits interrupted cleanup to resume; conflicts, duplicate evidence, invalid
chains and missing payload without retirement authority refuse.

Reconciliation binds the requested tenant and concrete VM instance against the
original host-signed seal, not the workload name or a current `plan.json`.
Retirement attribution is copied from that authenticated historical entry;
deleting or replacing the current VM plan does not change it.

The current verifier still requires original opening/sealing entries in the
verified audit segment set. Legitimate pruning of those entries therefore
refuses recovery and retirement; a standalone signed envelope is not accepted
as a substitute for chain continuity. Audit pruning pins or chain-linked
preservation are a remaining lifecycle dependency, so this surface does not
guarantee unattended cleanup across audit pruning.

Recovered-seal publication uses the original authenticated opening and a staged,
terminal incomplete manifest. A dedicated primary-chain emitter holds the tenant
audit lock across verification, exact-seal lookup and conditional append, then
verifies and syncs the result. Retrying an identical published seal does not
append another one. Read-only seal lookup reports absence only in authenticated
unpruned history; it is not a substitute for atomic publication. The lifecycle
caller must still hold the capture lease and establish producer quiescence or
death. Replicated emitters are refused by this atomic recovery operation rather
than being given an unsupported cross-destination atomicity guarantee.

Cleanup pins a private host-owned capture directory beneath a trusted configured
root, opens descendant components without following links, takes a nonblocking
exclusive lease, and removes only verified single-link ciphertext segments named
by the authenticated manifest. The manifest, original root and key envelope are
unchanged. Cooperating writers hold the same lease. This is not an adversarial
same-user namespace guarantee: hostile host-user processes that ignore the lease,
storage snapshots and open descriptors remain outside this trusted-host boundary.

## Required witnesses

Use synthetic sensitive markers, never real customer data. Exercise protected
persistence, restart, replacement, missing and incorrect keys, explicit export,
byte pressure, age expiry, clock errors and interrupted cleanup. Assert that
protected payload is absent from plaintext managed artifacts and audit labels,
that permitted operational metadata remains usable, and that loss and intentional
removal cannot be mistaken for complete capture. Permission-only tests cannot
stand in for encryption or retention tests.

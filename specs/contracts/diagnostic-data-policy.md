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

## Surface inventory

Every file or store mvm itself writes that holds diagnostic payload, sensitive
configuration or audit metadata, with its class, how it is protected, how long
its plaintext lives and what removes it. "Instance-scoped" means the file lives
in the VM's state directory (`vm_state_dir`, created 0700), is replaced with a
fresh 0600 inode on each boot, and is removed with that directory: when a
transient run ends, or by `mvmctl machine rm`, which keeps the directory only
while a live process still owns it. It is never copied out by managed
retention, so it is transient plaintext with that directory as its owner, not a
retained copy.

| Surface | Class | Protection | Plaintext lifetime and cleanup | Byte bound |
|---|---|---|---|---|
| HVF guest console | Sensitive payload | Protected capture, required; the supervisor config cannot select plaintext | No plaintext file. Payload retired 604800 s after terminal seal; generations at most 3600 s | Workload-output family budget (8 MiB, 65536 chunks) |
| HVF supervisor stderr | Sensitive payload | Discarded (`/dev/null`); payload-free status evidence instead | None written | Not applicable |
| Workload output through the stream plane | Sensitive payload | Encrypted transcript (protected families under the audit root; legacy per-VM `stream/`) | No plaintext file. Protected families follow the retention above; legacy captures are retention-ineligible and go with the VM state | Family budget, or the legacy capture's own bounds |
| Firecracker, libkrun and QEMU `console.log` | Sensitive payload | Private file (0600, fresh inode, link at the path replaced) | Instance-scoped | None: bounded only by what the guest writes to its serial console. Workload stdout and stderr do not go there |
| `firecracker.log`, `qemu.log`, `supervisor.stderr.log`, `network-endpoint.stderr.log`, `gpu-endpoint.log` | Sensitive payload | Private file, as above | Instance-scoped | None |
| `supervisor.lifecycle.log` (libkrun) | Sensitive payload (free-form detail) | Private append: created 0600, refuses a link, a second hard link or another user's file | Instance-scoped | None; one line per lifecycle stage |
| `supervisor-config.json`, `substitution-env.json`, the QEMU bridge spec | Sensitive configuration | Private file, written whole | Instance-scoped | Fixed by schema |
| HVF RAM image written at capture | Sensitive payload (guest memory) | Private file, fresh inode | Staging and checkpoint rules of the snapshot and checkpoint policies, not this one | Guest memory size |
| Builder VM console, supervisor stdout/stderr and command logs | Sensitive payload | The libkrun builder's command, supervisor and config files are private files; builder console files are created by the VMM inside the 0700 builder state directory and are not individually narrowed | Builder state directory; replaced each boot | None |
| `MVM_HVF_AGENT_DEBUG` trace | Sensitive payload | Private append at the operator-named path; nothing written when unset | Operator-selected: outside managed retention, never cleaned up by mvm | None |
| Guest telemetry records | Sensitive payload | Retained only sealed under the transcript key-custody facility; a plaintext telemetry store is not permitted | Per the collector's sealed store | Collector bounds |
| Audit chain segments, seals and retirement records | Audit metadata | Chain-signed, private managed state | Independent of payload; pinned while enrolled capture metadata remains | Segment rotation; no deletion except deliberate prune |
| Operator exports (`machine logs` export, transcript export) | Intentional plaintext disclosure | Verified decryption, explicit destination | Operator-owned; outside managed retention | Not applicable |
| PID files, exit codes, timing and quota records | Operational metadata | Private state directory | Instance-scoped | Fixed by schema |

`xtask check-private-diagnostic-files` keeps the VMM, backend, supervisor and
builder-log writers on the private-creation helpers. An unbounded
instance-scoped file is a stated limit, not a retention policy: a detached
instance that runs for months keeps its whole serial console until it is
removed.

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
public identity and a macOS build enabling `native-caller-identity`. Other
platforms and feature-disabled builds refuse this opt-in before admission or
VM-state effects; they do not fall back to an unregistered launch. This bounded
prerequisite does not implement cross-platform native custody. Admission loads
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

A bounded private consumed-registration ledger lives outside runtime VM state,
under the configured MVM home's `caller-registration` directory. It stores
only purpose-domain-separated commitments to the canonical challenge and signed
expiry times, not keys or raw plans. Exclusive directory locking, bounded reads,
and a synced atomic replacement complete before startup status, boot-input reads,
or owner activation. The replay directory's canonical ancestor chain is synced
as well, so first-use creation does not rely only on syncing files inside an
unanchored directory. At 4096
unexpired entries or 1 MiB the ledger refuses new consumption rather than evicting
an unexpired record. Expiry pruning and a persistent clock high-water advance
are one transaction; a backward clock refuses instead of reviving pruned records.
Corrupt storage, or missing storage after recorded initialization, is never
silently reset.

A non-cloneable consumed-launch capability is passed to the capture owner;
the owner cannot substitute verification-only state or consume it a second time.
Missing kernel or initramfs failures after successful consumption remain spent
even though no capture owner or guest has yet started.
Owner installation rechecks both the signed plan window and the exact caller
registration deadline after setup, without rounding that deadline up. A clock
earlier than the observed consumption time refuses activation; consumption never
extends validity.

A private, create-only `caller-registration.used` slot in each managed VM
directory separately guards immutable installation in that instance. Both
mechanisms are replay bookkeeping, not authorization permits. Failed setup may
remain spent; recovery requires repairing the underlying failure, normal instance
teardown, and fresh admission. Ordinary teardown removes the per-instance slot
but not the durable ledger, so the old still-valid registration remains refused
while a fresh registration can be admitted. Never erase replay bookkeeping to
retry the same launch bytes.

Caller registration is currently cold-only. Opted-in standby preparation and
warm claims are refused before changing pool or guest state, and restoring a
checkpoint that carries caller registration is refused before rewriting child
configuration or spawning a supervisor. Snapshot creation alone does not make
such a checkpoint restorable; it requires a fresh cold launch. No legacy standby
bootstraps a caller key from a supplied signed plan. Opted-out launch defaults,
restore behavior, and handoff bytes remain unchanged.

Registration is a prerequisite, not producer ingress, producer readiness,
guest readiness, or evidence of protected entrypoint stdout/stderr capture.
It creates no readiness ACK. Any full startup measurement must begin before
resolution and include admission, native custody, verification, durable replay
bookkeeping, producer readiness, and guest readiness. Registration-only timing
cannot establish that full-readiness target.

The real cold-launch witness and startup-performance measurement are blocked by
[lifetime-safe HVF stop and fail-closed cleanup](https://github.com/tinylabscom/mvm/issues/4276).
The current driver drops its owned supervisor child after readiness, while the
public stop path signals a numeric PID. Best-effort transient cleanup may remove
process evidence after a failed stop. The ignored caller-registration witness
therefore returns `Unsupported` before launch, and its cleanup companion refuses
to erase an existing ownership record without proof of quiescence. These refusals
are not native-boot passes. Scoped admission/owner/replay tests and separate
native-custody tests do not establish a full native launch or readiness latency.

## Private creation and replacement

### Opt-in launch failure observations

`MVM_FAILURE_DIAGNOSTICS=1` enables payload-free `MVM_FAILURE_V1 ` records on
the existing child stderr channel. Each newline-terminated JSON record has
exactly `phase`, `category`, `stage`, and `exit_code`. The first three fields
are closed enums; `exit_code` is an integer or explicit `null` when not
observed. No error text, builder detail, console payload, paths, names,
arguments, environment values, identifiers, or digests enter this schema.

Phases are `transient_boot`, `transient_command`, `builder_job`, and
`hvf_readiness`. Categories are `unknown`, `internal`, `invalid_request`,
`unsupported`, `version`, `fetch`, `nix_build`, `nix_eval`, `timeout`, and
`output_contract`. Stages are `absent`, `unknown`, `sign_check`,
`signing_lock`, `signing`, `reexec`, `config_read`, `config_parse`,
`status_publish`, `startup_inputs`, `capture_policy`, `capture_setup`,
`pid_publish`, and `pid_published`.

The documented-launch conformance command runner opts in when
`MVM_E2E_FAILURE_MANIFEST` names an operator-selected output file in an existing
trusted parent directory. It scans at most the first 65536 stderr bytes,
rejects malformed records, unknown fields/enums and records exceeding 512
bytes, and retains at most 16 records per command, 128 commands, and 262144
serialized manifest bytes. Saturating counters explicitly report rejected,
oversize, dropped records, skipped bytes, and dropped commands. Unscanned
bytes are not claimed to contain zero records.

The manifest correlates commands using harness-local scenario and command
ordinals, not source job names or identifiers. Each command reports success
and exit (or `null` on spawn failure), plus `collected`, `absent`, or
`unreadable` status. `absent` means no accepted record, not successful capture.
The aggregate has `schema_version: 1` and a closed lifecycle `state`:
`not_started`, `in_progress`, `complete`, `loss`, or `unreadable`. Before any
suite build or bootstrap, the script creates a fresh `0600` destination using
create-new semantics. An existing file or symlink is refused, never reused.
The empty `not_started` record explicitly covers failure before the first
scenario. A bounded no-follow read verifies the initializer's inode handoff
and exact empty schema; file existence alone does not authorize collection.
Direct conformance invocations also require a fresh destination.

Snapshots remain `in_progress` until the runner explicitly finalizes after its
scenario loop, before normal test-failure exits. Interruption or an earlier
runner failure leaves a partial state. Finalization records `loss` for counted
rejections, truncation or dropped observations, and `unreadable` for command
capture or any prior persistence failure. Persistence failure is sticky even
if later writes succeed. A failed write attempts one best-effort `unreadable`
repair without replacing the original failure. Atomic replacement can rename
before its parent-directory sync fails; if repair also fails, even terminal
source bytes may remain. Source `complete` is only a reported collector-loop
observation, never durable-finalization evidence or a passing suite.

Initialization reports fixed `initialized`, `refused`, or `unreadable` status;
the initializer returns 2 for refusal and 3 for I/O failure. On failure the
script disables diagnostic collection without changing test or cleanup outcomes.
The workflow passes the original suite initialization output as
`MVM_E2E_FAILURE_AUTHORIZATION` to `scripts/e2e-failure-manifest.py --export`,
in one always-run step before the existing upload. It must exactly match
`MVM_E2E_FAILURE_MANIFEST`; file existence is never authorization. The exporter
does not require the initializer's inode: legitimate Rust atomic replacements
are expected. It opens the selected source with no-follow/nonblocking flags,
requires a regular current-owner `0600` single-link file by `fstat`, and reads
at most 262145 bytes, rejecting anything over 262144. UTF-8 decoding, duplicate
key rejection and full closed-schema validation precede canonical
reserialization. Unknown or missing fields, unknown enums, booleans where
integers are required, non-integer numbers and out-of-range values are refused.
All counters/ordinals are unsigned 32-bit; exits are signed 32-bit or explicit
null, and command success is a boolean or explicit null. The same 128-command,
16-record and 512-byte canonical-record limits apply.

The separately exported schema retains these bounded observations but maps
source `complete` to `observed` and `loss` to `observed_loss`; `not_started`,
`in_progress`, and `unreadable` remain explicit. Every export has
`finalization: "unverified"`. Neither a terminal state nor a command success
field establishes suite success, authenticity, durable finalization, or complete
coverage. Missing authorization or a missing source produces a fresh empty
`absent` diagnostic; invalid/refused source data produces a fresh empty
`unreadable` diagnostic. Neither exports raw source bytes or error details.
No completion receipt or acknowledgment protocol is used.

`MVM_E2E_FAILURE_EXPORT` names the exact run/attempt/shard-isolated snapshot in
`RUNNER_TEMP`, created exclusively as a new `0600` file. Output is canonical
sorted compact JSON, bounded to 262144 bytes including the additional export
field. Only successful fresh snapshot writes publish the export step's path
output; upload uses only that output for this diagnostic, never the mutable
source and never a static fallback. Export failure does not alter suite or
cleanup outcomes. Existing legacy suite/VM log uploads are unchanged: the
combined artifact is **not** claimed to be payload-free or sanitized.

Path outputs reject CR/LF and non-UTF-8 destinations. Python/Rust schema-parity
regressions cover fields, integer types, all record enums, and limits. Existing
parent directories must be trusted; same-user hostile mutation of those
directories is outside this boundary. Exclusive snapshot creation refuses
stale snapshots rather than reusing them.

Collection and private atomic manifest replacement happen before returning
to scenario cleanup. Non-regular destinations, including symlinks, are
refused; failures report only the fixed `failure-manifest: unreadable` marker.
The collector never traverses runtime state or exports raw artifacts.

These records are unauthenticated observations: a child can spoof them.
They never gate acceptance or prove custody, readiness, or protected capture.
JSON, allowlisting, and private permissions do not establish confidentiality
or permission to publish. Select only this manifest for a separately reviewed
export; never upload stderr, runtime directories, or an entire home.

Emission uses one best-effort blocking stderr write, without retrying or
replacing the original error. A small record is **not** a nonblocking or
latency guarantee. The existing `command.output()` stdout/stderr buffering
remains unbounded and is **not fixed** by this collector. Lost/partial source
writes cannot be counted reliably; absence is not completeness. Interactive
PTY commands and other harness command paths are not covered.

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
as a substitute for chain continuity. Audit prefix pruning must retain original
opening, seal and retirement evidence for enrolled captures while verification
metadata remains, including after ciphertext retirement. Audit segments may
therefore remain indefinitely. A retirement event is pre-unlink intent, not
proof that unlink completed; pruning cannot infer release from that event.
This policy does not authorize metadata disposal or replacement proof sidecars.

Prune admission runs inside the tenant audit-chain transaction and holds
nonblocking managed-family/capture leases through the signed prune, unlink and
directory sync. Busy inventory is a retryable operational refusal, not proof of
an evidence pin. An unavailable family whose tenant cannot yet be authenticated
can conservatively block pruning for another tenant. No inventory scan is added
to VM startup or ordinary signing.

Inventory is bounded to managed workload-output families and the managed
forensic transcript root, without following descendant symlinks. Enrollment
comes from the signed manifest-root commitment, never unsigned routing or local
arm records. Known authenticated legacy v6 captures are not enrolled or pinned.
Missing or corrupt authority refuses admission; a signed seal without retained
metadata cannot establish legacy status and cannot be pruned as unenrolled.
After a verified legacy seal is legitimately pruned, its retained manifest
alone cannot authenticate that legacy status on a later prune attempt. That
attempt also refuses for missing authority; it does not enroll the capture.
Original signed openings remain pinned even when metadata is unavailable.
New opening publication shares the prune lock and can only append to the
surviving chain. Unsealed forensic candidates without signed opening authority
conservatively refuse pruning rather than acquiring authority retroactively.

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

## Acceptance evidence and its limits

Reconciliation of the six criteria of the parent issue against landed code.
"Witnessed" names a test that exists; every limit is stated rather than implied.

| Criterion | Evidence | Limit |
|---|---|---|
| Classify diagnostics, telemetry, configuration, audit metadata and exports | Classification and surface inventory above; `xtask check-private-diagnostic-files` pins the writers | The inventory is a document, not generated from the code. A new writer outside the gate's scan is not covered. |
| Which payloads need encrypted capture, which metadata may stay visible | Classification table; transcript manifest carries only digests, counts, timestamps and the wrapped key | Firecracker, libkrun and QEMU `console.log` and the other instance-scoped logs are private plaintext, not encrypted. |
| Reuse the encrypted transcript facility | HVF console and workload output use the transcript envelope | Producer integration is per surface; surfaces outside it are not protected capture. |
| Private creation for managed state | Private-creation helpers and the gate above | Builder console files are created by the VMM and are not individually narrowed. Private permissions are not encryption. |
| Byte and time retention separate; audit verification preserved | Independent retention dimensions; `protected_lifetime_is_terminal_bound_and_immutable` witnesses that an expired payload is refused on both export paths and leaves ciphertext and manifest bytes unchanged; `operator_reconcile_expires_only_authorized_payload_and_preserves_evidence` witnesses that reconciliation removes only authorized ciphertext, keeps the manifest, wrapped key and sealed root verifiable, and turns the read refusal from "deadline passed" into "authenticated retirement" | Stopped, never-restarted captures are not physically deleted automatically. Expiry is a read refusal first and a deletion only after reconciliation. |
| Validate with synthetic markers and lifecycle tests | Tests above use synthetic markers and assert the audit log carries none | No end-to-end witness boots a native workload through capture, expiry and reconciliation; the cold-launch witness is blocked as described above. Removing a file is not secure erasure. |

This policy protects against unintended persistence under a trusted host. It
does not describe confidential execution and gives no protection from the host.

## Required witnesses

Use synthetic sensitive markers, never real customer data. Exercise protected
persistence, restart, replacement, missing and incorrect keys, explicit export,
byte pressure, age expiry, clock errors and interrupted cleanup. Assert that
protected payload is absent from plaintext managed artifacts and audit labels,
that permitted operational metadata remains usable, and that loss and intentional
removal cannot be mistaken for complete capture. Permission-only tests cannot
stand in for encryption or retention tests.

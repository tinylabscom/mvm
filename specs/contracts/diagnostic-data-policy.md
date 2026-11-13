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

## Telemetry and audit review of the cleanup campaign

Review of every merged pull request whose title carries `#4839` (86 as of 2026-11-13), asked the same question each time: did the change delete or refactor tracing, telemetry, redaction, correlation, bounded-resource or shutdown behavior, or a signed-audit guarantee, and if so is the behavior retained. The earlier pass over the first 33 pull requests (its witnesses live in git tag `specs-archive-2026-11-02` and PR 4977) was redone here from the diffs, not copied.

Method: `gh pr diff` per pull request; code lines (comments excluded) filtered for `tracing::`, span, OTLP, observability, audit, redact, emit, log macros and `eprintln!`; every pull request that adds or removes such a line, or moves a file that holds them, was read in full. Added and removed telemetry-bearing lines were compared as multisets so a pure move reads as zero net change. Every witness named below was checked with `rg 'fn <name>'`.

Result: no pull request removed a bounded queue, a redaction step, a correlation identifier, a shutdown path or a signed-audit emission. Two changes are not pure retentions and are stated in their rows: 4935 (third-party `log` records no longer forwarded, accepted at the time) and 4964 (the literal `DEFAULT_FILTER` value is no longer pinned by a test). 4968 relaxes a boot admission check and touches no emitter. The runtime telemetry gaps tracked by the open issues and the telemetry binaries inventory are unchanged by any of these pull requests. A pull request that mentions `#4839` only in its body is outside this set.

| PR | Telemetry or audit surface touched | Verdict | Witness |
|---|---|---|---|
| 4884 | none | Retained | - |
| 4888 | none | Retained | - |
| 4919 | none | Retained | - |
| 4925 | none | Retained | - |
| 4932 | none | Retained | - |
| 4934 | none | Retained | - |
| 4936 | Generator script for the spawn inventory; no runtime code | Retained | - |
| 4937 | Local sha256/hex helpers replaced by `mvm_contract::hash::sha256_hex` and `hex::encode`, including digests feeding signed or audited values | Retained: same lowercase two-digit hex of the same bytes | `sha256_hex_matches_the_standard_encoding` |
| 4935 | `tracing-subscriber` built without default `tracing-log` | Changed, accepted and documented: third-party `log::` records (rustls, mio) no longer reach the subscriber. No first-party `log::` use remains; spans, OTLP export, correlation and redaction are `tracing`-only and untouched | `a_full_queue_drops_the_span_and_counts_it_without_blocking` |
| 4939 | none | Retained | - |
| 4945 | none | Retained | - |
| 4946 | none | Retained | - |
| 4947 | none | Retained | - |
| 4948 | none | Retained | - |
| 4950 | Comment-only edits in mvm-cli | Retained | - |
| 4952 | Comment-only edits in mvm-agentd | Retained | - |
| 4953 | Comment-only edits in mvm-sdk | Retained | - |
| 4954 | Comment-only edits in `audit/merkle.rs`, `supervisor/audit_file.rs` and other hostd files | Retained | - |
| 4955 | Comment-only edits in mvm-runtime | Retained | - |
| 4956 | Comment-only edits in mvm-vmm | Retained | - |
| 4958 | none | Retained | - |
| 4959 | none | Retained | - |
| 4963 | Audit evidence completeness requires each leaf exactly once | Retained, tightened (mandatory signed-audit guarantee strengthened) | `a_leaf_listed_twice_in_place_of_another_fails_completeness_despite_equal_count` |
| 4964 | Deleted constant-restating tests, including `default_filter_keeps_mvm_at_info` (pinned the literal `mvm=info,warn`), `filter_default_covers_mvm_targets_at_trace`, `default_capacity_constant_is_documented_value` and a source-text scan in `input_gate.rs` | Retained at runtime. Changed in coverage: no test now pins the literal value of the CLI `DEFAULT_FILTER`; `observability_config_uses_the_workspace_filter_by_default` compares the config to the constant itself, so an edit of the literal would pass. Minor, listed for honesty. The deleted scan guarded a plaintext secret type that no longer exists; the fingerprint path is compiler-enforced | `observability_config_uses_the_workspace_filter_by_default` |
| 4944 | Generator script for the CLI surface inventory | Retained | - |
| 4965 | Claims ledger citations only (`model/claims.toml`) | Retained | - |
| 4968 | HVF startup admission: a kernel descriptor alone (no frozen images, no caller registration) is now a legacy canonical-kernel boot instead of an error | Changed, not a telemetry or audit emitter: no emission was removed. Frozen-image boots still require a consumed caller registration; a kernel-only boot runs the pre-existing legacy startup, which carries no protected-capture registration (as for any legacy boot) | `frozen_images_cannot_substitute_for_consumed_caller_admission` |
| 4970 | Claims ledger citations for claim 8 admission | Retained | - |
| 4972 | `images.lock` unread pin removal | Retained | - |
| 4974 | Claim 7 statement narrowed to nightly and release-tag audits | Changed: claim text corrected to what the workflow runs; this is a dependency audit, not the audit log | - |
| 4973 | Unrecognised `--hypervisor` refused; aliases removed | Retained | `require_hypervisor_selectable_refuses_an_unrecognised_name` |
| 4966 | Removed hidden CLI aliases; one caller-identity test narrowed from show+status to show | Retained | `caller_identity_show_does_not_create_state` |
| 4975 | BDD suite fixture and docs ledger | Retained | - |
| 4976 | none | Retained | - |
| 4977 | The earlier telemetry review itself (ledger doc only) | Retained | - |
| 4981 | Test of unprepared-initramfs refusal | Retained | `a_launch_with_an_unprepared_initramfs_refuses_naming_bootstrap_without_a_connection` |
| 4979 | xtask footprint measurement | Retained | - |
| 4985 | Chrono feature narrowing (build-only) | Retained | - |
| 4988 | none | Retained | - |
| 4987 | Visibility narrowing; `audit.rs` emit and build helpers `pub` to `pub(super)`; no body changes | Retained | - |
| 4989 | Cleanup failures that were silently discarded now log `tracing::warn!` (paused Firecracker restore teardown, idle-pool claim rollback, transient-VM Ctrl-C stop, builder teardown) | Retained, strengthened: more failure messages, none removed | - |
| 4990 | CI wiring for the spawn inventory | Retained | - |
| 4991 | libkrun/QEMU boot refuses when a stale pid file cannot be removed | Retained: new refusal, no telemetry removed | `a_marker_that_cannot_be_removed_refuses_the_boot` |
| 4992 | Five production `unwrap` invariants moved into types | Retained | - |
| 4996 | none | Retained | - |
| 4995 | none | Retained | - |
| 4993 | Safety comments on unsafe blocks | Retained | - |
| 5008 | Visibility narrowing (agentd, fs, hostlib, vmm) | Retained | - |
| 5015 | Visibility narrowing; `protected_inventory`, `protected_retention` and `UnauditedAnchor` become `pub(crate)`; signatures unchanged | Retained | - |
| 5040 | Removed the `broker::control` forwarding module | Retained | - |
| 5041 | none | Retained | - |
| 5043 | Visibility narrowing (xtask, conformance, stragglers) | Retained | - |
| 5044 | none | Retained | - |
| 5045 | hostd consolidation: audit emitter event modules folded into `events.rs`; `supervisor::audit_set` and `audit_segment` forwarding shims deleted in favor of `mvm_core::audit_verify`; telemetry-handshake signing moved inline into `helper_client.rs`. Add/remove line multisets match apart from paths and `mod` lines | Retained: bodies moved intact, including the nonzero-and-at-most-30-second deadline on `sign_telemetry_handshake` | `naively_dropping_old_entries_fails_verification_at_line_zero` (import paths only changed) |
| 5046 | Removed the `driver::spec` forwarding module | Retained | - |
| 5049 | One host-authority CI gate script | Retained | - |
| 5147 | Replaced self-asserting and source-text tests with outcome tests | Retained | `the_python_wrapper_honours_its_config_and_reports_failures_as_envelopes` |
| 5143 | Claims ledger witness audit | Retained | - |
| 5165 | none | Retained | - |
| 5169 | Deleted the retired guest-side `mvm-egress-proxy` binary and library module, including its stderr ALLOW/DENY lines, and its `non-runtime` entry in the telemetry binaries inventory | Retained: no host-side emitter lost. The egress decision point and its audit are the host `EgressGate`; the deleted proxy was already recorded as launched by nothing, and its stderr lines were never signed audit | xtask `check-single-network-path` (a gate, not a test) |
| 5164 | xtask history-comment gate; comment-only edits across crates | Retained | - |
| 5168 | Secret audit emit now runs through `block_on_anywhere` instead of building a private runtime; failure `tracing::warn!` kept for both failure modes. Lock `expect`s replaced by poison-tolerant `lock` | Retained, strengthened: the emit used to panic when reached from inside a runtime | `recorder_dual_emit_works_from_inside_a_current_thread_runtime`, `recorder_dual_emit_works_from_inside_a_multi_thread_runtime` |
| 5174 | Tests that witness preserved properties: data-plane saturation still admits control, hello grants, audit receipt archive and export | Retained | `a_saturated_data_plane_refuses_data_requests_and_still_admits_control`, `a_hello_ack_grants_only_what_was_asked_for` |
| 5198 | none | Retained | - |
| 5203 | Deleted unreferenced Firecracker `diagnose_vm`, `list_vms`, `stop_all_vms`, `read_reserved_slot` and `build_verity_cmdline_args`, with three `warn!` calls on PID and machine-config parse failures inside them | Retained: no reference to any deleted name remains in `crates/`, so no emission path existed | - |
| 5202 | Dropped two tests that guarded nothing; early-mount and Stage 0 drive checks rewritten as data | Retained | - |
| 5204 | Deleted pub items with no caller (no telemetry or audit symbols) | Retained | - |
| 5205 | One shell-quote helper and one unix-seconds helper (`mvm_core::util::time::now_unix_secs`) | Retained: identical saturate-to-zero semantics, including the hostd `health_probe` and `stream/plane` callers | - |
| 5208 | Dropped a caller-less hvf `vms_root` wrapper | Retained | - |
| 5163 | Spawn disposition classification; secret source CLI reads moved to `mvm_core::bounded_run::run_bounded` with the same stdout cap (`MAX_SOURCE_BYTES + 1`), 4096-byte stderr cap and timeout, plus continued draining | Retained: bounded output and kill-on-timeout preserved | `a_tool_that_outlives_the_bound_is_killed_with_a_typed_error`, `ten_megabytes_of_output_is_kept_only_up_to_the_cap` |
| 5209 | Dropped the `MVM_BACKEND` env alias | Retained | - |
| 5210 | Dropped `vcpus` and `lima_status` aliases | Retained | - |
| 5240 | none | Retained | - |
| 5349 | One launch-config stdin reader for the daemon bins, including `mvm-audit-signer`; error text still reads `<bin> stdin read failed` | Retained: same message text per binary | - |
| 5351 | none | Retained | - |
| 5352 | Unproven `expect`/`unwrap` replaced by typed errors; instruction-trust `Verdict::Unsigned` is the typed fallback; explain refuses a plan with no audit entries | Retained: the unreachable fallbacks fail closed (`Unsigned` is not `Verified`) and the instruction-trust audit mapping is unchanged | `a_file_with_no_sidecar_is_unsigned` |
| 5359 | One `sha256_file` and one deps `read_manifest` | Retained | - |
| 5347 | none | Retained | - |
| 5355 | Outcome tests for macOS loader-path scripts | Retained | - |
| 5364 | Comment only | Retained | - |
| 5362 | Removed root `build.rs` that set an unread env var | Retained | - |
| 5383 | none | Retained | - |
| 5385 | Persistent-builder pid and kernel cache fixes | Retained | `a_zero_supervisor_pid_is_not_alive` |
| 5388 | Refuse unsignalable pids read from pid files | Retained | `parse_refuses_pids_that_must_never_be_signalled` |
| 5390 | FlowMux: UDP open slot released on refusal, unsolicited datagrams no longer count as guest activity, stream-id arithmetic saturates, dead credit helper removed. Existing `warn!` on UDP open failure kept | Retained, strengthened: tighter bounded-resource and idle accounting, no loss or audit path removed | `unsolicited_datagrams_do_not_keep_an_idle_association_open`, `a_peer_chosen_id_at_the_top_of_the_range_is_recorded_without_overflow` |
| 5395 | One signalable-pid rule shared by pid-file readers and recorded session pids | Retained | `a_pid_that_cannot_name_one_supervisor_is_not_signalable` |

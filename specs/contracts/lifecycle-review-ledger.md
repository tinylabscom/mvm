# Lifecycle and unsafe review: reviewed to date (umbrella #4839)

Backing: preview
Validation: none — this records what was read and what was fixed, as stated in the fixing PRs; it is not a claim that the review is exhaustive and enforces nothing beyond the `undocumented_unsafe_blocks` lint it cites.

The umbrella issue owns status. This file records the "reviewed to date" half of the box
"Review ownership, allocation, errors, state transitions, cancellation, lock/task ownership,
cleanup/rollback, unsafe/FFI boundaries, and panic paths affected by changes" in
[#4839](https://github.com/tinylabscom/mvm/issues/4839). The ongoing half is the PR checklist item in
`AGENTS.md` ("Definition of Done", item 7).

**The review is not exhaustive.** The tables list the areas read, the defects they produced, and,
separately, the files that were not read. Absence from the "read" column is not evidence of
soundness. "Read" is taken from the fixing PR descriptions and the review notes for the lane; the
line ranges are as recorded there and were not re-derived when this file was written.

## Offline recovery decision boundary

The A1 slice under [#5120](https://github.com/tinylabscom/mvm/issues/5120)
reviews `host_interface::{lease,policy,error,offline,recovery,workload,state}`
and the unchanged local adapter against the
[offline decision contract](offline-recovery-decisions.md).
The separate companion preserves legacy signed bytes. Verification binds
the exact issuer, lease, host policy, workload/package, expiry, operations
and finite restart/range constraints; a private immutable context feeds a
single-transition consumer with injected clocks and ownership observations.

Reservation/debit, fencing, activation and launch eligibility are separate.
Duplicate input cannot redispatch; stale or conflicting bindings refuse.
Cancellation retains charges and pending cleanup; possible dispatch becomes
unknown rather than reusable. Expiry or uncertain time takes precedence even
after readiness/cancellation and requests closure plus exact-owner
reconciliation. A heartbeat never supplies retirement evidence.

The review is of pure decisions and deterministic tests only. The reducer
owns no native resource and performs no I/O. Existing ledger persistence,
allocator convergence, native stop custody, authenticated channels, actual
effect closure and crash restoration are not qualified here. A2 remains
owned with #5543; A3–A5 must establish native lifecycle evidence before any
production recovery caller is connected.

## Endpoint gate-probe control transport

Reviewed the client launch probe, endpoint config projection, listener binding
and dispatch, and ordinary/owned endpoint spawn evidence. Gate probes use a
separate host-only Unix socket for both Wire and FlowMux endpoints; the guest
data protocol remains fixed by admission. The endpoint binds the control
socket before reporting process readiness, with the existing private-directory
and mode-0600 listener discipline. Only `GateProbeRequest` is accepted there,
and the existing projected gate answers without forwarding, granting egress,
recording workload audit, or authenticating a guest session.

The control listener accepts at most four concurrent probes with no queued
task waiters, limits each request body to 8 KiB before allocation, and gives
the entire request/response exchange five seconds. These limits apply only
to probes, not guest or connector traffic. Four DNS-sized samples fit the
request cap, while a normal launch uses one connection and performs no
external I/O in its probe. Focused tests cover over-cap prefixes, stalled
prefixes/bodies, a nonreading response peer and connection saturation.

The existing endpoint process owns the listener. Reaping removes its path;
ordinary restart reconciles stale sockets, while owned spawn refuses existing
evidence. A failed probe still refuses launch. The added subprocess witness
covers both modes, admitted HTTPS and refused ports, forward-request refusal,
private permissions, unchanged guest authentication, and teardown. This does
not witness a native VM boot or Linux confinement; those remain live CI checks.

## Persistent start admission ownership

The persistent-source slice under
[#5520](https://github.com/tinylabscom/mvm/issues/5520) reviews the machine
lifecycle guard from source and volume preparation through host admission,
backend dispatch, authenticated readiness and rollback. The client retains
source preparation, writable-volume leases and post-dispatch acceptance.
Hostd borrows the caller-held `MachineLifecycleLock`, validates its name and
cold state without reacquiring it, retains the selected `VerifiedRuntimeSet`
through one durable admission, and spends that admission on the existing
persistent dispatch tail.

Pre-dispatch lock, runtime and required-audit refusals start no backend.
Confirmed post-start rollback records failure before reaping state under the
same guard. An unconfirmed native start or stop records an unsealed outcome and
retains runtime, name and volume custody; it does not authorize cleanup or a
second attachment. `plan.launched` remains client-owned after the private
host-socket gate probe, mailbox setup, authenticated guest readiness, grant
readback, budget recording and lease commit.

Mock and source-level tests cover stage order, runtime tampering, audit
durability refusal, lock mismatch and uncertain lease retention. They do not
qualify Linux Firecracker, a billable GCP host, or the formal cold/warm
performance requirements.

## CLI transient cold preparation ownership

The next [#5520](https://github.com/tinylabscom/mvm/issues/5520) source slice
prepares admitted CLI cold authority in hostd before warm/template/cold
selection. Hostd orders runtime attachment, one launch-scoped selected-runtime
verification and one signed admission with its durability obligation, without
starting a backend. The existing Required-tier sync may overlap selection and
isolated guest initialization, but the retained config still blocks warm claim,
non-activation boot or workload activation until that sync succeeds. The opaque
capability retains the exact lowered config, policy, runtime evidence, admitted
plan and immutable audit continuation; serialized plan JSON remains a
projection only.

Warm claim and cold dispatch consume the same one-shot authority. A lost warm
reservation returns that exact unspent capability, while warm success or a
terminal refusal returns only the audit continuation. Writable image locks stay
with the CLI until cold is selected, then transfer once through the existing
CLI-transient finalization. Confirmed teardown permits the deferred launch,
posture, exit and seal narrative. Uncertain stop retains runtime, scratch and
writable-image custody and leaves the session unsealed. Planless warm parents
and template snapshots remain explicit, non-migrated alternatives.

Mock-backed tests cover preparation order with zero starts, one signed
admission, deferred launch audit, absent persistent budget hooks and
uncertain-stop retention. Existing runner tests cover Required-sync refusal
before activation or non-activation boot; the wrapper has no new live-backend
witness. These tests do not qualify native HVF or Firecracker behavior or the
formal cold/warm performance requirements.

## Signed application HVF startup diagnostics

Reviewed in [#5681](https://github.com/tinylabscom/mvm/pull/5681): standalone
`mvm-hostd` verifier feature selection, supervisor descriptor preflight and
early caller/input binding, `ColdHvfChannel` failure retention, and the private
failure-record writer. Default helper builds now include registry signature
verification; explicitly feature-stripped builds cannot produce the HVF binary.

The startup transition remains prepared → uncertain → activated. A failed
activation retains the original `ColdHvfBootFailure` and supporting guards;
formatting borrows diagnostic text and grants no stop or release authority.
Optional diagnostic recording follows namespace validation and precedes caller
preparation. It does not create missing parent directories or turn an unsuitable
diagnostic path into a new launch refusal. Writes assume trusted, stable
ancestors; this is not descriptor-pinned confinement. Text is bounded and
home-path/control-character sanitized, not general credential redaction.

Focused tests cover genuine descriptor verification and tamper refusal,
standalone build features, private paths, missing-parent preservation, and a
never-launched failure retaining its supporting guard until explicit release.
A source-order tripwire covers recorder placement. Actual native startup
failure recording, unconfirmed-child recovery, confirmed rollback, and a
successful public Claude boot/stop remain outside this source-only witness.
No retained runtime state or native credential was changed by the patch.

## Audit-chain module ownership

The ADR-061 prerequisite relocates the existing chain signer, file writer,
checkpoint cache, recorder, mirror, dedup and transcript/bound sinks into
`crates/mvm-hostd/src/audit/`. Supervisor module and flattened exports retain
the same concrete identities. This changes Rust source ownership, not runtime
resource ownership or the security claims of ADR-001.

The archived focused review read module declarations/imports, file-signer
batch/Drop and sidecar-lock ownership, and the bound recorder's direct journal
path, weak sink binding, health persistence and expiry refusal. The direct
journal operation stays restricted to the common audit module
(`pub(in crate::audit)`). The bound sink moves with the recorder rather than
widening this method to crate visibility.

Existing transition owners remain: the host caller supplies signing authority;
the file signer serializes append/rotation with the sidecar lock; callers own
batch durability waits; Drop best-effort flushes deferred entries; endpoint
startup owns registration and the bound sink owns its epoch-local health.
An expired weak binding still refuses instead of falling back to unbound
recording. No cancellation, lock, key, event, serialization, recovery or
retirement transition is changed by the mechanical move.

The [implementation report](../../xtask/data/evidence/adr-061/audit-chain-implementation-report.md)
separates historical review/checks from recovery evidence at `d772741916`.
Recovery compared current source modulo imports/visibility; it did not repeat
the historical runtime validation. Combined checks and the separately owned
file/checkpoint/emitter directory-policy changes require integration validation.
This is not a new review of producer adapters, native completion, the combined
signer helper, mailbox features or backend isolation.

## Guest-runtime first-use publication

Reviewed `mvm-build`'s `runtime_pieces`, `cache_install`, `runtime_overlay`,
`initramfs`, `sdk_sidecar`, and the OCI installer in `guest_agent_build`, plus
the CLI first-use caller through `mvm-client::release`. Archive verification
and launch admission remain separate and unchanged.

Each version/architecture artifact slot (also libc for a sidecar) has one
stable sibling file lock. Builders own it from the reuse decision through
construction, publication, final validation and provenance recording;
standalone installers, explicit discard and initramfs eviction use the same
owner. Locked internal installers do not reacquire it. Dropping the guard
explicitly unlocks on success or error; this lock is not a process-lifetime
or custody-transfer proof.
SDK staging and stale-stage cleanup use the libc slot name under the shared
architecture parent, so independently owned libc slots cannot share staging.
An abandoned staging directory remains subject to the existing cleanup rule.
The initramfs resolve-miss path no longer deletes a directory based on a
stale observation before it has a candidate.

The OCI installer owns its slot, prepares and validates all four candidate
binaries before touching cached files, reuses identical regular files, and
renames changed files without a remove/copy gap. Preparation failure leaves
the previous valid binaries intact. This is not a multi-file transaction:
an I/O failure during publication can still leave a mixed replacement.

Filesystem/archive fixtures cover competing callers waiting for each slot,
successful assembly and reuse, refused candidates preserving existing output,
overlapping libc staging, and wrong-architecture OCI candidates preserving a valid set. The existing
CLI concurrent first-use regression remains enabled. No live backend,
hardware boundary, crash-durability or hostile-host guarantee was added.
Read-only launch resolvers do not hold snapshot leases: explicit replacement
or discard of a different generation remains outside this first-use repair.

## Initial committed project policy generation

The focused review in [#5654](https://github.com/tinylabscom/mvm/pull/5654)
covers `mvm-core/src/host_interface/activation_barrier.rs`, the
`mvm-hostd/src/policy_generation` coordinator/store, host plan admission,
and their CLI/client launch, persistent-start, checkpoint and restore callers.
The resident coordinator owns generation-one publication under the exclusive
barrier; launch/restore callers retain shared guards through their transitions.
Publication records durable intent, a no-clobber project closure and the active
index. Missing or inconsistent activation state refuses reuse rather than
falling back to staged files. Backend owners retain workload teardown custody.

Review found relative IPC project identities could resolve against the resident
process's working directory and ordinary pre-activation runs unnecessarily
required that process. Regression tests cover requester-side canonicalization,
server-side relative-path refusal, and absent-helper compatibility before
activation. Host verification also rejects generation-bearing plans that omit
or widen committed CPU-share grants. The CLI already refused CPU-share-limited
entrypoints; this was not a demonstrated CLI bypass.

This review does not establish live policy cutover, generation updates,
deactivation, or other-backend support. No effect-fencing/route-transfer or
fleet transaction is implemented. The live evidence is restricted to the
Linux/Firecracker scenarios cited in the PR; it does not replace review of
unrelated lifecycle paths or claim crash recovery can resume an incomplete
publication automatically.
## Actor conversation waits and recovery

Reviewed the MVMC v2 invocation budget, guest-local single-exchange admission,
caller-disconnect handling, authenticated enrollment/lease validation, host
conversation waits, durable peer delivery worker, and HVF mailbox idle handling.
Caller patience narrows signed authority; queueing and handshake consume the
original monotonic budget. Concurrent local requests receive an explicit refusal,
and both active and busy frame decoders have absolute deadlines. The guest owns
one exchange worker, not an unbounded thread per caller.

Cold guest clocks can lag newly issued enrollment and lease timestamps. The guest
authenticates signatures and static bindings before waiting for actual guest time
to reach issuance, then repeats full validation before use. Waiting is bounded by
the original caller deadline and a short validation phase; it neither adjusts the
clock nor accepts early authority. Invalid signatures, contradictory windows,
expiry, and cancellation remain refusals.

The delivery worker retries transient unavailability with capped jittered
backoff, using the persisted attempt/expiry limits and original sealed message.
Only configured mailbox and builder control ports survive HVF transport idle
eviction; service deadlines and EOF still apply. Integrity refusals do not
schedule a timer retry, though a later unrelated wake can retry a retained
record within its existing budget.

On 2026-11-17, `scripts/actor-live-hvf.sh` completed the trusted-host development
two-guest workflow: forbidden template and oversized message refusal, durable
call/reply and ACKs, parent application exit zero, and two terminal reservations.
Child application-terminal observation was uncertain during release; native
teardown was established separately through original ownership. The separate
`actor_response_survives_helper_process_crash_before_signed_ack` process test
witnesses exact-config recovery of an accepted response before the parent result
ACK. Neither witness establishes automatic actor-supervisor restart, VM crash
recovery, same-UID helper confinement, production assurance, latency, or density.

## Original HVF actor liveness

Reviewed `HvfRunningVm::status`, `OwnedInstance::try_exited`,
`ConnectedInstance::connect_bound`, the supervisor stop-control exchange, and
the actor controller's activation/resource/lifecycle/serve error boundaries.
An original live owner previously fell through into a fresh name-based control
connection. Status now returns from retained child custody for both live and
exited observations; observation errors remain errors. Attached status still
requires its authenticated generation-bound probe. Exit finalization checks,
stop authority, resource release, and terminal accounting are unchanged.

Pure branch regressions cover live/exited/unknown original status without
attachment and attached-generation refusal. An in-process supervisor protocol
test covers repeated observation connections: the serial server has no
extra-owner rejection rule. This does not identify the cause of a particular
live EOF, nor prove guest application readiness. No guest execution or broad
supervisor/lifecycle review is implied by this focused change.

## Manager-owned policy coordinator identification

Covers `mvm-hostd/src/policy_generation/managed.rs`, the `Status` request and
connection handling in `policy_generation/coordinator.rs`, and the
`mvmctl policy coordinator` caller, for
[#5255](https://github.com/tinylabscom/mvm/issues/5255). A systemd user
manager owns the process: it creates, restarts and reaps the unit, and the
coordinator only refuses to serve when it is not that unit. The client owns
nothing but one connection, which it drops on every outcome. Deadlines are the
manager query bound, a non-waiting connect and an exchange bounded per read and per write (five
seconds each, not five seconds in total); there is no retry. No durable state is written, so there is nothing to recover: a
restart between the two manager observations is reported as unknown. The
detached spawn path, activation and generation storage are unchanged and not
re-reviewed here. Not reviewed: a provisioned unit on a real host, restart
limits, and any commit, migration or signing path.

## Publication obligation and recovery

Covers `GenerationStore::publish_initial` and `GenerationStore::recover` in
`mvm-hostd/src/policy_generation/store.rs`, for
[#5255](https://github.com/tinylabscom/mvm/issues/5255). A durable
`pending.json` is written first, then the activation marker, the record and
the index, and removed last; readers and activations refuse while it exists,
and recovery removes files only. A rolled-back first publication also removes
the activation marker. Launch and restore ask the coordinator to recover when
they find an obligation, and the coordinator holds an exclusive owner lock so
only one process recovers.
Still open: an activation marker with no index and no obligation can no longer
be produced by publication, only by outside damage, and is still refused with
no automatic recovery. Recovery in the same boot after a failed directory sync
relies on the later successful sync of the obligation's removal to cover the
earlier rename, and a filesystem that reports a writeback error only once could
make that sync succeed without the rename being durable. On a filesystem
without no-replace rename the record is published by link then unlink, and a
crash between them leaves a record that recovery refuses. A failure after the
obligation is written is exercised only by stopping between the store's own
step functions, not through a real failing `fsync`, and the unresolved-error
wrapping inside `publish_initial` has no test driven by a real failure.
Migration exclusion and prepared-head signing custody are untouched.

## Workload ledger store

Covers `mvm-hostd/src/policy_generation/workload_store.rs`, the
`CommitWorkload` request in `policy_generation/coordinator.rs`, the readers in
`mvm-core/src/host_interface/workload.rs` and `mvm-hostd/src/containment.rs`,
for [#5255](https://github.com/tinylabscom/mvm/issues/5255). The policy
coordinator is the only writer of the containment ledger. Files, all under
`policy-generations/workloads/`: `ledger.json` (sequence plus entries) and
`pending.json` (the obligation, `Migrate` or `Commit{sequence, sha256}`).

Commit order, under the store's lane and the coordinator owner lock: recover,
migrate if the ledger is absent, apply the change, write `pending.json`
durably, replace `ledger.json` durably, remove `pending.json`. A quarantine of
an already quarantined workload returns the current commit without writing; a
replace must name the workload's current epoch. Readers refuse while
`pending.json` exists (checked before and after reading the ledger), on a
malformed, oversize or non-regular ledger, and read the legacy file only when
no canonical ledger exists. A reader that sees the obligation waits and
re-reads, up to 100 rounds of 10 ms, before it refuses, so a commit in flight
does not fail a launch. A stranded obligation is resolved by a `Recover`
request: `quarantine`, `replace` and every launch, start, resume, restore and
fork path send it, on every host and backend, when they see one
(`recover_workload_ledger`, one `stat` otherwise). A reader reached some other
way refuses until one of those runs.

Interruptions: after the obligation and before the ledger rename, the ledger
still has `sequence - 1` and recovery removes the obligation; after the rename,
the ledger bytes match the recorded hash and recovery removes it; matching
neither leaves the obligation, readers and further commits refuse, and the
answer on the wire is `Unresolved`. Recovery runs at bind, on `Recover`, and
before every commit.

Migration: pre-validate the legacy file (size, strict parse, count and name
bounds; a bad file changes nothing), write `Migrate`, create the archive
directory, exchange it with `host-interface/workloads.json` so that path is a
directory, write `MOVED` inside it, read the archived file, write `ledger.json`
at sequence 0, remove the obligation. Any older binary's rename onto that path
fails and its read fails. A resumed migration repeats from the obligation; a
legacy write landing before the exchange is what the ledger starts from. The
archive is never deleted or rewritten.

Bounds: 16384 workloads, of which the last 1024 are reserved for quarantine
(a replace cannot create an entry inside the reserve), names 1 to 256 bytes,
4 MiB per ledger. The byte limit has the same reserve: a replace that creates a
new entry is refused once the ledger would exceed 4 MiB minus 1024 worst-case
escaped entries; a quarantine keeps the full limit.

Ownership: the store holds an exclusive lock on a file inside the ledger
directory for its life, so a second owner is refused however the home path is
spelled (a symlink, a different spelling). The coordinator's own owner lock is
separate and unchanged. A migrated ledger is never rebuilt: a fenced legacy
path with no migration obligation and no canonical file is an error, because
the archive predates every later commit. Waiting activations cannot take the
last 32 handler slots, which keeps a quarantine from being refused at the
connection limit by activations alone.

Limits: a launch that read the ledger before a quarantine commit can still
start after it, so the operator stops the machine after quarantining; mailbox
destination commits are not ordered by this lane yet; quarantine and replace
need the coordinator process and are refused when it cannot start. A failure
after the obligation is exercised by stopping between the store's steps, not
through a failing `fsync`.

## Compile-time AES-GCM boundary

Reviewed `crates/mvm-crypto/src/aead.rs`,
`crates/mvm-core/src/crypto/aead.rs`, and the seal/open paths and independent
cipher tests in `crates/mvm-core/src/net/session.rs`. The shared crypto crate
only instantiates the existing `aes-gcm` implementation in its own optimized
compilation unit. It borrows fixed-size keys and nonces for one operation and
returns owned ciphertext/plaintext; it owns no persistent keys, process, task,
lock, or lifecycle state.

The public `aead::Aead` trait lets implementations define their key, nonce,
and error types. `Aes256Gcm` remains the concrete selection at both production
call sites; no algorithm negotiation, protocol switch, or new cipher is added.
Integration tests cover trait-object dispatch and a downstream refusal-only
implementation with different associated types.

The callers retain key zeroization, nonce generation, associated-data selection,
framing, signature verification before session decryption, sequence advancement,
replay checks, and existing error mapping. The at-rest encryption `expect`
retains its existing message and failure condition. The leaf adds a known AES-256-GCM
vector and wrong-key/nonce/AAD, truncated-tag, and byte-tampering tests; the
independent direct-cipher tests in `mvm-core` remain. This is not a review of
the upstream cipher implementation or of the broader snapshot/session lifecycle.

## Mechanical gate

`clippy::undocumented_unsafe_blocks` is `deny` workspace-wide ([#5438](https://github.com/tinylabscom/mvm/pull/5438);
about 200 `SAFETY` comments were written after reading each site, and three packages that had skipped
the lint table now inherit it). The earlier unsafe documentation pass for `mvm-setpriv` and
`mvm-host-services` is [#4993](https://github.com/tinylabscom/mvm/pull/4993). The lint checks that a
comment exists, not that its claim is true; the sites were read, but a comment is not a proof.

## Reviewed areas and defects fixed

| Area reviewed | Defect class | Fixed in | Files read and found sound or fixed |
| --- | --- | --- | --- |
| Silent `let _ =` on teardown and rollback paths | cleanup failure discarded | [#4989](https://github.com/tinylabscom/mvm/pull/4989) | builder pipeline teardown, transient-run Ctrl-C handler, Firecracker `teardown_paused` restore branches, idle-pool claim rollback (`crates/mvm-backends/src/fc/idle_pool.rs`) |
| Production `unwrap` on guaranteed values | panic path encoded in types | [#4992](https://github.com/tinylabscom/mvm/pull/4992) | `embed_toolchain::strip_glibc`, stage0 nix-seed lift, `vm artifact` prefix resolution, TypeScript decorator site scan, manifest image validation |
| Panics and truncation on hostile sizes | arithmetic overflow, narrowing casts, lock poisoning | [#5168](https://github.com/tinylabscom/mvm/pull/5168) | `mvm-fs` ext4 writer and `elf.rs`; cpio writer in `mvm-builder-guest`; `mvm-agentd/src/process_rpc.rs` and `mvm-core` instance metrics locks. Census is heuristic (script, not a parser) |
| Unproven `expect`/`unwrap` in six crates | panic path | [#5352](https://github.com/tinylabscom/mvm/pull/5352) | `mvm-fs`, `mvm-net`, `mvm-client`, `mvm-bundler`, `mvm-http`, `mvm-hostd`; poisoned-mutex expects and static schema parses left alone on purpose |
| Other typed-error conversions | panic path | [#5075](https://github.com/tinylabscom/mvm/pull/5075), [#5083](https://github.com/tinylabscom/mvm/pull/5083), [#5139](https://github.com/tinylabscom/mvm/pull/5139) | empty workloads, bare image refs, unnamed persistent requests; agentd, vmm and hostd reachable panics; registry `block_on` bridge inside a tokio runtime |
| Persistent builder pid and kernel cache | signalling pid 0 (own process group); racy fixed staging name | [#5385](https://github.com/tinylabscom/mvm/pull/5385) | persistent-builder stop path, `extract_bundled_kernel` |
| Pid-file readers | corrupt pid file reaching `kill(2)` | [#5388](https://github.com/tinylabscom/mvm/pull/5388), [#5395](https://github.com/tinylabscom/mvm/pull/5395) | `EndpointPid::parse`, broker, audit-signer, network-endpoint, QEMU and GPU endpoint pid readers; one `signalable_pid` rule in `crates/mvm-vmm/src/host/process_liveness.rs` |
| Stale pid file at boot | boot proceeding past an unremovable pid file | [#4991](https://github.com/tinylabscom/mvm/pull/4991) | libkrun and QEMU boot paths |
| Killed boot-timeout child never reaped | kill without `wait()` leaves a zombie in a long-lived parent | [#5489](https://github.com/tinylabscom/mvm/issues/5489) | libkrun driver boot and vsock-timeout paths now kill and reap through `driver::kill_and_reap`, with a waitpid-based no-zombie test; the `hvf_restore.rs` sites are owned by #5490 and the `hvf/stop_state.rs` and `fc/idle_pool.rs` sites listed with the gap were test-only and already reaped |
| FlowMux registry and UDP relay | peer-chosen stream id overflow; unsolicited datagrams holding an association; UDP slot leak on open failure | [#5390](https://github.com/tinylabscom/mvm/pull/5390) | `crates/mvm-hostd/src/supervisor/endpoint/flowmux/registry.rs`, `udp_relay.rs`. The slot-leak fix has no test (needs fd or thread exhaustion) |
| HVF guest PC, SMP unwind, HTTP flow cancellation | guest-chosen PC overflow; panic wedging `thread::scope`; cancellation unwatched after response head | [#5402](https://github.com/tinylabscom/mvm/pull/5402) | `crates/mvm-runtime/src/backends/hvf/smp.rs` (non-test code), `http_flow.rs`, `open_flow.rs` lines 1-352 |
| HVF standby parent teardown | start error paths leaving the parent VM running when the recorded pid was unsignalable | [#5491](https://github.com/tinylabscom/mvm/issues/5491) | `crates/mvm-backends/src/driver/hvf/standby.rs` (`recorded_pid_or_stop`): every recorded-pid refusal stops the just-booted parent through the owned-stop path; failing-before test with a negative pid |
| HVF snapshot and cancellation lifecycle | pause/capture races, completion notification | [#4994](https://github.com/tinylabscom/mvm/pull/4994), [#5064](https://github.com/tinylabscom/mvm/pull/5064), [#4983](https://github.com/tinylabscom/mvm/pull/4983) | fixed under the HVF owner work; not re-read for this table |
| Volume, checkpoint and peer-EOF custody | custody, removal guard, EOF after timeout refusal | [#4880](https://github.com/tinylabscom/mvm/pull/4880), [#4957](https://github.com/tinylabscom/mvm/pull/4957), [#4864](https://github.com/tinylabscom/mvm/pull/4864), [#4879](https://github.com/tinylabscom/mvm/pull/4879) | fixed under the volume and vmm owner work; not re-read for this table |
| Unsafe/FFI documentation | missing `SAFETY` claims | [#4993](https://github.com/tinylabscom/mvm/pull/4993), [#5438](https://github.com/tinylabscom/mvm/pull/5438) | every `unsafe` block in the workspace has a comment; see the gate above |
| Restore readiness teardown | failed restore leaving its supervisor running | [#5490](https://github.com/tinylabscom/mvm/issues/5490) (fix on `fix/5490-hvf-restore-teardown`, PR pending) | `crates/mvm-backends/src/driver/hvf_restore.rs` (`await_restored`): both error returns after the ready marker now stop and reap the spawned supervisor through the owned child handle, with the outcome logged; the published record is validated by `restored_identity` and the pid read stays on the guarded `process_liveness` helper |

## Endpoint provisioning handoff

### Host capacity reservation

Ordinary admitted launches and actor pre-plan reservations share the generic
`admission-budget/reservations.json` memory/CPU ledger. A short exclusive lock
serializes legacy-charge measurement, pending holds and durable reservation
creation; it is not held across signing or boot. Admission retains the actual
permit, not a readiness boolean. The physical VM name is frozen at dispatch;
coordinated reservations refuse physical-name substitution.

Prepared ordinary holds can be released before effects. Dispatching/unknown
holds remain charged after launcher failure. A successfully recorded ordinary
running hold carries the original PID and start identity and can reclaim only
memory/CPU on confirmed death of that identity. Missing/malformed PID files are
not proof. A caller-owned ordinary launch with no PID marker can refund only
through its original successful runtime stop and resource-drop callback, and
only when it has no managed lease keys. A failed stop, managed lease ambiguity,
or failed accounting write retains capacity and reports the refusal; this is
not complete ordinary volume-cleanup reconciliation. Actor-coordinated holds
cannot use that refund and never auto-release: the original lifecycle
owner must confirm death and resource cleanup and commit the terminal result
before invoking digest-bound reconciliation.

Ordinary runs without a configured host memory/CPU ceiling do not create a
pending journal. They still write their legacy charge for a later configured
ceiling. Actor holds are always journaled and an unbounded ordinary permit
cannot be promoted into a coordinator hold.

The ordinary Firecracker launch script now writes the existing `fc.identity`
pid/start sidecar from the process that will exec Firecracker, while keeping
the bare `fc.pid` wire unchanged. Accounting requires those files' PIDs to
match. HVF and libkrun publish their own pid/start identities and refuse
unavailable identity publication before guest execution. No process is signaled
by recapturing a PID. Older or unsupported bare-only evidence remains unknown;
there is no new name-only recovery command. Lost-owner reconciliation and
managed-volume cleanup evidence remain explicit availability limitations.

The actor coordinator combines this prepared host hold with its separate scope
reservation before one dispatch authorization. These are conservative prepared
holds, not atomic cross-file writes. Interrupted coordination may overreserve;
it must not grant capacity twice or automatically dispatch a recovered request.
No ordinary launch initializes an actor journal. Unadmitted warm-factory
capacity is not newly accounted here, and no resident-capacity or timing claim
is promoted.

Actor cold-start refusals now retain runtime-origin no-dispatch evidence only
before the first possible helper/native dispatch. The opaque evidence binds
the physical VM name, complete admitted plan (including nonce), and original
signed envelope. Missing state/PIDs, successful rollback, and missing original
VM custody cannot mint it. The endpoint boundary is conservative even when its
particular configuration would not spawn a process.

Admission validates that evidence and durably emits `plan.cancelled` before
changing a dispatching hold. Coordinated holds enter charged `NoDispatch`,
which cannot authorize another launch; the lifecycle owner still writes its
cancelled journal and terminal audit before digest-bound refund. Root cleanup
uses its existing never-dispatched terminal transaction only for the matching
attempt. Ordinary cancellation retains a digest-bound terminal tombstone.
Both cleanup owners retry a failed cancellation audit/accounting write from
the retained original proof; they do not treat a successful rollback as evidence.
Unknown and partial starts retain their original native/helper owners.
Crash recovery cannot reconstruct the opaque runtime proof from process absence.
Reviewed paths are runtime actor startup, the shared cold runner, admitted-start
failure handling, root cleanup, child cancellation, and host-budget transitions;
this is not a new review of backend teardown or live native execution.

The focused launch-lifecycle review for
[#5117](https://github.com/tinylabscom/mvm/issues/5117) follows the admitted
cold-start and resumed-session paths through `WorkloadRunner`, the real
network endpoint spawner, and the endpoint's bound-audit readiness handshake.
The handshake already follows binding and probing the serving audit sink;
this review adds no second readiness gate.

The post-spawn provisioning tail in
`crates/mvm-runtime/src/workload_runner/runner/spawner.rs` must retain cleanup
ownership until its fallible telemetry provisioning record is written. The
existing `EndpointGuard` covers that interval, then hands cleanup back to
`ClaimGuards` on success. The regression tests exercise a real stand-in child
and its pid/environment sidecars, not a guest VM or real FlowMux session.

Cleanup retains the existing reaper's semantics: identity-checked SIGTERM and
best-effort removal of sidecars, fingerprints, and telemetry state. It does not
wait for termination or return signal/removal errors; the provisioning error
remains the launch error. A crash, an unremovable path, or a process that ignores
SIGTERM is not newly guaranteed clean. Bound audit health evidence is retained,
not reset for reuse. This is not an exhaustive review of warm restore,
supervisor teardown, or actor lifecycle, and completes no phase-0 gate.

## Flow-audit lifecycle boundary

The focused review for [#5538](https://github.com/tinylabscom/mvm/issues/5538)
covers the changed FlowMux decision and session-cleanup paths, the bound-recorder
adapter and shared asynchronous-recorder bridge, and endpoint readiness.
It is not a new review of every file in the earlier census below.

The transition owners are:

- The admitting host supplies the workload plan and execution epoch; a builder
  supplies an explicit non-workload identity.
- Endpoint startup requires a successful write through the actual bound sink.
  The sink carries no lifecycle control capability and adds no post-boot
  registration handoff.
- One endpoint-owned state serializes write outcomes across all its sessions.
  Missing records remain marked incomplete after recovery of the journal;
  suppressed UDP repeats do not reset the failure streak.
- An operation whose required audit write fails is refused. After journal
  recovery, later recorded operations may proceed, but the missing evidence
  remains recorded as incomplete.
- Session completion cancels its forwarding work and flushes accumulated health.
  The health file begins `active`, never `complete`; an unclean exit or failed
  health-file write cannot establish a complete epoch. Signed epoch sealing and
  crash-recovery integration remain separate contracts.

Health creation exclusively reserves an owner-only path before publishing its
first snapshot. An interrupted, even empty, reservation refuses reuse. Updates
use the shared atomic durable writer: sync a private temporary, rename it into
place, then sync the parent directory. Failed rename retains temporary cleanup;
successful rename disarms old-name cleanup. This path uses creation-time modes
and libc rename without extending the endpoint's seccomp allowlist.

UDP closure retains the relay and its capacity charge until the worker exits;
the session thread never joins a live relay while handling CloseUdp or Reset.
Nonblocking transport I/O and readiness preserve blocking read behavior while
bounding a whole frame write by one credit-wait deadline. Session locking ends
before the write can wait, so incoming cancellation can still be authenticated.
Final cleanup closes the transport, cancels and joins relay owners, releases
their charges, then flushes suppression counts. Native socket tests cover a
non-reading guest, slow draining, partial-frame failure, and continuous denied
datagrams; ordinary association closure leaves unrelated TCP flows intact.

The endpoint-process witnesses verify missing-sink refusal and signed,
plan-bound denial records; they do not establish live HVF/Firecracker behavior.
Backend-specific verification is recorded in the implementing issue and PR,
not inferred here.

VM lifetime remains with the existing runner/backend owners. Automatic
termination after three production audit-write failures remains unimplemented
under #5538; this audit-only slice adds no stop control, post-boot target
acquisition, or backend-based startup refusal. Completing that requirement needs
qualified lifecycle ownership and confirmed rollback, not a new lookup by name
or PID. Original-owner persistent Firecracker work remains subject to the
deferral and process-model decision in
[#5522](https://github.com/tinylabscom/mvm/issues/5522).

## Instance-bound recovery and foreground completion

The focused review for [#5621](https://github.com/tinylabscom/mvm/issues/5621)
covers health-probe restart dispatch, the client launch/stop/remove paths,
CLI initialization and transient teardown, and the warm-claim handoff.
It does not qualify a new backend or establish live hardware behavior.

The existing per-machine resume lock serializes named lifecycle transitions.
Health recovery retains the authenticated HVF instance that triggered the
probe and checks it before stop effects; replacement passes fresh admission.
Library and CLI removal retain the transition through resource cleanup.
An absent stop also takes the transition before name-based effects.
Fresh definition creation and saved-state removal share payload cleanup that
preserves the lock inode, including when discarding an earlier machine's
orphaned snapshots and mount registry.

Guest initialization runs on its original connected stream outside that lock.
Completion reacquires the lock before metadata updates or rollback. Foreground
transient cleanup likewise checks retained runtime-directory custody and,
for backends with same-directory restore, the original HVF instance or
Firecracker process identity. The retained directory handle is a negative
replacement check on a trusted host, not an authorization credential.
Warm claims transfer the child transition guard from preparation through
foreground custody capture; failure rollback runs before that guard drops.
An unconfirmed child stop retains its state and parent reservation instead
of making the parent available or deleting control state.

The regression fixtures cover stale completion, stopped/preparing transitions,
failed-stop lease retention, and guarded warm handoff. Fixture results,
workspace gates, and remaining live qualification are recorded on the issue;
this source-review record does not turn those fixtures into a guest-boot
witness. Other direct backend consumers and the broader restore lifecycle
have not received an exhaustive new review here.

## Mailbox journal fence

`JournalFence::fence` (`crates/mvm-core/src/mailbox/journal/fence.rs`) writes a durable
`journal.fence` marker into a journal store. Journal open, which is what the mailbox
helper's start path calls, now refuses a fenced store with `JournalError::Fenced` before
it scans the directory. Fencing takes the same writer lock open takes, so it returns
`Busy` and writes nothing while any writer has the store open, and it cannot succeed under
a running helper. While the returned guard lives no writer can open the store, and
dropping it leaves the store fenced. Presence of anything at the marker path decides; its
content is never parsed. Fencing twice succeeds, and the directory sync runs on a repeat
so a retry after a failed sync becomes durable.

What it does not do: nothing calls it yet. It does not stop a helper that already has the
store open. The locks are advisory, so a process that writes the files without the journal
API is not excluded. It does not fence the anchor or the source-intent directory.

## Files NOT read

None of the following was read for lifecycle, ownership or cancellation defects. Treat them as
unreviewed.

- `crates/mvm-backends/src/driver/hvf_restore.rs` lines 1-380 and 620 to the end (the part between was read).
- Snapshot codecs: `crates/mvm-runtime/src/backends/hvf/snapshot.rs` and `crates/mvm-vmm/src/snapshot.rs`.
- `crates/mvm-runtime/src/backends/hvf/kernel_boot.rs`: most of `run_primary` and the device wiring.
- Tests in `crates/mvm-runtime/src/backends/hvf/smp.rs`.
- `crates/mvm-hostd/src/supervisor/endpoint/flowmux/`: `ingress.rs`, `tcp_relay.rs`, `open_flow.rs` beyond line 352, `socket.rs`, `wire.rs`, `resources.rs`.
- `crates/mvm-backends/src/driver/libkrun.rs` configuration building.
- Async cancellation safety outside FlowMux.
- The volume bridge beyond its wire codec (`crates/mvm-agentd/src/volume.rs`, `crates/mvm-client/src/volume/`).

## Known and unfixed

Found during the #5390 review. Every gap recorded here has since been fixed; the row
that remains describes its fix so the next reader sees the resolution without digging.

| Item | Site | Owner | Next step |
| --- | --- | --- | --- |
| `HvfVm::create` did not destroy the VM or release the GIC config when GIC creation fails — fixed by an RAII guard (`PendingHvfVm`) over the setup seam (`VmSetup`), so every early return after `hv_vm_create` drops into cleanup, and by `commit` releasing the config on the success path too; cleanup order is unit-tested with a fake seam, the real-FFI check on a live HVF host is still owed (tracked in #5492, fix on branch `fix/5492-hvf-gic-guard`) | `crates/mvm-runtime/src/backends/hvf/hv_impl.rs` (`HvfVm::create`) | HVF owner | merge the fix, then confirm `mvmctl` launch/teardown on a real macOS HVF host (the failure itself is not injectable through the real framework) |

## Fixed after this table was written

| Item | Site | Fixed in | Files read and found sound or fixed |
| --- | --- | --- | --- |
| FlowMux registry kept `Closed` entries for the session lifetime; retired entries are now dropped, with reuse refused by the allocator's high-water mark | `crates/mvm-hostd/src/supervisor/endpoint/flowmux/registry.rs` (`StreamRegistry::retire`, `open_guest`/`open_host` watermark) | #5493 | `registry.rs`; removal is safe because every retire path has already had its final frame admitted by the session validator, relay threads gate on the per-stream `retired` flag, and ID ordering survives in the allocator counters. Verified by `open_close_cycles_do_not_accumulate_registry_entries` and `a_retired_stream_id_cannot_be_reopened_by_the_peer` |

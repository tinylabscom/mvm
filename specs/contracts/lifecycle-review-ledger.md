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

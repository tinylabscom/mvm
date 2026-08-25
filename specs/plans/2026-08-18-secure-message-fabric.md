# Implement the local secure message fabric and supersede stdio transport

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

## Status

**READY FOR IMPLEMENTATION AFTER ADR-046 IS REVIEWED.**

This is the `mvm` half of the work. It builds the complete one-host fabric and
the deterministic state-machine implementation that `mvmd` will replicate.

Distributed work belongs to a separately numbered `mvmd` ADR and plan.
This package includes `MVMD-HANDOFF.md` so the local implementation does not
quietly absorb fleet consensus, placement, or peer-transport responsibilities.

Do not implement fleet consensus, node membership, elections, or cross-host
leader routing in this repository.

## Goal

Deliver a production-quality local vertical slice:

```text
two real microVMs on one host
one admitted session
one ExclusiveInbox per workload
end-to-end encrypted mailbox request
durable functional response stream
stdout/stderr/trace over Telemetry lane
operator input over Input lane
SQLite-backed deterministic state machine
complete transition audit and tracing
process crash/redelivery
session archive and active-state purge
prepared-cold communication_ready p99 <= 200 ms
```

The same `ConversationCommand` and `ConversationStateMachine` are reused by
`mvmd` data-group replicas later.

## Scope

This plan includes:

- all guest, host-reader, and local-workload communication inventory;
- one mandatory secure-channel substrate;
- removal of raw guest transport and raw console payload capture;
- fixed bounded fabric contracts and codecs;
- guest-local stdio adapters;
- workload-owned E2E mailbox keys;
- a ciphertext-only guest message role;
- a local standalone committer;
- deterministic conversation state-machine commands;
- resident shard workers;
- hardened shard-local SQLite;
- local mailboxes, functional streams, telemetry, input, and protected system
  events;
- complete transition audit and standard tracing projections;
- session archive-before-purge;
- shared `mvmd` data-only contracts and deterministic apply interface;
- crash, fuzz, property, static, security, memory, and performance gates;
- migration of workflow documents to consume this fabric.

It does not include:

- Raft or another consensus implementation;
- live node-to-node transport;
- distributed replica placement;
- leader election;
- distributed mailbox migration;
- distributed archive aggregation;
- broadcast topics;
- competing-consumer queues;
- exactly-once external side effects;
- OTP behavior APIs;
- a mandatory external database/broker;
- libSQL;
- host-readable mailbox plaintext by default.

## Non-negotiable invariants

- [ ] Every guest-controlled application byte crossing guest↔host is
      authenticated and encrypted.
- [ ] No production plaintext, raw framing, 0-RTT, permissive verification, or
      downgrade path exists.
- [ ] Mailbox and functional-stream application content is E2E encrypted.
- [ ] Host, control agent, guest message role, store worker, audit worker, and
      archive worker receive no application-plaintext API.
- [ ] User messages can address workload mailboxes only.
- [ ] No fabric field or payload can select a host executable, guest
      executable, plan, argv, environment, filesystem path, plugin, shell,
      runtime, lifecycle operation, broker request, or stdin.
- [ ] Stdio is guest-local compatibility only.
- [ ] Functional workflows never route stdout into stdin.
- [ ] Accepted mailbox/functional data is never silently dropped.
- [ ] Every durable transition atomically writes its audit-outbox record.
- [ ] SQLite sees bounded ciphertext and fixed metadata only.
- [ ] SQLite files are never shared between hosts or opened from guest paths.
- [ ] The apply path is deterministic and idempotent by `CommitPosition`.
- [ ] A conflicting command at an applied position quarantines the shard.
- [ ] Warm snapshots contain no live fabric authority or cryptographic state.
- [ ] Archive commit and read-back verification precede purge.
- [ ] Archive records cannot be replayed as live commands.
- [ ] The feature does not consume the launch-performance budget.
- [ ] No security rule is weakened to meet a benchmark.
- [ ] No external service is introduced by this plan.
- [ ] No consensus library enters the `mvm` dependency graph.
- [ ] New security-sensitive crates use `#![forbid(unsafe_code)]` except for an
      already-established reviewed FFI leaf.
- [ ] No TODO, stub, fake receipt, unimplemented production branch, ignored
      error, or “best effort” audit is accepted as completion.

## Performance contract

| Measurement | Required release result |
| --- | ---: |
| prepared cold → `communication_ready` | p99 ≤ 200 ms |
| warm claim → `communication_ready` | p99 ≤ 50 ms |
| fabric enabled vs disabled cold delta | p99 ≤ 5 ms |
| fabric enabled vs disabled warm delta | p99 ≤ 2 ms |
| first local durable 1 KiB mailbox message | p99 ≤ 10 ms |
| commit → subscriber notification | p99 ≤ 5 ms |
| idle fabric CPU | no fixed polling |
| launch while archive/compaction workers are active | same launch gate |

Missing spans are not zero. Contaminated/degraded samples are refused.

## Initial hard bounds

- [ ] Pin message application ciphertext at or below 256 KiB.
- [ ] Pin functional frame ciphertext at or below 64 KiB.
- [ ] Pin local command batch at or below 4 MiB.
- [ ] Pin SQLite encoded row/BLOB at or below 1 MiB.
- [ ] Pin SQL statement text at or below 64 KiB.
- [ ] Pin mailboxes per VM at or below 32.
- [ ] Pin active subscriptions per VM at or below 32.
- [ ] Pin in-flight deliveries per ExclusiveInbox at or below 64.
- [ ] Pin functional streams per VM at or below 128.
- [ ] Pin delivery attempts with plan-bounded default 8.
- [ ] Make total shard/session bytes explicitly plan- and host-capped.
- [ ] Put every bound in one reviewed limits module and memory-ceiling formula.
- [ ] Reject rather than silently raise a bound.

## Workstream dependencies

```text
M0 inventory / baselines / models
  -> M1 contracts and codec
  -> M2 secure-channel convergence
  -> M3 guest message role + stdio adapters
  -> M4 deterministic SQLite state machine
  -> M5 local mailbox
  -> M6 functional streams
  -> M7 telemetry/input migration and old-plane removal
  -> M8 audit/tracing/inspection
  -> M9 archive and purge
  -> M10 mvmd apply contracts and simulator
  -> M11 adversarial qualification
  -> M12 performance / claims / docs
```

M4 may prototype internal storage after M1 while M2 is finishing, but no guest-
reachable fabric path may ship before M2.

---

## M0 — Reconcile specifications, inventory channels, model the state machine, and record baselines

### Repository and governance

- [ ] Record exact `origin/main`, branch, worktree, host, and supported backend
      matrix in the delivery note.
- [x] Numbering resolved: this plan's ADR is ADR-046, and the plan itself is
      slug-named per the current convention rather than carrying a number.
- [ ] Read current `CLAUDE.md`/`AGENTS.md` and repository workflow rules.
- [ ] Read ADRs 001, 014, 019, 020, 031, 035, 037, 040, 041, and 042.
- [ ] Read Plans 265, 267, 274, 293, 294, 295, 296, 299, 302, 308, 311, 314,
      315, 318, 319, 328, 329, and 330 where present.
- [ ] Inspect current workflow ADR/plan/research documents and record required
      message-fabric dependency edits.
- [ ] Add ADR-046 and this plan's cross-references to the current sprint/status
      documents without marking implementation complete.
- [ ] Read ADR-051 and treat its vocabulary decision as binding: this plan owns
      the messaging contract, and the workflow plan consumes it.

### Communication-channel catalog

- [ ] Add a machine-readable communication catalog under `model/` or the
      repository's current claims/config location.
- [ ] Catalog every guest→host service.
- [ ] Catalog every host→guest service.
- [ ] Catalog every guest control request path.
- [ ] Catalog stdout/stderr/structured-trace producers.
- [ ] Catalog input/stdin producers.
- [ ] Catalog every console/serial payload producer.
- [ ] Catalog host broker channels.
- [ ] Catalog networking/FlowMux channels.
- [ ] Catalog reader/listener endpoints.
- [ ] Catalog addon/substitution/port-forward channels.
- [ ] Catalog current `StreamEdge`/topology paths.
- [ ] Catalog every raw `read_frame`/`write_frame` helper and production caller.
- [ ] Catalog every direct post-connect `Read`/`Write`.
- [ ] Give each entry owner process/crate, direction, port/service, identity,
      encryption, parser, hard bounds, plan grant, payload visibility,
      retention, audit events, migration phase, and witness.
- [ ] Add `xtask check-communication-channel-catalog`.
- [ ] Make the check discover guest service/port enums and fail on uncataloged
      entries.
- [ ] Make the check discover new vsock listeners/connectors and fail on
      uncataloged entries.
- [ ] Make the check discover VMM console consumers/producers and fail on
      uncataloged entries.
- [ ] Make the check discover reader listeners and fail on uncataloged entries.
- [ ] Add a shrinking temporary allowlist for current raw paths.
- [ ] Add `xtask check-message-fabric-expansion-freeze`.
- [ ] Prove a planted new raw path fails the gate.

### Blast-radius ledger

- [ ] Add a component capability ledger covering:
      - workload SDK;
      - guest stdio adapter;
      - guest message role;
      - guest control role;
      - host secure-session endpoint;
      - local router;
      - shard/store worker;
      - audit signer;
      - archive worker;
      - reader gateway.
- [ ] Record untrusted inputs per component.
- [ ] Record plaintext availability per component.
- [ ] Record keys per component.
- [ ] Record filesystem paths per component.
- [ ] Record network destinations per component.
- [ ] Record process/syscall privileges per component.
- [ ] Record tenant/session/shard scope per component.
- [ ] Record maximum compromise consequence.
- [ ] Record recovery action and required witness.
- [ ] Fail documentation/claims checks when a component lacks a stated blast
      radius.

### Executable reference model

- [ ] Implement a pure model for session states.
- [ ] Implement a pure model for shard `CommitPosition`.
- [ ] Implement immutable payload/envelope revision identity.
- [ ] Implement message ready/inflight/complete/dead-letter states.
- [ ] Implement lease/ACK/NACK/expiry races.
- [ ] Implement sender high-water/equivocation rules.
- [ ] Implement functional stream open/append/complete/abort.
- [ ] Implement process crash and same-boot redelivery.
- [ ] Implement boot retirement.
- [ ] Implement close/archive/purge.
- [ ] Assert no ACK without valid lease.
- [ ] Assert no old boot or generation can consume or ACK.
- [ ] Assert no committed functional object disappears without final
      disposition.
- [ ] Assert no purge precedes archive commit.
- [ ] Assert no command at one position changes result on replay.
- [ ] Assert conflicting same-position command quarantines.
- [ ] Assert telemetry cannot mutate functional state.
- [ ] Assert Input cannot select execution/lifecycle state.

### Baselines and ownership decisions

- [ ] Extend performance reports with:
      `fabric_prepare`, `workload_fabric_keys`, `fabric_transport`,
      `fabric_binding`, `communication_ready`.
- [ ] Record at least 30 release samples after two warm-ups for fabric-disabled
      prepared-cold lanes on each available native backend.
- [ ] Record fabric-disabled warm-claim baseline.
- [ ] Record current control authentication latency.
- [ ] Record current host registration latency.
- [ ] Record current first stdout/stderr/input latency.
- [ ] Record current guest/host idle RSS and process/thread/FD counts.
- [ ] Record launch under current transcript sealing/maintenance work.
- [ ] Identify the resident host process that owns local router lifetime.
- [ ] Identify the process-supervision point for resident shard workers.
- [ ] Identify the archive scheduler owner.
- [ ] Decide platform-specific confinement for Linux.
- [ ] Decide platform-specific confinement for macOS.
- [ ] Mark unsupported platforms honestly where equivalent confinement cannot
      yet be settled.
- [ ] Decide separate secure sessions vs a fixed closed-lane multiplexer using
      measured handshake/launch evidence.
- [ ] Do not choose a generic dynamic multiplexer.

### Exit gate

- [ ] All byte-bearing paths are cataloged.
- [ ] New raw-path expansion is blocked.
- [ ] The blast-radius ledger is complete.
- [ ] The state model and planted-invariant tests are green.
- [ ] Raw baseline reports are committed.
- [ ] Resident ownership and platform confinement are explicit.
- [ ] No runtime behavior has changed.

---

## M1 — Define portable IDs, capabilities, lane contracts, commands, receipts, and bounded codecs

### Contract module

- [ ] Add `mvm_contract::fabric` with `#![forbid(unsafe_code)]`.
- [ ] Add fixed-size validated `SessionId`.
- [ ] Add `ConversationId`.
- [ ] Add `MessageId`.
- [ ] Add `PayloadCiphertextId`.
- [ ] Add `EnvelopeContentId`.
- [ ] Add `MailboxId`.
- [ ] Add `AttemptId`.
- [ ] Add `StreamId`.
- [ ] Add `DataGroupId`.
- [ ] Add `AssignmentGeneration`.
- [ ] Add `CommandId`.
- [ ] Add `CommitPosition`.
- [ ] Add `DeliveryToken`.
- [ ] Reuse or wrap existing W3C-shaped `TraceId`/`SpanId`.
- [ ] Give every fixed ID exact width, canonical display, checked parsing, and
      reserved-value rejection.
- [ ] Keep transport-free types `no_std + alloc` where possible.

### Lane and route contracts

- [ ] Define closed `FabricLane`.
- [ ] Define `MailboxAddress` with workload-only destination.
- [ ] Define `MailboxBinding`.
- [ ] Define `FunctionalStreamBinding`.
- [ ] Define `ArtifactBinding` references without implementing artifact storage.
- [ ] Define `TelemetrySource` for stdout, stderr, trace, early boot, and host-
      generated diagnostics.
- [ ] Define `InputTarget` limited to an admitted workload compatibility sink.
- [ ] Define protected `SystemEvent` with no guest serialization constructor.
- [ ] Replace conceptual `StreamEdge` topology with a pure typed route graph.
- [ ] Reject cycles for functional routes.
- [ ] Reject implicit fan-in.
- [ ] Reject telemetry/input edges in the functional graph.
- [ ] Reject physical VM/node/CID/path/fd addressing in bindings.

### Capabilities and identity

- [ ] Define `WorkloadFabricIdentity`.
- [ ] Define `MailboxSendCapability`.
- [ ] Bind capability to sender boot.
- [ ] Bind capability to recipient mailbox and boot.
- [ ] Bind capability to session/data group.
- [ ] Bind capability to assignment generation.
- [ ] Bind allowed schema IDs/versions.
- [ ] Bind size, expiry, lane, and continuity policy.
- [ ] Define `ExclusiveInboxGrant`.
- [ ] Define `InputGrant`.
- [ ] Define `TelemetryPolicy`.
- [ ] Define recipient-only and explicit recovery/investigation key-capsule
      policy.
- [ ] Reject cross-tenant capability use.
- [ ] Reject unknown issuer/key ID before interpreting granted fields.

### Message and stream envelopes

- [ ] Define immutable signed message header.
- [ ] Define CEK capsule roles.
- [ ] Define bounded padded ciphertext.
- [ ] Define payload and envelope content-ID domain separators.
- [ ] Define sender signature transcript.
- [ ] Define causation/correlation fields.
- [ ] Define TTL and creation bounds.
- [ ] Define envelope revision/supersession fields if rewrap is retained.
- [ ] Define functional stream open/frame/terminal records.
- [ ] Bind frame to request, attempt, stream, sequence, prior frame, boots, and
      generation.
- [ ] Define telemetry record metadata using retained ADR-035 semantics.
- [ ] Define Input record and delivery receipt.

### State-machine commands

- [ ] Define `ConversationCommand`.
- [ ] Define accept-message command.
- [ ] Define lease command.
- [ ] Define lease-extension command.
- [ ] Define ACK command.
- [ ] Define NACK/retry command.
- [ ] Define expire-lease command.
- [ ] Define dead-letter/requeue command.
- [ ] Define open/append/complete/abort functional-stream commands.
- [ ] Define telemetry-root/checkpoint command shape for future `mvmd`.
- [ ] Define session close/archive/purge commands.
- [ ] Define command results and stable error/refusal classes.
- [ ] Make commands deterministic: no implicit clock, randomness, filesystem,
      or environment reads during apply.
- [ ] Put leader/standalone-observed times and generated tokens explicitly in
      commands where needed.
- [ ] Validate generated tokens before apply.
- [ ] Define idempotent replay result storage.

### Binary codec

- [ ] Implement fixed prefix parsing before allocation.
- [ ] Use explicit network-byte-order reads/writes.
- [ ] Use checked integer arithmetic for all offsets and totals.
- [ ] Reject truncation and trailing bytes.
- [ ] Reject unknown major/minor versions according to exact compatibility
      policy.
- [ ] Reject unknown flags/opcodes/suites.
- [ ] Apply hard size cap before ciphertext allocation.
- [ ] Do not use Rust struct layout as wire layout.
- [ ] Do not put JSON/CBOR/Protobuf parser in the outer fabric infrastructure.
- [ ] Keep application payload opaque.
- [ ] Add golden cross-endian vectors.
- [ ] Add encode/decode canonicality tests.
- [ ] Add per-field tamper/content-ID tests.
- [ ] Add fuzz targets for all decoders.
- [ ] Add memory-ceiling formula for decoder and maximum in-flight buffers.

### Exit gate

- [ ] Contract crate passes no_std/wasm targets already required by the repo.
- [ ] Golden vectors and fuzz seeds are committed.
- [ ] Reference model consumes the same command types.
- [ ] No runtime caller exists yet.

---

## M2 — Converge every production guest/reader channel on one mandatory secure substrate

### Secure channel

- [ ] Add or isolate a focused secure-channel crate.
- [ ] Configure TLS 1.3 only.
- [ ] Require mutual authentication.
- [ ] Disable TLS 1.2.
- [ ] Disable 0-RTT.
- [ ] Disable anonymous mode.
- [ ] Disable permissive certificate verification.
- [ ] Disable key logging.
- [ ] Disable compression.
- [ ] Disable session resumption initially.
- [ ] Define closed service/ALPN enum for control, fabric, telemetry, input,
      broker, network, reader, and future node bridge.
- [ ] Add `RawTransport -> VerifiedSecureSession` typestate.
- [ ] Expose application framing only on verified sessions.
- [ ] Bind expected tenant/node/node-boot/VM/VM-boot/plan/generation/service.
- [ ] Add bounded session lifetime by time, bytes, frames, generation, and
      policy.
- [ ] Add application protocol sequence/channel binding for receipts.
- [ ] Provision boot-specific transport credentials before first application
      byte.
- [ ] Ensure warm parent snapshots contain no live transport credential.
- [ ] Keep transport keys separate from mailbox, audit, plan, and archive keys.
- [ ] Add wrong identity/service/boot/plan/generation/version tests.
- [ ] Add replay and exhaustion tests.
- [ ] Add handshake and first-frame microbenchmarks.

### Migrate existing channels

- [ ] Migrate guest control RPC.
- [ ] Migrate host broker RPC.
- [ ] Migrate stdout/stderr/trace transport.
- [ ] Migrate input transport.
- [ ] Migrate network-flow adapter required by ADR-042 without creating a
      second network path.
- [ ] Migrate addon/substitution/forwarding channels or make them refuse.
- [ ] Migrate reader gateway.
- [ ] Remove production raw frame helper visibility.
- [ ] Restrict raw helpers to test/fuzz configuration.
- [ ] Delete raw VMM console payload capture.
- [ ] Add encrypted early-boot diagnostic path or document the unavailable
      window.
- [ ] Update catalog entry and shrink allowlist in every migration PR.
- [ ] Add `xtask check-no-raw-guest-transport`.
- [ ] Add `xtask check-no-raw-console-payload`.
- [ ] Add planted bypass tests.
- [ ] Measure launch/auth delta after each channel migration.

### Exit gate

- [ ] Every catalog channel is secure or explicitly absent.
- [ ] No production raw helper or console payload path remains.
- [ ] Static gates and downgrade ladders are green.
- [ ] Pre-fabric launch performance remains inside budget.

---

## M3 — Add workload-owned keys, the ciphertext-only guest message role, and stdio adapters

### Workload keys

- [ ] Add workload-UID key bootstrap after fresh post-boot entropy.
- [ ] Generate independent signing and HPKE keys using reviewed library APIs.
- [ ] Avoid custom crypto solely to save startup time.
- [ ] Keep private keys under exact workload UID/trust domain.
- [ ] Keep keys out of control and message roles.
- [ ] Keep keys out of warm snapshots.
- [ ] Support workload process restart within one VM boot using UID-private
      volatile state.
- [ ] Zeroize keys at boot/session end.
- [ ] Register public keys through the secure local endpoint.
- [ ] Bind registration to plan, session, UID, VM boot, and generation.
- [ ] Emit signed/verified `WorkloadFabricIdentity`.
- [ ] Measure key/bootstrap latency concurrently with guest readiness.

### Guest message role

- [ ] Add a separate role in the existing guest executable or a separately
      packaged internal binary after M0 ownership review.
- [ ] Run under distinct UID.
- [ ] Prestart in `Unbound` state.
- [ ] Give it separate ALPN/service.
- [ ] Give it no control dispatcher.
- [ ] Give it no process handlers.
- [ ] Give it no filesystem-management handlers.
- [ ] Give it no mount handlers.
- [ ] Give it no shell/exec/plugin/runtime.
- [ ] Give it no E2E private keys.
- [ ] Give it no external network.
- [ ] Expose private `AF_UNIX/SOCK_SEQPACKET` workload endpoints.
- [ ] Enforce private parent directory and exact modes.
- [ ] Verify kernel peer credentials.
- [ ] Require workload session capability.
- [ ] Preserve exact ciphertext packet boundaries.
- [ ] Implement bounded credits/subscription protocol.
- [ ] Add Linux seccomp/Landlock/UID confinement.
- [ ] Add the strongest available macOS process/filesystem/network confinement
      and document residual differences.
- [ ] Add `xtask check-guest-message-role-closure`.
- [ ] Add static dependency fence against powerful guest-agent handlers.

### Stdio adapters

- [ ] Replace stdout pump boundary with `Telemetry` records.
- [ ] Preserve stdout vs stderr identity.
- [ ] Preserve byte ordering and partial writes.
- [ ] Do not infer severity from stderr.
- [ ] Preserve structured trace as distinct telemetry source.
- [ ] Replace raw input route with `Input` records.
- [ ] Preserve one writer and explicit EOF.
- [ ] Preserve secret fingerprint scanning and current policy limits.
- [ ] Ensure Input cannot select argv/process/lifecycle state.
- [ ] Ensure Telemetry cannot affect functional commands.
- [ ] Update CLI ergonomics without exposing raw boundary streams.
- [ ] Add `communication_ready` only after secure session, grants, public key
      registration, and local endpoint readiness.
- [ ] Skip message-role binding entirely when plan has no fabric grant.

### Exit gate

- [ ] A real workload can register keys and bind a private endpoint.
- [ ] stdout/stderr/input use typed lanes.
- [ ] Guest role confinement tests are green.
- [ ] No durable mailbox exists yet.

---

## M4 — Implement the deterministic hardened SQLite conversation state machine

### Crate and process boundary

- [ ] Add `mvm-message-fabric` or the verified role-named crate.
- [ ] Add `#![forbid(unsafe_code)]`.
- [ ] Implement `ConversationStateMachine`.
- [ ] Implement `StandaloneCommitter`.
- [ ] Implement `CommittedCommandSink` for future `mvmd`.
- [ ] Keep all consensus types behind `CommitPosition`; import no consensus
      library.
- [ ] Run SQLite in resident bounded shard workers.
- [ ] Shard by tenant/security domain and future `DataGroupId`.
- [ ] Ensure one worker cannot open arbitrary paths.
- [ ] Pre-open directory descriptors before confinement where supported.
- [ ] Limit sessions/bytes per worker.
- [ ] Make worker failure affect only its assigned shard.
- [ ] Add process supervision and deterministic recovery.

### Schema

- [ ] Add shard metadata and schema fingerprint.
- [ ] Add `last_applied`/command-result table.
- [ ] Add sessions and generation fences.
- [ ] Add workload/boot bindings.
- [ ] Add mailboxes and assignments.
- [ ] Add immutable payload ciphertext.
- [ ] Add envelope revisions/capsules.
- [ ] Add sender high-water/equivocation state.
- [ ] Add ready/inflight/dead-letter state.
- [ ] Add leases/delivery tokens.
- [ ] Add functional streams/attempts/frame indexes.
- [ ] Add telemetry/input roots and retained metadata.
- [ ] Add immutable audit outbox.
- [ ] Add archive/closure state.
- [ ] Add payload-free session tombstones.
- [ ] Use `STRICT` tables.
- [ ] Add exact ID-length checks.
- [ ] Add enum/range checks.
- [ ] Add ciphertext-length checks.
- [ ] Refuse wire `u64` beyond SQLite signed range.
- [ ] Store no plaintext body or key.

### SQLite posture

- [ ] Pin bundled SQLite/rusqlite versions.
- [ ] Compile out extension loading where possible.
- [ ] Disable trusted schema.
- [ ] Enable defensive mode.
- [ ] Disable DQS.
- [ ] Disable mmap.
- [ ] Enable foreign keys.
- [ ] Enable cell-size checks.
- [ ] Use WAL.
- [ ] Use synchronous FULL for acknowledged functional commits.
- [ ] Disable auxiliary SQLite workers.
- [ ] Refuse attached databases.
- [ ] Install post-migration authorizer.
- [ ] Permit only required static statements and tables.
- [ ] Keep all SQL as checked-in constants.
- [ ] Prepare every statement under the authorizer in tests.
- [ ] Set tight runtime limits for length, SQL, columns, variables, depth,
      instructions, heap, pages, and time.
- [ ] Derive `max_page_count` from admitted shard quotas.
- [ ] Verify SQLite compile options at startup.
- [ ] Reject symlinks/nonregular files/wrong owner/wrong mode/network FS.
- [ ] Require private directories and files.
- [ ] Run `quick_check` only on recovered existing shards before writes.
- [ ] Quarantine corruption; never auto-recreate over unproven state.

### Deterministic apply

- [ ] Apply command effect, `last_applied`, audit outbox, and replay result in
      one transaction.
- [ ] Replay same position/command returns stored result.
- [ ] Same position/different command quarantines.
- [ ] Reject position gaps unless snapshot installation explicitly advances.
- [ ] Never read wall clock/randomness/environment inside apply.
- [ ] Validate leader/standalone-provided token/time fields deterministically.
- [ ] Make message acceptance idempotent.
- [ ] Make ACK/NACK idempotent.
- [ ] Make terminal stream commands idempotent.
- [ ] Make close/archive/purge idempotent.
- [ ] Add typed disk-full/corruption/busy/timeout/refusal errors.
- [ ] Add failpoints at every SQLite transition boundary.

### Encryption and canaries

- [ ] Generate per-session storage DEK.
- [ ] Encrypt host-visible sensitive wrappers before store worker.
- [ ] Bind AEAD associated data to tenant/session/shard/object/boot/generation/
      sequence/key ID.
- [ ] Keep E2E ciphertext nested unchanged.
- [ ] Scan DB, WAL, SHM, temp, segments, errors, audit, and traces for plaintext
      canaries.
- [ ] Scan for private-key/CEK canaries.
- [ ] Prove no live-record eviction at capacity.

### Exit gate

- [ ] State machine passes schema, authorizer, corruption, disk-full, replay,
      conflict, canary, and failpoint tests.
- [ ] No guest can yet send a live mailbox message.

---

## M5 — Deliver local durable ExclusiveInbox mailboxes

- [ ] Implement `LocalFabricAuthority`.
- [ ] Persist monotonic local assignment generations.
- [ ] Issue local-development capabilities only.
- [ ] Implement local logical route resolution.
- [ ] Implement sender SDK CEK generation.
- [ ] Implement E2E payload encryption.
- [ ] Implement recipient key capsule.
- [ ] Implement optional explicit recovery/investigation capsule policy.
- [ ] Implement sender signature and content IDs.
- [ ] Validate capability before durable acceptance.
- [ ] Verify sender signature/content IDs before store.
- [ ] Commit message + dedup + mailbox sequence + audit outbox atomically.
- [ ] Return acceptance only after durable commit.
- [ ] Publish availability notification only after commit.
- [ ] Implement Exact `ExclusiveInbox` subscription.
- [ ] Implement bounded credits and prefetch.
- [ ] Implement lease command and random token generation before apply.
- [ ] Implement ACK.
- [ ] Implement NACK with bounded retry delay.
- [ ] Implement lease extension.
- [ ] Implement leader/standalone timer task that proposes explicit expiration
      commands.
- [ ] Implement TTL expiry.
- [ ] Implement dead letter.
- [ ] Implement explicit requeue.
- [ ] Detect sender sequence equivocation.
- [ ] Refuse stale consumer boot/generation.
- [ ] Refuse unsupported replicated durability rather than downgrade.
- [ ] Implement workload SDK decryption and bounded application decode.
- [ ] Implement same-boot process crash/restart redelivery.
- [ ] Implement boot retirement as explicit `recipient-key-retired` in the
      initial slice unless a separately reviewed rewrap phase is enabled.
- [ ] Keep sender-assisted rewrap behind its own checklist and threat review.
- [ ] Add local metadata-only inspection commands.
- [ ] Add two-real-microVM send/receive/ACK test.
- [ ] Add process crash and host shard-worker crash tests.
- [ ] Add stale snapshot/old boot tests.
- [ ] Measure first-message and commit-notification latency.

### Exit gate

- [ ] Local mailbox vertical slice works between real microVMs.
- [ ] Required crash matrix is green.
- [ ] No host component can read or execute payload.
- [ ] Latency gates pass.

---

## M6 — Add durable functional response streams and attempts

- [ ] Add reply mode `None`.
- [ ] Add unary reply.
- [ ] Add functional-stream reply.
- [ ] Generate stream CEK and capabilities.
- [ ] Define open/progress/data/error/complete/abort frames.
- [ ] Bind frames to request/attempt/stream/sequence/previous frame/boots/
      generation.
- [ ] Create new attempt and stream for redelivered request.
- [ ] Preserve partial failed attempt.
- [ ] Auto-renew request lease while a bounded response writer remains active.
- [ ] Store encrypted frames in append-only segment files.
- [ ] Index committed frames in SQLite.
- [ ] fsync segment according to durability before index/ack.
- [ ] Recover torn unindexed tail.
- [ ] Never silently drop functional frame.
- [ ] Apply bounded producer backpressure.
- [ ] Return explicit capacity/deadline failure.
- [ ] Add durable reader cursor/resume.
- [ ] Keep live UI queue bounded.
- [ ] On live queue gap, resume from durable store rather than lose data.
- [ ] Add Rust SDK `call`, `cast`, `call_stream`, `subscribe`, `ack`, `nack`.
- [ ] Correlate attempts with Telemetry/trace IDs.
- [ ] Add disconnect/resume/process-crash/new-attempt integration.
- [ ] Measure frame throughput and resume latency.

### Exit gate

- [ ] Functional streams are E2E encrypted, durable, resumable, and
      attempt-aware.
- [ ] Telemetry loss semantics are not used for functional data.

---

## M7 — Complete Telemetry/Input migration and remove the old workload stream plane

- [ ] Route every stdout source through `Telemetry`.
- [ ] Route every stderr source through `Telemetry`.
- [ ] Route structured traces through `Telemetry`.
- [ ] Route admitted operator input through `Input`.
- [ ] Preserve redaction seam before host persistence/fan-out.
- [ ] Preserve host-owned sequence/timestamp.
- [ ] Preserve per-reader bounded queues.
- [ ] Preserve explicit gap markers.
- [ ] Preserve hash-chain and sealed-root behavior.
- [ ] Preserve signed retention policy.
- [ ] Preserve no-payload audit entries.
- [ ] Preserve stdin one-writer/EOF behavior.
- [ ] Preserve secret-scan limitations honestly.
- [ ] Make telemetry unable to complete functional calls.
- [ ] Make stdout unusable as workflow result protocol.
- [ ] Delete `StreamEdge` DTOs after all consumers migrate.
- [ ] Delete stdout→stdin route implementation.
- [ ] Delete old direct input frame transport.
- [ ] Delete old stream-plane guest boundary protocol.
- [ ] Delete raw console fallback.
- [ ] Update CLI/help/errors to describe message fabric.
- [ ] Add migration errors for old plans/bindings.
- [ ] Update ADR-035 status/supersession note.
- [ ] Update Plans 293/294/295/296 status or add explicit historical pointers.
- [ ] Add static gate preventing reintroduction of stdio-as-protocol.
- [ ] Add compatibility tests for ordinary legacy process stdio inside guest.

### Exit gate

- [ ] One guest-boundary fabric remains.
- [ ] Process compatibility remains.
- [ ] No functional control/result path depends on stdout/stderr/stdin.

---

## M8 — Complete audit proofs, tracing, and operator inspection

- [ ] Define exhaustive transition→audit event matrix.
- [ ] Make transition functions require audit-outbox record.
- [ ] Add source acceptance receipt.
- [ ] Add durable commit receipt.
- [ ] Add lease receipt.
- [ ] Add final disposition receipt.
- [ ] Add functional stream terminal receipt.
- [ ] Add telemetry/input root references.
- [ ] Bind receipts to `CommitPosition`.
- [ ] Bind receipts to message/content/session/trace/generation/boot identities.
- [ ] Extend existing audit signer/checkpoint/Merkle machinery.
- [ ] Avoid synchronous asymmetric signature per low-level transition unless
      evidence shows it is required.
- [ ] Add independent reconciliation between shard high-water and signed audit
      high-water.
- [ ] Quarantine unexplained divergence.
- [ ] Add `xtask check-fabric-audit-totality`.
- [ ] Add `xtask check-fabric-no-payload-logging`.
- [ ] Project committed records to `tracing`.
- [ ] Add optional asynchronous authenticated OTLP export.
- [ ] Ensure collector outage never blocks launch/commit.
- [ ] Ensure full durable audit outbox fails closed for new security-sensitive
      transitions.
- [ ] Add CLI/API for conversation inspect/follow.
- [ ] Add message lifecycle/proof command.
- [ ] Add functional stream follow/resume command.
- [ ] Add trace show/export command.
- [ ] Audit every authorized content/archive read.
- [ ] Ensure metadata-only default output.

### Exit gate

- [ ] Every transition is provable without relying on a tracing subscriber.
- [ ] Standard tracing tools can analyze metadata safely.

---

## M9 — Implement logical archive-before-purge

- [ ] Implement session close generation fence.
- [ ] Refuse new sends/subscriptions/streams/input/attachments after fence.
- [ ] Drain or explicitly dispose every message.
- [ ] Resolve every lease.
- [ ] Close every functional stream with terminal state.
- [ ] Seal telemetry/input transcript roots.
- [ ] Drain audit outbox.
- [ ] Stop session writers.
- [ ] Flush/fsync segment files.
- [ ] Checkpoint/close shard connection safely without blocking unrelated
      sessions longer than bounded budget.
- [ ] Define canonical logical archive records.
- [ ] Prohibit record-supplied paths.
- [ ] Prohibit symlinks/executable bits/compression/nested archives.
- [ ] Include plans, identities, assignments, messages, revisions, receipts,
      streams, telemetry/input roots, gaps, high-water marks, retention, and
      completeness.
- [ ] Build content root and signed manifest.
- [ ] Reopen and stream-read every staged archive record.
- [ ] Verify every digest/signature/sequence/count/high-water/completeness field.
- [ ] Atomically commit archive.
- [ ] Persist archive receipt and audit entry.
- [ ] Delete session rows.
- [ ] Destroy active session storage DEK.
- [ ] Delete session segment files.
- [ ] Retain payload-free tombstone.
- [ ] Fsync affected directories.
- [ ] Make late retries return stable closed-session result.
- [ ] Add read-only bounded archive reader.
- [ ] Give archive reader no enqueue/lease/plan/control/exec/restore API.
- [ ] Audit archive access/export/delete/key use.
- [ ] Add retention/legal hold/key rotation/cryptographic deletion.
- [ ] Add low-priority scrub and repair receipts.
- [ ] Make archive/compaction yield to foreground launch.
- [ ] Add full archive crash matrix.

### Exit gate

- [ ] Verified archive exists before purge.
- [ ] Session key and active rows/segments are removed.
- [ ] Tombstone prevents resurrection.
- [ ] Archive cannot become live input.

---

## M10 — Publish the deterministic `mvmd` integration boundary and simulated replicated application

- [ ] Add data-only `mvm_core::mvmd_iface::fabric` contracts.
- [ ] Add `DataGroupDescriptor`.
- [ ] Add session→data-group assignment.
- [ ] Add workload binding.
- [ ] Add node/boot/generation fields.
- [ ] Add committed command envelope.
- [ ] Add commit/read/snapshot response types.
- [ ] Add telemetry shard closure receipt.
- [ ] Add local archive shard receipt.
- [ ] Keep all behavior out of DTOs.
- [ ] Use `deny_unknown_fields` where serde applies.
- [ ] Add exact protocol/contract version.
- [ ] Add `CommittedCommandSink`.
- [ ] Add `StateSnapshotInstaller`.
- [ ] Add `StateSnapshotExporter`.
- [ ] Add `LocalFabricAuthority` and `MvmdFabricAuthorityClient` trait boundary.
- [ ] Do not import OpenRaft/raft-rs/consensus types.
- [ ] Build a deterministic simulated three-replica driver in tests.
- [ ] Apply the same committed commands to three independent SQLite shard DBs.
- [ ] Verify identical results and state digests.
- [ ] Simulate duplicate command delivery.
- [ ] Simulate replay after crash.
- [ ] Simulate conflicting same-position corruption.
- [ ] Simulate snapshot export/install/catch-up.
- [ ] Simulate old VM boot and generation refusal.
- [ ] Produce cross-repo golden fixtures for `mvmd`.
- [ ] Document exact mvm crate/revision/version consumption policy.
- [ ] Update workflow Plan 332 to consume data-group/workload-binding contracts
      rather than invent routing.

### Exit gate

- [ ] `mvmd` can consume stable contracts and the state machine.
- [ ] No live distributed claim is made.
- [ ] Three simulated replicas converge byte-for-byte/logically.

---

## M11 — Adversarial, formal, crash, fuzz, and static qualification

- [ ] Compare randomized implementation histories against the reference model.
- [ ] Use concurrency model checking for commit→notification races.
- [ ] Model lease expiration vs ACK.
- [ ] Model close vs send.
- [ ] Model archive vs retry.
- [ ] Model worker crash vs replay.
- [ ] Add deterministic failpoint sweep across every apply transaction.
- [ ] Add segment crash sweep.
- [ ] Add archive crash sweep.
- [ ] Add process `SIGKILL` harness for guest role, workload, router, shard
      worker, audit worker, and archive worker.
- [ ] Fuzz secure pre-auth bounds.
- [ ] Fuzz fabric envelope.
- [ ] Fuzz local guest protocol.
- [ ] Fuzz command decoder.
- [ ] Fuzz state transitions.
- [ ] Fuzz archive reader.
- [ ] Add cross-tenant isolation and enumeration-oracle tests.
- [ ] Add stale snapshot/VM generation tests.
- [ ] Add metadata padding/no-compression tests.
- [ ] Add quota/poison/amplification tests.
- [ ] Add database symlink/hardlink/owner/mode/network-FS attacks.
- [ ] Add canary scans across all persistence/log/export/crash paths.
- [ ] Add `xtask check-fabric-no-host-execution`.
- [ ] Add `xtask check-fabric-payload-opacity`.
- [ ] Add `xtask check-fabric-static-sql`.
- [ ] Add `xtask check-fabric-sqlite-posture`.
- [ ] Add `xtask check-fabric-archive-inert`.
- [ ] Add dependency fence against shell/process/plugin/runtime/archive-
      extraction dependencies.
- [ ] Pin and audit TLS/HPKE/signature/SQLite dependencies.
- [ ] Run supply-chain/license/reproducibility gates.
- [ ] Document residual platform-specific confinement limits.

### Exit gate

- [ ] Models, fuzzers, failpoints, crash sweeps, static checks, and canary scans
      are green.
- [ ] Every ambiguity updates ADR-046 before claim promotion.

---

## M12 — Ratify performance, density, claims, documentation, and release posture

### Performance and density

- [ ] Run 30+ release samples after exactly two warm-ups for fabric disabled
      cold/warm lanes.
- [ ] Run matching fabric-enabled lanes.
- [ ] Enforce absolute and delta launch gates.
- [ ] Record secure handshake/key registration/binding spans independently.
- [ ] Benchmark message sizes 0 B, 1 KiB, 64 KiB, 256 KiB.
- [ ] Benchmark functional frame sizes 1 KiB and 64 KiB.
- [ ] Benchmark one producer/consumer and bounded concurrency.
- [ ] Benchmark durable group-commit behavior without early ACK.
- [ ] Measure router/shard-worker/guest-role RSS.
- [ ] Measure per-subscription/inflight/reader memory.
- [ ] Measure file descriptors, threads, page cache, and idle CPU.
- [ ] Run 1,000 create/use/crash/archive/purge cycles.
- [ ] Prove no monotonic memory/FD/disk-key leak.
- [ ] Run launch while archive seal/read-back/scrub/compaction is active.
- [ ] Publish honest backend support matrix.
- [ ] Keep unsupported Firecracker or other backend status explicit until its
      independent launch SLO passes.

### Claims and docs

- [ ] Update ADR-001 threat model and claims ledger.
- [ ] Update ADR-035 supersession.
- [ ] Update ADR-019 readiness semantics.
- [ ] Update ADR-020 service boundaries.
- [ ] Update ADR-031 narrow SQLite revisit.
- [ ] Update ADR-037/040/041 cross-repo ownership references.
- [ ] Update ADR-042 secure network service reference.
- [ ] Reconcile Plans 293/294/295/296.
- [ ] Reconcile capability-secure workflow ADR/Plan 332.
- [ ] Add SDK documentation.
- [ ] Add delivery/idempotency documentation.
- [ ] Add stdio migration guide.
- [ ] Add tracing/OTLP guide.
- [ ] Add archive/investigation guide.
- [ ] Add local-vs-hosted support matrix.
- [ ] Add performance evidence document.
- [ ] Add BDD user scenarios.
- [ ] Update sprint/refactor/delivery records.
- [ ] Complete independent crypto review.
- [ ] Complete independent application-security review.
- [ ] Resolve or explicitly block on every review finding.
- [ ] Promote claims only after machine witnesses exist.

## Required validation commands

Use current repository equivalents and update this plan rather than silently
skipping a gate.

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo nextest run --workspace
cargo test --workspace --doc
cargo clippy --workspace --all-targets -- -D warnings
```

As checks land:

```bash
cargo run -p xtask -- check-communication-channel-catalog
cargo run -p xtask -- check-message-fabric-expansion-freeze
cargo run -p xtask -- check-no-raw-guest-transport
cargo run -p xtask -- check-no-raw-console-payload
cargo run -p xtask -- check-guest-message-role-closure
cargo run -p xtask -- check-fabric-no-host-execution
cargo run -p xtask -- check-fabric-payload-opacity
cargo run -p xtask -- check-fabric-static-sql
cargo run -p xtask -- check-fabric-sqlite-posture
cargo run -p xtask -- check-fabric-audit-totality
cargo run -p xtask -- check-fabric-archive-inert
```

## Recommended PR sequence

1. ADR/plan, channel catalog, expansion freeze, model, blast-radius ledger,
   benchmark vocabulary, raw baselines.
2. Contract IDs, commands, capabilities, codec, golden vectors, fuzz seeds.
3. Secure-channel substrate and credential identity.
4. Channel-by-channel migration and console removal.
5. Workload keys, guest message role, stdio adapters.
6. Hardened deterministic SQLite state machine.
7. Local mailbox lifecycle.
8. Functional streams.
9. Telemetry/input migration and old stream-plane deletion.
10. Audit/tracing/inspection.
11. Archive/purge.
12. `mvmd` apply contracts and simulated replicas.
13. Adversarial qualification.
14. Performance/claims/docs/review.

## Definition of done

- [ ] Every checkbox in this plan is complete with evidence.
- [ ] ADR-046 and implementation agree.
- [ ] One local guest-boundary fabric remains.
- [ ] Stdio is guest-local compatibility only.
- [ ] Two real microVMs communicate through durable E2E encrypted messages.
- [ ] Functional streams are durable/resumable.
- [ ] SQLite is shard-local, hardened, ciphertext-only, and deterministic.
- [ ] State-machine commands are reusable by `mvmd`.
- [ ] Archive-before-purge is crash-safe.
- [ ] Performance gates pass.
- [ ] No distributed capability is overclaimed.
- [ ] No placeholder, TODO, ignored error, or undocumented degradation remains.

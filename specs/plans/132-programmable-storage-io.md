# Plan 132 - Programmable storage and I/O substrate

> **Status:** proposed — **post-rewrite / future.** Builds on the rewrite's storage seams; it does not replace them. Layers *under* Plan 123's `StorageProvider`/`MountProvider` and reuses Plan 122's `mvm_core::crypto::aead` (so `EncryptionTransform` is one transform in the chain, not a second crypto path). The one bounded piece that fits 123's trait without the transform-chain machinery — a `compressed-ephemeral` StorageProvider impl — is tracked as a deferred follow-up in Plan 123; the rest (typed block vocabulary, composable transforms, userspace block device) stays here.
> **Renumbered:** 109 → 132 (2026-06-01) to clear the slot-109 collision with the live `109-zig-pid0-exploration.md`. **When picked up:** re-check the proposed `ADR-052` + the four `specs/contracts/*-v1.yaml` numbers against the consolidated ADR set (the rewrite curated ADRs to ~20), and reframe the phases to *extend* 123/122 rather than reinvent storage/crypto.
> **Owner:** TBD
> **Started:** -
> **Depends on:** ADR-002, ADR-041, ADR-048, ADR-049, ADR-050, plans 45, 58, 61, 67, 76
> **Implements:** typed block request contracts, safe storage transforms, compressed ephemeral volumes, plan-bound storage policy, guest storage status, gated Linux-only userspace block-device spike
> **Tracking:** storage programmability without weakening mvm's Firecracker / dm-verity / vsock-only security baseline

## Why

mvm already has strong runtime and policy semantics: signed plans,
verified root filesystems, guest-agent capability negotiation,
filesystem RPC policy, volume backends, seccomp, and backend security
profiles. What it does not yet expose is a programmable storage and
I/O substrate beneath those policies.

The current storage model is mostly file/object oriented:

- `mvm-storage::VolumeBackend` defines put/get/list/delete/stat/rename
  plus a local export path.
- guest volume attach/mount logic validates mount paths and then uses
  host-provided volumes.
- runtime overlays, verity sidecars, snapshots, and config/secret
  drives exist as separate implementation paths.

That is enough for baseline volumes. It is not enough for the next
storage surfaces we are likely to want:

- compressed ephemeral scratch volumes for sandboxes and build jobs;
- read-only-after-boot volumes;
- write-journaled volumes with bounded replay;
- verity-checked data volumes;
- tenant-key encrypted volumes with explicit audit posture;
- cache volumes whose contents are scoped to a tenant or workload;
- future Linux-only userspace block-device experiments.

This plan adds that substrate incrementally. Security is the primary
constraint: no programmable storage feature may create a cross-tenant
cache leak, weaken verified boot, bypass guest-agent policy, expose
secrets through compression or deduplication side channels, or expand
the host kernel attack surface without explicit experimental gating.

## Security priorities

Hard rules:

1. **No arbitrary user code in the host storage path.** Users may
   select declared transforms and policies; they may not provide code
   that executes in the host process, storage server, builder VM, or
   hypervisor control path.
2. **No global cross-tenant dedupe.** Zero-page and same-page handling
   are allowed because they do not compare tenant data against other
   tenants. Content-defined dedupe across tenants is forbidden unless a
   later ADR proves it does not leak information.
3. **Secret-bearing volumes disable unsafe optimization by default.**
   If a volume may contain secrets, the default posture is encrypted,
   tenant-scoped, and no shared compression dictionary or cross-volume
   dedupe.
4. **Kernel-facing I/O is experimental until proven.** Any `io_uring`,
   userspace block device, direct virtqueue, or Linux block-layer path
   is feature-gated, Linux-only, builder-VM-tested, and off by default.
5. **dm-verity remains authoritative for sealed roots.** Storage
   transforms may support data volumes and overlays, but they must not
   silently replace or bypass the verified-rootfs contract.
6. **All transform chains fail closed.** Unknown transform names,
   unknown versions, missing policy, missing key material, missing
   verity metadata, or unsupported backend capabilities reject the
   launch.
7. **Control plane stays small.** Guest-agent control frames do not
   carry large block or file payloads. Large data uses bounded
   streaming, backend transfers, or mounted data-plane paths.
8. **Every mutating storage decision is auditable.** Audit records
   include tenant/workload/volume identifiers, policy id, transform
   ids, backend kind, and artifact digest where applicable. They never
   include bytes, secret values, keys, or unredacted credentials.

## Non-goals

- No replacement for Firecracker, libkrun, Apple Container, or any
  existing backend.
- No host Docker daemon, container storage driver, or Docker volume
  dependency.
- No unreviewed kernel module, eBPF program, FUSE daemon, or block
  server in the production path.
- No arbitrary filesystem plugin ABI in the first version.
- No production userspace block device until live Linux gates, fuzzing,
  teardown tests, and a security review are complete.

## Whole-plan acceptance criteria

When this plan is done:

1. mvm has a typed block request/result model with overflow-safe sector
   and byte arithmetic.
2. mvm has a storage transform contract that supports safe, declared
   transform chains.
3. at least one compressed ephemeral volume backend ships behind a
   policy-controlled surface with tenant isolation tests.
4. storage policy is representable in signed execution plans and
   audited at admission and launch.
5. secret-bearing volumes default to encryption and no shared
   compression or dedupe behavior.
6. guest-agent volume/status calls negotiate explicit capabilities and
   never stream unbounded block data through control frames.
7. all storage backends pass shared conformance tests, including
   redaction and cross-tenant denial checks where applicable.
8. any Linux kernel-facing storage path remains experimental until the
   Linux builder-VM gate, fuzz gate, teardown gate, and security review
   are all green.
9. public docs distinguish file/object volumes, block-like volumes,
   compressed ephemeral volumes, verified volumes, and experimental
   Linux device paths.

## Phase checklist

- [ ] Phase 0 - ADR and contract specs
- [ ] Phase 1 - Typed block vocabulary
- [ ] Phase 2 - Transform chain contract
- [ ] Phase 3 - Compressed ephemeral volume backend
- [ ] Phase 4 - Plan and policy integration
- [ ] Phase 5 - Guest capability and status surface
- [ ] Phase 6 - Live guest attach path
- [ ] Phase 7 - Integrity, encryption, and journaling transforms
- [ ] Phase 8 - Experimental Linux userspace block-device spike
- [ ] Phase 9 - Benchmarking and backpressure
- [ ] Phase 10 - Documentation and claim gates

---

## Phase 0 - ADR and contract specs

**Progress:** `- [ ]`

### Goal

Record the security boundary and typed contracts before implementation.

### Deliverables

- `specs/adrs/052-programmable-storage-io.md`
- `specs/contracts/block-transform-v1.yaml`
- `specs/contracts/volume-policy-v1.yaml`
- `specs/contracts/ephemeral-compressed-volume-v1.yaml`
- `specs/contracts/kernel-storage-experimental-v1.yaml`

### Required decisions

- transform chain ordering rules;
- whether transforms are allowed on rootfs, overlay, volumes, or only
  specific storage classes;
- tenant cache scope model;
- secret-bearing volume classification;
- policy serialization shape;
- what telemetry is safe by default.

### Exit criteria

- [ ] ADR accepted.
- [ ] Contract files land.
- [ ] Threat model explicitly covers confidentiality, integrity, and
      availability risks from programmable storage.

---

## Phase 1 - Typed block vocabulary

**Progress:** `- [ ]`

### Goal

Add storage primitives without touching Linux kernel APIs.

### Scope

Add a new module such as `crates/mvm-storage/src/block.rs` containing:

- `Sector`
- `SectorCount`
- `SectorRange`
- `BlockOp`
- `BlockRequest`
- `BlockCompletion`
- `BlockError`
- `QueueId`
- `RequestTag`

### Requirements

- sector size is explicit, defaulting to 512 bytes;
- byte offset and length conversion uses checked arithmetic;
- zero-length requests are rejected unless the operation explicitly
  allows them;
- all range math rejects overflow;
- errors classify retriable, resource-exhaustion, integrity, policy,
  caller-bug, and backend-failure cases.

### Exit criteria

- [ ] Unit tests cover arithmetic edge cases at `u64::MAX`.
- [ ] Proptests cover offset and length conversion.
- [ ] Serde roundtrips exist for plan-facing public types.

---

## Phase 2 - Transform chain contract

**Progress:** `- [ ]`

### Goal

Make storage behavior programmable by declared, reviewed transforms.

### Scope

Add a transform contract, likely in `crates/mvm-storage/src/transform.rs`.

Initial transforms:

- `BoundsTransform`
- `ReadOnlyTransform`
- `AuditTransform`
- `ZeroPageTransform`
- `TenantScopeTransform`
- `NoSecretsCompressionTransform`

### Requirements

- transform order is deterministic and recorded in audit;
- unknown transform id fails closed;
- unknown transform version fails closed;
- transform chain is bound into the signed execution plan;
- runtime may further restrict transform chains but may not widen them.

### Exit criteria

- [ ] Transform ordering tests exist.
- [ ] Unknown transform denial tests exist.
- [ ] Audit event shape and redaction tests exist.
- [ ] Existing `VolumeBackend` conformance tests still pass.

---

## Phase 3 - Compressed ephemeral volume backend

**Progress:** `- [ ]`

### Goal

Ship the first useful programmable storage backend without kernel APIs.

### Scope

Implement a per-volume compressed ephemeral backend in userspace with:

- page table keyed by page index;
- unwritten pages read as zero;
- zero pages stored as metadata;
- same-byte pages stored as metadata;
- optional compression using a maintained crate;
- memory cap enforced before accepting writes;
- discard support;
- stats snapshot;
- reset and teardown support.

### Security requirements

- tenant-scoped by construction;
- no cross-tenant or cross-volume dedupe;
- no shared compression dictionary;
- secret-bearing volumes default to compression disabled unless policy
  explicitly allows a safe encrypted posture;
- stats for secret-bearing volumes default to coarse counters only.

### Exit criteria

- [ ] Backend contract fixture exists and passes.
- [ ] Tenant-isolation tests exist.
- [ ] Secret-bearing policy disables unsafe optimization by default.
- [ ] Reset and teardown tests prove data is cleared.

---

## Phase 4 - Plan and policy integration

**Progress:** `- [ ]`

### Goal

Bind storage behavior into admission instead of leaving it as an
implementation detail.

### Scope

Touch likely includes:

- `crates/mvm-plan/src/types.rs`
- `crates/mvm-policy/src/policies.rs`
- execution-plan signing and admission verification

New concepts likely include:

- `VolumePolicyRef`
- `VolumeTransformSpec`
- `StorageClass`
- `SecretBearing`
- `CacheScope`
- `IntegrityMode`
- `TelemetryLevel`

### Requirements

- production sealed root requires verity metadata;
- secret-bearing volume requires approved secret posture;
- compression is rejected for secret-bearing volumes unless policy
  explicitly allows it;
- cache scope must be tenant or workload for private artifacts;
- transform chain in the signed plan must match runtime launch
  behavior.

### Exit criteria

- [ ] Storage policy is part of plan verification.
- [ ] Tampered transform-chain tests fail verification.
- [ ] Missing backend capability fails admission.
- [ ] Backward-compatible defaults exist for newly added fields.

---

## Phase 5 - Guest capability and status surface

**Progress:** `- [ ]`

### Goal

Expose storage readiness and capability state without widening the
guest control plane.

### Scope

Potential additions:

- `GuestCapability::StorageStatus`
- `GuestRequest::StorageStatus`
- typed status response for mounted volumes, backend kind, policy id,
  transform ids, integrity mode, coarse usage, readiness, and last
  error category

### Requirements

- no volume contents in status;
- no raw secret paths or keys in status;
- status is read-only and production-safe;
- large data never moves through this request;
- missing capability fails before dispatch.

### Exit criteria

- [ ] Protocol roundtrip tests exist.
- [ ] `deny_unknown_fields` rejection tests exist.
- [ ] Redaction tests exist.
- [ ] `mvmctl status` or JSON status can report storage readiness.

---

## Phase 6 - Live guest attach path

**Progress:** `- [ ]`

### Goal

Connect policy-bound storage classes to guest-visible volumes.

### Requirements

- compressed ephemeral volume can be provisioned for a VM;
- guest mount path remains constrained by existing mount path policy;
- read-only and integrity modes are reflected in guest mount behavior;
- teardown removes host state;
- orphan cleanup has a bounded retry path.

### Exit criteria

- [ ] Mount allowed-path tests exist.
- [ ] Mount denied-path tests exist.
- [ ] Read-only write rejection is enforced.
- [ ] Teardown after failed launch is covered.
- [ ] Linux live smoke is gated in the builder VM when needed.

---

## Phase 7 - Integrity, encryption, and journaling transforms

**Progress:** `- [ ]`

### Goal

Add security transforms only after the transform contract has proven
stable.

### Candidate transforms

- `EncryptionTransform`
- `VerityReadTransform`
- `WriteJournalTransform`
- `ReplayProtectedJournalTransform`
- `QuotaTransform`
- `RateLimitTransform`

### Requirements

- keys use existing key-provider and secret-posture rules;
- encrypted data never exposes plaintext in cache keys, paths, audit,
  logs, or stats;
- verity failures are distinct from I/O errors;
- journal replay is bounded and idempotent;
- quota errors are fail-closed and auditable.

### Exit criteria

- [ ] Encrypt/decrypt roundtrip tests exist.
- [ ] Wrong-key and tampered-ciphertext tests exist.
- [ ] Verity mismatch rejection tests exist.
- [ ] Journal crash/replay tests exist.
- [ ] Redaction tests cover all failure paths.

---

## Phase 8 - Experimental Linux userspace block-device spike

**Progress:** `- [ ]`

### Goal

Evaluate whether a Linux userspace block path is worth adding, without
creating a production commitment.

### Gate

This phase must not start until Phases 0-4 are complete.

### Feature gate

- Cargo feature: `storage-ublk-experimental`
- Linux only
- runtime target: builder VM or native Linux with explicit opt-in
- production default: off

### Scope

- one scratch-volume prototype;
- bounded queue depth;
- bounded request size;
- bounded in-flight bytes;
- deterministic teardown;
- no rootfs path;
- no secret-bearing volume path;
- no public docs claim beyond `experimental`.

### Exit criteria

- [ ] Request parser fuzzing exists.
- [ ] Invalid-op and invalid-range tests exist.
- [ ] Queue-full and forced-teardown tests exist.
- [ ] Repeated create/destroy loop test exists.
- [ ] Live Linux smoke runs only behind the builder-VM gate.
- [ ] A spike report records whether to abandon, continue experimental,
      or design a production ADR.

---

## Phase 9 - Benchmarking and backpressure

**Progress:** `- [ ]`

### Goal

Make performance observable without turning it into an unsupported
claim.

### Metrics

- logical bytes read/written;
- physical bytes stored;
- compression ratio;
- memory used;
- queue depth;
- in-flight bytes;
- latency p50/p95/p99 for read/write/flush/discard;
- backpressure reason;
- integrity-failure count;
- policy-denial count.

### Exit criteria

- [ ] Benchmark report format exists.
- [ ] Backpressure reasons are typed and documented.
- [ ] Secret-bearing detailed telemetry stays off by default.
- [ ] No latency claim is made without a recorded benchmark path.

---

## Phase 10 - Documentation and claim gates

**Progress:** `- [ ]`

### Goal

Ship docs that are precise enough for users and strict enough for
release review.

### Required docs

- `public/src/content/docs/reference/filesystem.md`
- `public/src/content/docs/reference/architecture.md`
- `public/src/content/docs/guides/config-secrets.md`
- `public/src/content/docs/guides/manifests.md`
- a storage guide if the docs structure warrants it

### Claim rules

- `programmable storage` may only refer to declared transform chains,
  not arbitrary host plugins;
- `compressed` must say whether the volume is secret-bearing-safe;
- `verified` must identify the metadata being verified;
- `encrypted` must identify key scope and redaction posture;
- `kernel-backed` must remain experimental until Phase 8 exits with a
  production ADR.

### Exit criteria

- [ ] Docs match code.
- [ ] Claim-gating rules are updated if new phrases are introduced.
- [ ] `specs/SPRINT.md` reflects the new status when work begins.

## Suggested PR breakdown

1. ADR plus contract specs.
2. Block vocabulary plus arithmetic tests.
3. Transform trait plus initial safe transforms.
4. Compressed ephemeral backend plus contract fixture.
5. Plan/policy integration plus signed-plan binding.
6. Guest status and capability surface.
7. Live attach path for non-kernel backend.
8. Encryption, integrity, and journaling transforms.
9. Experimental Linux userspace block-device spike.
10. Benchmarks, docs, and claim gates.

## Open questions

- Should compressed ephemeral volumes live in `mvm-storage` only, or
  should a smaller crate own block vocabulary?
- Should transform policy bind into `ExecutionPlan` directly or via a
  referenced policy bundle?
- Which volume classes are allowed in sealed production images first?
- Should secret-bearing classification be inferred from policy or
  explicitly declared and then enforced by policy?
- How much per-volume telemetry is safe to expose by default?
- Should object-store backends support a block adapter, or remain
  API-only until a later plan?

## Definition of done

This plan is complete only when:

- [ ] All phases above are checked complete in this file.
- [ ] `cargo test --workspace` passes.
- [ ] `cargo check --workspace` passes.
- [ ] Linux builder `cargo clippy --workspace --all-targets -- -D warnings`
      passes before merge for Linux-gated paths.
- [ ] Security tests cover positive and negative paths for every
      transform.
- [ ] Docs and public claims match shipped status.
- [ ] No production path depends on experimental kernel-facing storage.

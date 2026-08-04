# Plan 292 — Tiered artifact storage and warm-start acceleration

> **Status:** Proposed.
>
> This plan is a storage and performance follow-up to the existing warm-start
> and production object-store work. It does not replace the checkpoint lineage,
> the `mvm`/`mvmd` volume contract, or the vsock-only workload boundary.

## Goal

Make `mvm` fast on the common local hot path while allowing `mvmd` to retain
large, inactive, and recoverable artifacts in encrypted object storage.

The target architecture has four properties:

1. A warm claim uses a clean local factory parent, a fresh child identity, and
   local CoW materialization. Object storage is not on the warm-start critical
   path.
2. Immutable rootfs, runtime-overlay, checkpoint, and volume data are stored as
   content-addressed manifests over chunks, rather than as unstructured large
   blobs.
3. `mvm`/`mvm-hostd` own local attachment, verification, hot caching, and guest
   enforcement. `mvmd` owns tenant provider construction, remote encryption,
   key orchestration, reconciliation, and cold-tier retention.
4. Every remote restore is explicitly slower than a hot restore when it has a
   cache miss, and every durability, confidentiality, and rollback property is
   observable and testable.

The motivating external design demonstrates that low-latency writes come from a
replicated hot tier, while object storage is used asynchronously for cold data.
Its page cache, chunk grouping, background tiering, and rehydration model are
the useful ideas to adapt. The direct SQLite VFS, generic FUSE filesystem, and
remote storage on the synchronous write path are not part of this plan.

## Existing boundaries and reuse requirements

This plan must compose with the following existing decisions:

- Plan 255 owns the `SnapshotStore` storage primitive, memory-snapshot file
  handling, warm-pool substrate, and fork identity hygiene.
- Plan 265 owns backend-specific restore safety, page-cache priming, density,
  warm-start SLOs, restore witnesses, and competitive benchmarks.
- Plan 283 owns the production `mvm`/`mvmd` volume contract and the remote
  `object_store` implementation.
- `mvm-fs` owns CoW/reflink/sparse-copy and chunk materialization primitives.
- `mvm-runtime` owns checkpoint lineage, parent verification, warm-pool
  lifecycle, admission, and restore orchestration.
- `mvm-hostd` owns host-side authorization, audit, and workload enforcement.
- `mvmd` owns multi-tenant provider access, remote encryption, and fleet
  reconciliation.

Do not introduce a second snapshot graph, a second remote-provider stack, a
third product feature taxonomy, or a general-purpose object-store filesystem.

The existing content-addressed store already deduplicates immutable blobs and
publishes them atomically. The existing warm-snapshot bridge already verifies
content and lineage before materialization. The new work extends those seams;
it does not fork them.

## Non-goals

- Do not put S3/GCS/Azure/R2 access in the guest.
- Do not make object storage a POSIX filesystem exposed through FUSE.
- Do not put remote object storage on the synchronous warm-claim path.
- Do not reuse a dirty guest as a new workload.
- Do not add SQLite, libSQL, or another embedded database to `mvm` state,
  checkpoint lineage, or audit storage.
- Do not globally deduplicate sensitive tenant data when equality would reveal
  cross-tenant information.
- Do not make remote memory snapshots part of the warm-start SLO until their
  confidentiality and backend-compatibility contracts are complete.
- Do not claim that a cache miss has near-memory latency.
- Do not change the signed `mvm`↔`mvmd` wire shape without a coordinated,
  byte-identity-preserving cross-repository change.

## Target architecture

```text
                         mvmd
      provider access, tenant keys, reconciliation
                              |
                encrypted manifests and chunks
                              |
                    remote object storage

  mvm / mvm-hostd

  clean factory parent -> fresh child -> guest
          |
     local hot cache
          |
  local SnapshotStore / VolumeBackend
          |
  remote rehydration only on cold recovery or cache miss
```

The warm path is:

```text
claim local parent
  -> verify parent content and signed lineage
  -> CoW materialize local immutable artifacts
  -> assign fresh child identity
  -> restore under the no-NIC guard
  -> reapply confinement
  -> establish a fresh authenticated vsock session
  -> deliver the first workload RPC
```

The cold path is:

```text
resolve authorized manifest
  -> fetch encrypted chunks into private staging
  -> verify manifest and ciphertext digests
  -> decrypt and authenticate
  -> verify plaintext digests and compatibility
  -> fsync and atomically publish locally
  -> attach or restore
```

The cold path must never silently fall through to an unverified local cache
entry or silently downgrade a requested durability level.

## Phase 0 — Freeze the contracts and baselines

### 0.1 Define the latency dimensions

- [ ] Add a benchmark contract covering cold boot, warm claim, first
      authenticated RPC, local cache hit, local cache miss, remote rehydration,
      checkpoint upload, checkpoint restore, and concurrent claims.
- [ ] Record p50, p95, and p99 for every phase, not only total elapsed time.
- [ ] Separate Firecracker/VMM process startup, snapshot load, device-model
      verification, guest readiness, and first-RPC handshake in the timing
      output.
- [ ] Run the same benchmark on the supported Linux/KVM and macOS backend
      environments where the path is available.
- [ ] Record artifact size, memory size, backend version, kernel digest,
      initramfs digest, CPU count, host memory, filesystem, object-store
      provider, region, and network distance with every result.
- [ ] Keep the local warm-start SLO separate from the cold remote-recovery SLO.

The existing warm-start target remains p50 ≤30 ms and p99 ≤50 ms. The latest
documented release measurements are p50 35–36 ms, so the plan must continue to
optimize the local path rather than hide the gap behind remote caching.

### 0.2 Define durability modes

- [ ] Specify the acknowledgement boundary for local staged, locally durable,
      remotely committed, and fully replicated data.
- [ ] Include the selected durability mode in checkpoint and volume operation
      results.
- [ ] Refuse an operation when the requested mode cannot be satisfied; never
      report success merely because an asynchronous upload was queued.
- [ ] Add crash tests for every acknowledgement boundary.

### 0.3 Freeze compatibility inputs

- [ ] Enumerate the fields that make an artifact restore-compatible: artifact
      kind, architecture, backend, VMM version, kernel, initramfs, runtime
      overlay, device model, memory size, page size, guest-agent protocol, and
      volume attachment shape.
- [ ] Bind those inputs to the artifact manifest and refuse incompatible
      restores before VMM start or guest attachment.
- [ ] Include the universal-initramfs digest and runtime-overlay version in the
      restore compatibility check.
- [ ] Define a versioned manifest format and a mixed-version rollout policy.

### 0.4 Ownership and dependency gates

- [ ] Keep cloud-provider construction and tenant credentials out of `mvm`.
- [ ] Extend the dependency-light `mvm-volume-contract` only when the remote
      behavior requires a cross-repository contract change.
- [ ] Keep the default `mvm-protocol` closure free of object-store clients and
      async runtime dependencies.
- [ ] Add a structural gate that rejects a second provider stack or a remote
      volume implementation that bypasses the canonical contract.

**Phase 0 acceptance:** benchmark schema and durability semantics are written,
compatibility inputs are fixed, and dependency ownership is enforced before
any chunking or remote-tier implementation begins.

## Phase 1 — Complete the local hot path

This phase belongs with the active warm-start work and must land before remote
tiering is used to make performance claims.

### 1.1 Running VMM pool

- [ ] Distinguish a saved checkpoint pool from a pool of already-running VMM
      processes in the capability model.
- [ ] Keep compatible Firecracker processes pre-spawned and ready to claim.
- [ ] Claim a running VMM without starting a new Firecracker process on the
      request path.
- [ ] Ensure every pool slot is a clean, authority-free factory parent.
- [ ] Replenish, quarantine, and evict slots under explicit memory, count, and
      age budgets.
- [ ] Make pool shutdown and worker drain release or persist slots safely.

### 1.2 Restore and fork hygiene

- [ ] Assign a fresh VM identity, boot ID, session nonce, generation ID, and
      per-instance writable state for every child.
- [ ] Require a fresh signed and admitted execution plan for every workload
      child.
- [ ] Reapply seccomp, landlock, uid/gid, jailer, resource, and device policy
      after restore.
- [ ] Establish a fresh authenticated vsock handshake and reject stale flows.
- [ ] Refuse any attempt to promote a factory parent directly to a workload.
- [ ] Keep the no-NIC device-model guard between restore and guest execution.

### 1.3 Verified page-cache priming

- [ ] Prime only the read-only, dm-verity-sealed rootfs and immutable runtime
      overlay.
- [ ] Reject priming requests for writable volumes, secrets, mutable overlays,
      or data associated with a prior workload.
- [ ] Make priming identity-aware so a tenant cannot request another tenant’s
      cached pages.
- [ ] Add a live witness that a primed artifact remains bound to its verified
      digest and verity root.

### 1.4 Local performance gates

- [ ] Add a reproducible live warm-claim benchmark rather than relying only on
      an ignored in-crate timing test.
- [ ] Gate warm claim p50/p99 independently from cold boot.
- [ ] Report cache-hit ratio, parent-pool occupancy, claim queue time, and
      restore failure rate.
- [ ] Do not publish a warm-start result unless the positive live boot path,
      post-restore handshake, and all security witnesses pass.

**Phase 1 acceptance:** the local warm path is faster than cold boot, has a
measured p50/p99 result, passes restore security witnesses, and does not depend
on remote object storage.

## Phase 2 — Add chunked local artifacts in `mvm-fs`

### 2.1 Manifest and chunk types

- [ ] Add a versioned artifact-manifest type in the storage owner selected by
      the existing dependency direction.
- [ ] Represent large immutable artifacts as ordered chunks with digest,
      plaintext length, ciphertext length, offset, and artifact scope.
- [ ] Bind the manifest to checkpoint lineage outside the storage primitive;
      the manifest must not become a second provenance graph.
- [ ] Support whole-blob manifests during migration so existing snapshots stay
      readable.
- [ ] Make the canonical content identity independent of provider-specific
      ETags or object names.

### 2.2 Artifact-specific chunk policies

- [ ] Benchmark several chunk sizes for rootfs, runtime overlays, memory
      snapshots, and writable volume checkpoints.
- [ ] Record request count, transfer amplification, deduplication, local cache
      hit rate, materialization time, and manifest size for each policy.
- [ ] Choose chunk sizes from measured behavior rather than copying an external
      system’s constant.
- [ ] Bound the maximum chunk count and manifest size before parsing or
      allocating.

### 2.3 Local storage implementation

- [ ] Extend the existing local content-addressed store rather than creating a
      second cache directory.
- [ ] Publish chunks and manifests through private staging and atomic rename.
- [ ] Materialize chunked artifacts through the existing reflink/sparse-copy
      strategy where possible.
- [ ] Preserve reference counting and add lineage-aware reachability for
      checkpoint garbage collection.
- [ ] Keep path validation and symlink refusal at every materialization boundary.

### 2.4 Local tests

- [ ] Add serde roundtrip and unknown-field refusal tests for manifests.
- [ ] Add complete roundtrip tests for empty, one-chunk, multi-chunk, and
      sparse artifacts.
- [ ] Add duplicate-chunk deduplication tests.
- [ ] Add missing-chunk, altered-chunk, altered-manifest, wrong-scope, and
      incompatible-backend refusal tests.
- [ ] Add concurrent publication tests proving readers never observe partial
      chunks or manifests.
- [ ] Add crash-recovery tests for staged chunks, published manifests, and
      interrupted garbage collection.
- [ ] Add fuzz coverage for manifests, chunk lists, lengths, offsets, and
      decompression metadata.

**Phase 2 acceptance:** local chunked artifacts are faster or no slower than
whole-blob materialization for the measured hot cases, are backward-readable,
and have complete integrity, atomicity, and resource-bound tests.

## Phase 3 — Add the `mvmd` cold tier

This phase uses the existing Apache Arrow `object_store` implementation and
must not reintroduce a second cloud-provider stack.

### 3.1 Remote manifest publication

- [ ] Upload encrypted chunks under opaque, non-PII object keys.
- [ ] Verify every uploaded chunk before publishing its manifest.
- [ ] Publish manifests conditionally and immutably where the provider allows
      it.
- [ ] Bind the manifest to tenant/resource scope, lineage, byte lengths,
      encryption metadata, and the canonical digest.
- [ ] Treat ETag and provider version identifiers as advisory metadata only.
- [ ] Make partial uploads invisible to readers until the manifest is committed.

### 3.2 Background tiering

- [ ] Add a background tiering worker that selects inactive or pressure-targeted
      chunks using age, access frequency, local capacity, and retention policy.
- [ ] Upload encrypted chunks before evicting local copies.
- [ ] Keep hot entries pinned while a warm parent or active restore references
      them.
- [ ] Make tiering idempotent across worker restarts.
- [ ] Bound upload concurrency, temporary disk, memory, retries, and provider
      request rates.
- [ ] Add a circuit breaker so provider failure does not cause unbounded retry
      amplification.

### 3.3 Rehydration

- [ ] Resolve and authorize the manifest before fetching chunks.
- [ ] Fetch only required ranges or chunks when the consumer supports partial
      materialization.
- [ ] Verify ciphertext digest before decryption.
- [ ] Authenticate and decrypt with the manifest’s key version.
- [ ] Verify plaintext digest and artifact compatibility after decryption.
- [ ] Materialize into private staging, fsync, and publish atomically.
- [ ] Admit the artifact into the hot cache only after all checks pass.
- [ ] Emit a typed refusal when the provider, manifest, key, or artifact is not
      compatible.

### 3.4 Cross-worker recovery

- [ ] Reconstruct a worker’s hot cache from authoritative manifests after
      restart.
- [ ] Prove restore on a worker that has no prior local chunks.
- [ ] Prove concurrent restores of the same immutable artifact do not corrupt
      staging or duplicate committed versions.
- [ ] Prove a worker drain can offload or release all local references without
      losing a retained checkpoint.
- [ ] Validate pagination beyond the provider’s first listing page.
- [ ] Exercise MinIO and the supported production provider classes with the
      same contract tests.

**Phase 3 acceptance:** an authorized worker can restore a retained encrypted
artifact from a cold provider with no pre-existing local state, while partial
uploads, provider errors, altered chunks, stale manifests, and unauthorized
scopes fail closed.

## Phase 4 — Integrate tiering with snapshots and volumes

### 4.1 Templates and immutable runtime data

- [ ] Tier immutable rootfs, runtime-overlay, initramfs, and template chunks
      first.
- [ ] Prefetch template chunks when a warm-pool replenishment is scheduled.
- [ ] Keep the local hot copy pinned while a parent or child references it.
- [ ] Refuse a template restore when kernel, initramfs, overlay, device-model,
      or backend compatibility does not match.

### 4.2 Checkpoints

- [ ] Store checkpoint manifests as children of the existing signed checkpoint
      lineage.
- [ ] Preserve parent digest, epoch, audit anchor, and retention semantics.
- [ ] Make point-in-time recovery an explicit authorized operation.
- [ ] Separate a cold checkpoint recovery from a warm parent claim in the API,
      metrics, and user-facing output.
- [ ] Test restore after local cache eviction, worker restart, provider retry,
      and interrupted publication.

### 4.3 Writable volumes

- [ ] Preserve `StorageBucket` as the multi-attach, filesystem-shaped resource.
- [ ] Preserve `VolumeRecord` as exclusive-attach block storage.
- [ ] Keep one-writer fencing and durable versioned checkpoints.
- [ ] Never expose an object-store prefix as a guest POSIX filesystem.
- [ ] Keep local attachment and guest read-only enforcement in `mvm`.
- [ ] Keep remote provider construction, tenant credentials, and reconciliation
      in `mvmd`.

### 4.4 Memory snapshots

- [ ] Do not enable remote memory-snapshot tiering until authenticated encryption
      is mandatory for every persisted memory image.
- [ ] Bind memory snapshots to backend, architecture, VMM, kernel, initramfs,
      memory size, device model, and guest-agent compatibility.
- [ ] Prove that no secret-bearing state from a prior workload can enter a
      factory parent.
- [ ] Bound the temporary local disk and memory used by a remote memory restore.
- [ ] Determine experimentally whether the backend requires the complete memory
      image before resume. If it does, keep remote memory recovery off the warm
      SLO path.

**Phase 4 acceptance:** templates and checkpoints can be tiered and recovered
without changing guest-visible storage semantics, weakening lineage, or making
remote recovery appear to be a local warm claim.

## Phase 5 — Security hardening and adversarial validation

### 5.1 Confidentiality and key management

- [ ] Use client-side authenticated encryption before remote upload.
- [ ] Domain-separate keys by organization, workspace, tenant, resource kind,
      resource identity, and artifact class.
- [ ] Include key version and encryption parameters in the manifest.
- [ ] Keep keys in zeroizing types and out of manifests, logs, argv, and errors.
- [ ] Define recovery behavior for unavailable, revoked, and obsolete keys.
- [ ] Define deletion behavior for remote ciphertext when the key is destroyed.
- [ ] Do not claim online key rotation until a complete tested transition exists.

### 5.2 Deduplication privacy

- [ ] Decide whether sensitive data uses tenant-scoped digests, keyed digests,
      or encryption-derived identities.
- [ ] Prohibit global plaintext-equality deduplication for tenant-private data
      unless the leakage is explicitly accepted and documented.
- [ ] Keep public immutable artifact deduplication separate from tenant-private
      artifact deduplication.

### 5.3 Integrity, rollback, and substitution

- [ ] Verify manifest signature or audit binding before trusting chunk metadata.
- [ ] Verify every ciphertext and plaintext digest.
- [ ] Bind resource scope and lineage before cache admission.
- [ ] Enforce monotonic epochs and fenced versions.
- [ ] Refuse replayed, stale, truncated, reordered, duplicated, or oversized
      chunk lists.
- [ ] Refuse a restore when the parent checkpoint is missing, unaudited,
      tampered, or incompatible.

### 5.4 Isolation and side channels

- [ ] Include tenant/resource scope in cache keys and authorization checks.
- [ ] Keep same-page merging confined to an approved same-image fork family.
- [ ] Prove that cache eviction and rehydration do not expose another tenant’s
      pages, paths, or timing-sensitive metadata through the guest boundary.
- [ ] Never include raw resource names, credentials, or secret-bearing object
      metadata in cache filenames or provider keys.

### 5.5 Resource exhaustion

- [ ] Bound manifest size, chunk count, chunk size, decompressed size, and
      temporary storage.
- [ ] Bound concurrent uploads, downloads, decryptions, materializations, and
      restores per tenant and per worker.
- [ ] Add retry budgets, backoff, circuit breakers, and cancellation cleanup.
- [ ] Add quotas for object count, stored bytes, request rate, and rehydration
      bandwidth.
- [ ] Test decompression bombs, range-read amplification, cache thrashing, and
      provider retry storms.

### 5.6 Audit and observability

- [ ] Emit non-sensitive signed records for upload, publication, cache
      admission, eviction, rehydration, restore, integrity refusal,
      authorization refusal, fencing conflict, and garbage collection.
- [ ] Keep operational JSONL logs separate from the chain-signed audit source
      of truth.
- [ ] Redact credentials, signed URLs, provider response bodies, plaintext
      resource names where sensitive, and all secret values.
- [ ] Add metrics for cache hit ratio, remote bytes, request count, retry count,
      manifest failures, integrity failures, cold restores, and GC backlog.

**Phase 5 acceptance:** security tests cover valid, tampered, stale, replayed,
unauthorized, oversized, interrupted, and provider-failure cases, with no
secret or credential leakage in files, logs, manifests, or audit records.

## Phase 6 — Compatibility, chaos, and release evidence

- [ ] Run old whole-blob snapshots through the new reader.
- [ ] Run mixed-version worker tests during manifest rollout.
- [ ] Test provider outage during upload, publication, download, decrypt, and
      local publication.
- [ ] Kill workers at every staging and publication boundary and verify
      convergence.
- [ ] Test local cache deletion while a warm parent is active.
- [ ] Test remote manifest deletion while a retained child still exists.
- [ ] Test key unavailability and key-version mismatch.
- [ ] Test object-store pagination, stale reads, conditional-write conflicts,
      multipart completion races, and delete/recreate races.
- [ ] Publish benchmark results with local hot, local cold, and remote recovery
      paths clearly separated.
- [ ] Document exactly which claims are measured, which are targets, and which
      are unavailable on each backend.

## Required test matrix

### Unit and property tests

- [ ] Manifest serde roundtrip and unknown-field refusal.
- [ ] Chunk offset/length arithmetic and overflow refusal.
- [ ] Digest, encryption, and key-version binding.
- [ ] Deduplication and scope isolation.
- [ ] Atomic publication and crash recovery.
- [ ] Reference counting and lineage-aware garbage collection.
- [ ] Retry, cancellation, and backoff state machines.
- [ ] Compatibility matching across backend, kernel, initramfs, and agent
      versions.

### Integration tests

- [ ] Local chunked materialization through `SnapshotStore`.
- [ ] Remote provider conformance through the existing `object_store` path.
- [ ] Cross-worker restore with an empty local cache.
- [ ] Exclusive `VolumeRecord` fencing under concurrent writers.
- [ ] Multi-attach `StorageBucket` behavior under concurrent authorized readers.
- [ ] Checkpoint publication, restore, rollback refusal, and GC.
- [ ] Warm parent claim with local cache hit.
- [ ] Explicit cold recovery with remote cache miss.

### BDD and live tests

- [ ] Warm claim is faster than the cold baseline on the supported live backend.
- [ ] Cold recovery is visibly classified separately from warm claim.
- [ ] Remote restore refuses altered, stale, unauthorized, and incompatible
      manifests.
- [ ] Guest sees only validated local attachment paths.
- [ ] Guest cannot write through a read-only attachment.
- [ ] No cross-fork residue or cross-tenant page reuse is observable.
- [ ] Worker restart and drain preserve retained checkpoints.

### Fuzz and mutation coverage

- [ ] Fuzz manifest parsing, chunk metadata, restore metadata, encryption
      envelopes, and provider response metadata.
- [ ] Add mutation witnesses for digest verification, scope checks, epoch checks,
      key-version checks, and atomic-publication guards.
- [ ] Ensure every mutation that skips verification causes a test failure.

## Acceptance gates

The plan is complete only when all of the following are true:

- [ ] The local warm path has a reproducible p50/p99 measurement and remains
      independent of remote object storage.
- [ ] Chunked artifacts are backward-readable and locally materializable.
- [ ] Remote manifests and chunks are encrypted, authenticated, scoped, and
      atomically published.
- [ ] A worker with an empty local cache can recover an authorized retained
      artifact from remote storage.
- [ ] Remote recovery cannot bypass checkpoint lineage, plan admission, device
      model checks, confinement, or guest mount policy.
- [ ] `StorageBucket` and `VolumeRecord` retain their distinct semantics.
- [ ] No raw object-store credential, secret, token, or plaintext sensitive
      value appears in an artifact, manifest, cache path, error, or log.
- [ ] Provider outage, corruption, rollback, replay, key failure, staging
      interruption, and worker loss all fail closed or converge safely.
- [ ] Workspace tests, all-target Clippy, formatting, security gates, fuzz
      targets, BDD scenarios, and the required Linux/KVM live matrix pass.
- [ ] The benchmark report distinguishes measured results from design targets
      and does not compare remote recovery latency with local hot-cache latency
      as if they were the same operation.

## Recommended delivery order

1. Finish the local running-VMM warm path and restore security witnesses.
2. Add the versioned chunk/manifest abstraction and local implementation.
3. Add local cache metrics, eviction, reference tracking, and GC.
4. Add `mvmd` remote manifest/chunk publication over the existing
   `object_store` backend.
5. Add bounded remote rehydration and cross-worker recovery.
6. Integrate immutable templates and checkpoints.
7. Add writable-volume tiering while preserving existing attach semantics.
8. Revisit remote memory snapshots only after encryption and compatibility
   gates are complete.
9. Publish the measured performance, durability, cost, and security results.

The performance headline should remain the local warm claim. The remote tier’s
headline should be elasticity, recovery, and storage economics—not pretending
that an object-store miss is a memory hit.

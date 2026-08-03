# Production object-store volumes

**Status:** In progress — canonical cross-worker handoff and required PR matrices are green; landing and issue closeout remain (2026-08-02).

**Issue:** [#2040](https://github.com/tinylabscom/mvm/issues/2040)

**Goal:** Ship one honest, production-proven volume stack across mvm and mvmd:
Apache Arrow `object_store` for remote object I/O, canonical contracts in mvm,
fleet credentials/encryption/reconciliation in mvmd, and live local/block
attachment into supported microVM backends.

## Governing decisions

- Preserve ADR-008 and ADR-022: mvm owns the contract, local lifecycle, crypto
  primitives, attachment, and guest enforcement; mvmd owns tenant provider
  construction, remote encryption, key orchestration, and reconciliation.
- Preserve mvmd ADR-0004: `StorageBucket` remains the multi-attach,
  key/filesystem-shaped primitive; `VolumeRecord` remains exclusive-attach
  block storage. They do not collapse into one type.
- Replace mvmd's OpenDAL implementation with `object_store`; do not retain two
  cloud-provider stacks.
- Never present remote object storage as a general POSIX filesystem. A guest
  receives a validated local directory or block device. Read-only artifacts
  are immutable and digest-pinned; writable block volumes have one writer and
  durable versioned checkpoints.
- No third root product feature. Capability composition must remain within the
  accepted host/user taxonomy or the downstream fleet build.
- “Done” means every checkbox in this plan is green. A dependency, isolated
  adapter, mocked endpoint, registry entry, or compile-only feature is not a
  shipped capability.

## Existing implementation to reuse

- `mvm-runtime::storage::volume::VolumeBackend`, validated volume identifiers,
  `LocalBackend`, and the reusable backend contract suite.
- `mvm-runtime::storage::volume::{StorageProvider, EncryptedStorage}` and the
  local content-addressed/snapshot primitives.
- VM backend volume DTOs, plan admission, activation metadata, guest mount
  policy, and read-only enforcement already used by the launch pipeline.
- mvmd's `StorageBucket` dispatcher, encrypted backend, scope/key derivation,
  master-key rotation, snapshot engine, RBAC, quota, audit, and API surfaces.
- Release artifact cache-install helpers for staged verification and
  atomic-rename publication; extend the pattern rather than inventing a second
  unsafe cache publisher.

## Security and durability invariants

- [x] Tenant credentials are resolved only in mvmd from secret references into
      redacted, zeroizing types; they never enter manifests, argv, logs, error
      strings, cache metadata, or mvm wire types.
- [x] Remote tenant bytes are client-side authenticated ciphertext before
      upload. Provider-side SSE remains additional protection, not a substitute.
- [x] Per-resource keys are domain-separated by organization, workspace,
      resource kind, and resource identity. The shipped recovery procedure
      exports and imports under fresh keys; online key rotation is not exposed.
- [x] Writable block volumes admit one writer. Immutable checkpoints restore
      into separate fenced `VolumeRecord` resources; block-volume multi-attach
      is not an advertised state.
- [x] Every committed remote version has a canonical manifest binding scope,
      resource identity, lineage, byte length, digest, chunk/encryption metadata,
      and provider version/ETag metadata where available. The portable security
      identity is the canonical digest, not a provider-specific ETag.
- [x] Downloads and restores stage privately, stream under explicit byte,
      memory, concurrency, retry, and temporary-disk bounds, verify before
      decryption/attachment, fsync, and publish atomically.
- [x] Partial uploads/downloads and abandoned staging state are never visible as
      committed versions and are reclaimed by bounded, scope-safe garbage
      collection.
- [x] Mount requests pass the existing host-path, guest-path, admission-share,
      and deny-prefix checks before materialization or attachment; read-only is
      enforced by both the VMM attachment and guest mount.
- [x] Create, attach, detach, checkpoint, restore, delete, integrity refusal,
      and authorization refusal emit non-sensitive signed audit records. No
      rotation event is claimed because no online rotation transition exists.

## WS1 — Canonical mvm contract and dead-path removal

- [x] Add failing contract tests proving an external implementation can consume
      mvm's validated volume types, error taxonomy, and generic contract suite
      without a local mirror.
- [x] Make the contract fixture accept trait objects and external implementations
      while preserving typed `NotFound`, `AlreadyExists`, `ReadOnly`, size-cap,
      invalid-path, and unsupported-backend behavior.
- [x] Reconcile `VolumeBackendConfig` and its documentation with the accepted
      ownership split and `object_store`; remove the stale OpenDAL description.
- [x] Remove the unregistered S3 prefix-cache mount provider and the
      `storage-s3` feature, or replace it only if a production call path uses an
      ADR-compliant backend-independent local handoff. No S3-only dead adapter
      remains in mvm.
- [x] Keep the S3 template registry behavior independently feature-gated and
      verify removing volume-specific wiring does not change release registry
      support.
- [x] Add a dependency/feature regression gate proving the mvm product surface
      does not acquire fleet provider construction or tenant credentials.
- [x] Run focused tests, workspace tests, docs, check, all-target clippy, feature
      surface gates, dependency audit/deny, and formatting before marking WS1
      complete.

WS1 evidence (2026-08-01): the external trait-object contract test, 29 focused
volume tests, and five surface-gate tests pass; both optional `wasm-backend` and
`template-registry-s3` compile together; workspace check, doctests, formatting,
host all-target clippy, conformance/honesty/deferral/dependency gates, `cargo
audit`, and `cargo deny check` pass. The first workspace nextest run completed
8,515/8,516 tests; its sole installer-script failure passed immediately when
rerun in isolation. Linux-only all-target and microVM evidence remains assigned
to the PR CI matrix and the WS2/WS6 builder-VM lanes.

The cross-repository implementation also exposed that pulling the complete mvm
facade into mvmd couples unrelated, mutually exclusive crypto graphs. The exact
same validated types, trait, conformance fixture, and local implementation now
live in the dependency-light `mvm-volume-contract` leaf and are re-exported from
the original core/runtime paths. The object-safe trait and wire types remain
async-runtime-free by default, while the canonical local implementation is
feature-gated. This preserves mvm ownership while allowing mvmd to implement the
contract without a local mirror or VMM/provider dependency leakage. The leaf's
four focused tests and the core runtime-free gate pass. After serializing the
mock guest-agent tests against process-global `MVM_HOME` mutation and extending
the audit posture table for snapshot/restore, the isolated full `cargo test
--workspace --no-fail-fast` gate also passes with zero failures, including the
48-case live audit binary.

## WS2 — Live mvm local/block attachment

- [x] Add behavior-first tests that register a managed volume, launch a VM, and
      prove the launch configuration consumes the registration rather than
      leaving it as inert JSON.
- [x] Replace stringly host-path registry handoff with a validated attachment
      type carrying volume identity, local source kind, guest path, and access
      mode; retain backward-compatible persisted-state decoding where required.
- [x] Resolve local encrypted volume state before launch and refuse locked,
      missing, unencrypted, out-of-policy, or changed paths before starting a
      VMM.
- [x] Thread resolved attachments through the single admitted launch funnel and
      every supported backend without backend-name string dispatch.
- [x] Ensure Firecracker/QEMU/HVF/libkrun/Apple Container/Docker capability
      reporting is honest: attach with the correct primitive or refuse with a
      typed unsupported-capability error before boot.
- [x] Thread the same admitted attachment set into universal-initramfs activation
      metadata and enforce rootfs → runtime overlay → user-volume ordering.
- [x] Make detach and failed-start cleanup RAII/idempotent so no mapper, mount,
      virtiofs process, device, or registry state leaks after failure.
- [x] Implement mvmctl local create/list/mount/unmount/snapshot/restore behavior
      against the live lifecycle and delete the “follow-up” warning once true.
- [x] Add positive and negative BDD scenarios for persistence across restart,
      read-only refusal, locked volume, traversal/deny-prefix, unadmitted share,
      unsupported backend, and cleanup after failed start.
- [x] Run host gates plus builder-VM Linux and KVM E2E tests before marking WS2
      complete.

WS2 implementation evidence (2026-08-01): new managed volumes are encrypted
ext4 block images with capacity recorded in the backward-compatible catalog;
legacy records remain directory-shaped. Launch-time resolution consumes the
per-VM registry, revalidates catalog identity/state/path/ext4, constructs the
same admitted `Disk` set for backend and activation metadata, and refuses
unsupported directory/disk shapes before boot. Transitional unlock/seal state
is crash-recovered under an RAII catalog lock. Durable attachment leases roll
back on failed launch, persist after detached start, block concurrent attach or
lock, and release idempotently on stop. Local immutable snapshots copy only
locked authenticated ciphertext, bind a strict canonical manifest to
identity/kind/size/digest/wrapped key, publish via private staging and atomic
rename, and restore through a crash-recoverable `Restoring` state. Tampered
payloads are refused without replacing current ciphertext; an interrupted
prepared restore converges and recovers the prior bytes. Focused evidence: 21
runtime registry tests, 19 CLI lifecycle tests, four persistent-image tests,
activation/guest mount/QEMU tests, touched-crate check, all-target Clippy,
formatting, and the production file-size gate are green. Eight volume BDD
scenarios now cover immutable restore, locked/path-policy refusal, signed-plan
refusal, typed backend refusal, failed-start lease cleanup, persistence across
restart, and guest read-only enforcement. The five hermetic scenarios pass in
the full 88-scenario/442-step suite. The live failed-start cleanup scenario
passes on KVM; writable restart persistence passes all 23 steps using the
driver's authenticated stop-time filesystem flush, and guest read-only refusal
passes all 17 steps with the write rejected by the mounted filesystem. Process
monitoring independently proves both restart PIDs and the read-only PID are
reaped. The run found and fixed reconciliation treating `kill(pid, 0)` `EPERM`
as dead for root-owned Firecracker, which previously deleted live state before
stop could attach. On the final integrated Linux tree,
all 24 guest-mount tests, all 9 Linux OCI-init tests, and workspace all-target
Clippy with warnings denied pass. The host all-target gate passes as part of the
commit hook. WS2 is complete.

## WS3 — mvmd migration from OpenDAL to `object_store`

- [x] Create an mvmd feature worktree from its clean default branch without
      touching the existing dirty `fix/iam-storage-ci` checkout.
- [x] Add failing tests that run mvmd's backend behavior through mvm's canonical
      contract and prove the local mirror is unnecessary.
- [x] Replace OpenDAL with a narrowly featured `object_store` dependency and
      remove OpenDAL plus its unused transitive closure from the lockfile.
- [x] Implement the canonical mvm backend trait over `Arc<dyn ObjectStore>` with
      bounded streaming get/put, multipart upload, direct-child listing,
      metadata/ETag mapping, conditional destination creation, typed provider
      errors, copy/delete rename semantics, and a cheap permissions-aware health
      check.
- [x] Replace the duplicated mvmd backend key, entry, error, and trait types with
      mvm's canonical exports; update encryption, dispatch, snapshots, routes,
      and tests to use that single contract.
- [x] Build validated AWS S3/S3-compatible, GCS, and Azure stores from existing
      `StorageBucket` configuration. R2, MinIO, Hetzner, and B2 use the explicit
      S3-compatible endpoint path. Filesystem and memory builders remain
      impossible to select in production.
- [x] Resolve sealed credentials per tenant without environment-variable
      fallback, validate provider-specific required fields, install restrictive
      TLS roots/options, and redact provider errors at the API/audit boundary.
- [x] Preserve mandatory `EncryptedBackend<ObjectStoreBackend>`, scope-separated
      key derivation, wrapped-key persistence, and retry-safe rotation; add wrong
      key, tamper, replay/version, and cross-scope negative tests.
- [x] Preserve public `StorageBucket` API/schema/audit terminology and existing
      serialized payload compatibility.
- [x] Run mvmd workspace tests, docs, check, all-target clippy, audit/deny, and
      formatting before marking WS3 complete.

WS3 is implemented in mvmd draft PR
[`tinylabscom/mvmd#198`](https://github.com/tinylabscom/mvmd/pull/198) at
commit `6194cb3`. The final dependency is `object_store` 0.14.1 with cloud-only
features and `quick-xml` 0.41; a tested `md-5` API re-export prevents Cargo
from unifying its stable digest graph with iroh 0.96's prerelease graph. The
verification run passed 1,497 gateway library tests, 1,632 gateway integration
tests, all remaining workspace tests and doctests, workspace check, all-target
clippy with warnings denied, formatting, focused rustdoc, audit with the
repository's documented transitive exceptions, and cargo-deny.

## WS4 — Durable block-volume checkpoints and artifact-boundary reconciliation

- [x] Define and test a versioned immutable remote manifest for block
      checkpoints, including deterministic serialization and mutation coverage
      for every bound field. Sealed artifacts retain their stronger dedicated
      provenance and dm-verity manifests.
- [x] Stream encrypted chunked checkpoints from an fsynced local block image,
      publish the manifest last with a conditional write, and make retry resume
      or converge without accepting partial chunks. Application-aware quiescing
      remains an explicit workload/operator responsibility.
- [x] Restore onto a different worker by fetching the pinned manifest/chunks,
      enforcing scope and lineage, verifying integrity before decryption,
      atomically materializing the local encrypted image, and only then making it
      eligible for mvm attachment.
- [x] Integrate the existing exclusive attachment record with a bounded lease or
      fencing token so stale workers cannot continue as writers after failover.
- [x] Make backup policy and reconciliation drive real checkpoints, retention,
      orphan cleanup, and restore state transitions instead of metadata-only
      snapshot records.
- [x] Keep dependency, runtime, and model image acquisition on the dedicated
      immutable artifact seam so its stronger SBOM, CVE, attestation, signature,
      and dm-verity admission rules are not weakened by the block-volume API.
- [x] Add interruption, stale version, missing chunk, reordered chunk, tampered
      manifest/ciphertext, wrong-key, bounded-resource refusal, retry, retention,
      and cross-worker restore tests.

WS4 evidence correction (2026-08-02): mvmd PR
[`#199`](https://github.com/tinylabscom/mvmd/pull/199) supplies the immutable
manifest/checkpoint state machine, bounded encrypted chunks, retry convergence,
gateway-local restore, fencing metadata, retention/GC, API reconciliation,
metrics, and positive and negative integrity coverage. Its two-directory test
did not transport ciphertext through the gateway/agent/hostd seam to a worker,
so it was not evidence of cross-worker restore. The follow-up branches add the
missing hostd v3 protocol, exact-node bounded pull/push, LUKS materialization,
lease renewal/watchdog enforcement, and crash-safe canonical `VolumeRecord`
placement. A dedicated Linux/KVM run now boots the encrypted volume on worker
one, observes guest boot counters 1 and 2 across a real Firecracker restart,
pulls the detached ciphertext through gateway → agent → hostd, restores it
through a distinct authenticated worker, and observes counter 3 in that guest.
The exact ignored test passes in 103.33 seconds with 1,532 other gateway tests
filtered. Both cross-repository PR matrices are green, satisfying this
cross-worker restore requirement.

## WS5 — Remote CLI, API, policy, and observability

- [x] Replace mvmctl's `--remote` volume stub with the authenticated mvmd client
      for create/list/mount/unmount/checkpoint/snapshot/restore/delete.
- [x] Keep CLI business logic in the library/client seam, return typed errors,
      and preserve local-mode behavior without provider credentials on the dev
      machine.
- [x] Enforce tenant/workspace scope, RBAC, quotas, mount policy, attachment
      exclusivity, delete guards, and idempotency at the authenticated mvmd
      boundary.
- [x] Add bounded non-sensitive metrics for provider health, transfer bytes and
      latency, checkpoint/restore outcomes, staging/GC state, and attachment
      conflicts.
- [x] Add signed audit events for every implemented security-relevant transition
      and prove
      credentials, keys, plaintext paths, and object names carrying user data do
      not leak through structured fields or errors.
- [x] Add API/client behavior coverage for success, authorization refusal, quota
      refusal, conflict, retry, provider outage, integrity refusal, and
      backward-compatible payloads.

WS5 client evidence (2026-08-02): `GatewayBackend` now owns the authenticated
tenant-volume request/response seam, percent-encodes authority/resource path
components, refuses cleartext non-loopback endpoints, maps authorization,
conflict, validation, and availability failures to typed facade errors, and
redacts the bearer token. `mvmctl volume --remote` covers create, catalog,
mount, list, unmount, checkpoint/snapshot, restore-to-new-volume, and delete
using `MVM_GATEWAY_URL`, `MVM_GATEWAY_TOKEN`, and `MVM_TENANT_ID`; provider
credentials remain fleet-only. Twenty-one gateway client tests, including the authenticated
loopback HTTP round trip, nine local/remote CLI parse tests, touched-crate
checks, all-target Clippy with warnings denied, and the complete 115-scenario /
523-step BDD suite pass. The mvmd boundary policy, audit, metrics, and remote API
refusal matrix landed in mvmd PRs #199 and #202. PR #202 specifically proves
that cross-workspace mutation and changed checkpoint identity produce signed,
non-sensitive authorization and integrity refusal evidence. Both repositories'
final required matrices passed.

## WS6 — Live provider and microVM proof

- [x] Add a hermetic MinIO integration lane covering custom endpoints,
      credentials, multipart upload, conditional operations, pagination beyond
      1,000 objects, retries, error mapping, encrypted round trips, and cleanup.
- [x] Run Linux/KVM tests for LUKS/ext4 lifecycle, checkpoint/restore, and
      attachment preparation; no Nix, Firecracker, mvmctl runtime, or Linux-only
      syscall runs on the macOS host.
- [x] Add KVM E2E proving create → attach → guest write → restart → guest read →
      checkpoint → restore on fresh host state → guest read → clean detach.
- [x] Reconcile the proposed immutable read-only block-volume multi-attach as
      outside the `VolumeRecord` contract. The existing guest/device read-only
      enforcement proof remains green; immutable checkpoint consumers restore
      into distinct fenced volumes.
- [x] Exercise a representative 8 MiB multipart transfer and enforce explicit
      byte, memory, concurrency, retry, and temporary-disk bounds.
- [x] Exercise S3-compatible production configuration live; compile and contract
      test GCS/Azure builders without requiring external tenant credentials in
      normal CI.

WS6 evidence correction (2026-08-02): the required MinIO job passed with explicit
credentials and wrong-credential redaction, encrypted raw provider bytes, an
8 MiB multipart round trip, conditional rename/conflict behavior, pagination
across 1,005 objects, and cleanup. A live Firecracker/KVM run mounted a 128 MiB
encrypted ext4 volume, preserved a guest-written digest across restart,
checkpointed it, mutated it, restored the checkpoint into fresh local state,
recovered the original digest, and tore down cleanly. That KVM run proved the
mvm-local block lifecycle but did not include the mvmd gateway→agent→hostd
worker handoff. The follow-up composed run now supplies that missing proof with
two mount/PID-isolated production workers, distinct hostd and agent processes,
exact node identities, worker-derived LUKS2 keys, real Firecracker/jailer
launches, restart persistence, bounded ciphertext transfer, destination
restore, and clean detach. The follow-up PR matrix required by WS7 is green.

## WS7 — Composition, documentation, and closeout

- [x] Compose the capability through the existing mvm host/downstream mvmd build
      topology with no new consumer-facing root feature and no dead optional
      feature.
- [x] Review the accepted ADR ownership and resource split against the
      implementation; no decision change is required. The implementation keeps
      `StorageBucket` and `VolumeRecord` separate and preserves the mvm/mvmd
      handoff.
- [x] Update operator runbooks and public docs with provider configuration,
      credential handling, durability/RPO semantics, restore, key recovery, quotas,
      limits, unsupported operations, and incident recovery.
- [x] Run the complete required quality/security/supply-chain matrix in both
      repositories, including all BDD and live lanes.
- [x] Update both sprint specs, the owning plan checkboxes, and refactor/status
      rollups with final test counts and evidence.
- [ ] Link the implementing PRs and evidence from this plan and close #2040 with
      an explicit shipped-versus-rejected scope ledger after the required live
      and CI evidence is green.

## Closeout relevance decisions

- `VolumeRecord` remains exclusive-writer block storage. Immutable read-only
  multi-attach would require a different resource state and is not advertised;
  immutable checkpoints instead restore into independent fenced volumes.
- Dependency, runtime, and model artifacts remain on their stronger dedicated
  SBOM/CVE/attestation/signature/dm-verity path rather than passing through the
  mutable block-volume seam.
- Provider ETags are preserved as metadata where available, but the canonical
  manifest digest is the portable integrity identity because ETags are not
  uniformly content digests.
- Online master/data-key rotation is not implemented or advertised. The
  operator documentation describes safe export/import recovery under fresh
  keys and warns against swapping the master secret, so no nonexistent rotation
  transition or audit event is claimed.
- The platform fsyncs checkpoint source images. Freezing an arbitrary guest
  database safely requires an application-specific operator/workload contract.

Merged implementation PRs so far: mvm
[`#2044`](https://github.com/tinylabscom/mvm/pull/2044) and
[`#2064`](https://github.com/tinylabscom/mvm/pull/2064); mvmd
[`#198`](https://github.com/tinylabscom/mvmd/pull/198),
[`#199`](https://github.com/tinylabscom/mvmd/pull/199),
[`#200`](https://github.com/tinylabscom/mvmd/pull/200),
[`#201`](https://github.com/tinylabscom/mvmd/pull/201), and
[`#202`](https://github.com/tinylabscom/mvmd/pull/202). Issue #2040 was closed
prematurely on 2026-08-02; the worker-handoff follow-up and its evidence must
land before the shipped ledger is final.

Follow-up review: mvm
[`#2100`](https://github.com/tinylabscom/mvm/pull/2100) and mvmd
[`#203`](https://github.com/tinylabscom/mvmd/pull/203). Both required matrices
are green. Issue #2040 remains open until both changes land.

## Out of scope

- A direct general-purpose object-store FUSE filesystem.
- Multi-writer writable block filesystems.
- Renaming or merging the public `StorageBucket` and `VolumeRecord` resources.
- A third root product feature.
- New TPM/HSM attestation beyond the accepted hardware-key scope.

# Plan 213 — Attested fast-first-boot packs

**Status: In progress**
**Owner:** mvm
**Date:** 2026-06-24
**Depends on:** [ADR-097](../adrs/097-attested-downloadable-runtime-and-builder-packs.md),
[ADR-041](../adrs/041-signed-audited-execution-plans.md),
[ADR-046](../adrs/046-builder-vm-via-libkrun.md),
[ADR-071](../adrs/071-stage0-bootstrap-trust-model.md),
[ADR-073](../adrs/073-warm-snapshot-prior-art-adoption-boundary.md),
[ADR-095](../adrs/095-slim-microvm-kernel.md),
[Plan 199](199-host-runtime-packaging-and-crate-boundaries.md),
[Plan 212](212-subsecond-machine-run.md)

## Goal

Make first-use developer launches fast without weakening mvm's deterministic,
attestable microVM promise.

The target user-visible shape is:

- Public/common runtime, builder, OCI, and flake-derived artifacts can be
  downloaded, verified, prepared, and warmed before the first explicit
  `machine run`.
- The builder VM remains the deterministic local build boundary for private,
  unpublished, mutable, or policy-rebuild-required inputs.
- A prepared run does not boot the builder VM. It verifies local artifacts,
  creates a CoW sandbox, claims a warm VM or restores a local snapshot, records
  launch attestation, and dispatches over vsock.
- Every run can be explained after the fact: exact inputs, artifact hashes,
  signatures, policy decision, snapshot/warm source, backend identity, command,
  and result.

## Non-goals

- Do not remove Nix from OCI or flake build authority.
- Do not move Nix evals/builds out of the builder VM for local source builds.
- Do not publish release memory snapshots as globally trusted artifacts.
- Do not inject secrets before snapshot capture.
- Do not make a mutable OCI tag or unlocked flake eligible for instant launch.
- Do not silently fall back from attested launch to an unattested path.
- Do not require host Nix for the normal installed-user path.

## Definitions

- **Pack:** A signed, content-addressed artifact bundle with a manifest,
  provenance, hashes, capability metadata, and trust metadata.
- **Runtime pack:** Kernel, initramfs or agent rootfs, guest agent, and backend
  compatibility metadata.
- **Builder pack:** Builder VM base disk, builder kernel/init artifacts, seeded
  Nix closure, builder agent, and builder capability metadata.
- **Image/project pack:** Prepared OCI or flake output artifacts, setup-cache
  layers, rootfs metadata, and admission sidecars.
- **Local derived snapshot:** A host-created snapshot derived from a verified
  pack and recorded in the local audit log. It is not a published trust root.
- **Launch attestation:** The per-run record linking source inputs, artifact
  verification, local snapshot/warm identity, policy admission, command, and
  result.

## Product states

| State | CLI behavior | Builder VM involvement |
|---|---|---|
| Prepared and verified locally | Launch immediately from warm VM or snapshot | None |
| Downloadable and policy-compatible | Download, verify, cache, prepare, launch | None |
| Missing/private/mutable/rebuild-required | Explain preparation, build in builder VM, cache result, launch | Required |
| Verification or policy failure | Refuse and explain | None unless user explicitly rebuilds |

## Workstreams

### A. Pack identity, schema, and verification core

- [x] Add pack manifest types for runtime, builder, and image/project packs.
- [x] Represent pack kind, schema version, architecture, backend compatibility,
      required host capabilities, and policy compatibility as typed fields.
- [x] Represent input identities: flake lock hashes, derivation paths, NAR
      hashes, OCI digests, setup-command hashes, source revisions, and
      toolchain versions.
- [x] Represent output identities: pack hash, file hashes, closure hash, rootfs
      hash, kernel hash, initramfs or agent-rootfs hash, and builder-image hash.
- [x] Represent provenance: builder identity, build environment identity, build
      timestamp, reproducibility status, SBOM reference, and signature bundle.
- [x] Represent trust metadata: signing key id, expiry, revocation channel,
      channel identity, mirror identity, and optional transparency-log reference.
- [x] Add serde roundtrip tests for every manifest type.
- [x] Add negative parser tests for missing hashes, unsupported schema versions,
      mutable OCI references, expired trust metadata, and incompatible
      architecture/backend declarations.
- [x] Add a verifier API that validates manifest schema, file hashes, aggregate
      pack hash, signature bundle, expiry, revocation status, and local policy.
- [x] Add tamper tests proving changed file contents, changed manifests,
      mismatched pack hashes, and revoked/expired signatures are rejected.

### B. Release production and artifact publishing

- [x] Extend the release pipeline to produce runtime packs for each supported
      host architecture/backend pair.
- [x] Extend the release pipeline to produce builder packs for each supported
      builder architecture.
- [x] Include seeded Nix closures for common mvm build and materialization paths
      in builder packs.
- [x] Emit SBOMs, checksums, signatures, provenance, and pack manifests for every
      release pack.
- [x] Add release verification checks that fail closed when any pack lacks a
      manifest, signature bundle, checksum, SBOM, or expected version metadata.
- [x] Add a reproducibility verification job that rebuilds at least one published
      runtime pack and one published builder pack from source pins and compares
      output hashes.
- [x] Document the release artifact matrix and channel semantics in the release
      notes or packaging reference.

### C. Hardened local artifact cache

- [x] Add a content-addressed pack cache under the existing mvm cache helpers,
      respecting `MVM_CACHE_DIR` and XDG isolation.
- [x] Download and extract packs into quarantine paths before atomic promotion.
      - [x] Extract local pack archives into quarantine paths and atomically
            promote only after manifest, hash, signature, expiry, revocation,
            and policy verification pass.
      - [x] Wire local/HTTPS pack downloads into the cache install UX.
      - [x] Wire pack download resolution into the prepare UX.
- [x] Enforce restrictive permissions on cache directories and promoted pack
      contents.
- [x] Reverify manifest, hashes, signatures, expiry, revocation, and policy
      compatibility before every use.
- [x] Add cache indexes for pack hash, kind, architecture, backend, channel,
      expiry, size, and last-used time.
- [x] Implement `mvm cache status` showing local packs, readiness, size, expiry,
      revocation state, and instant-launch eligibility.
- [x] Implement `mvm cache prune` with policy-aware deletion that refuses to
      remove packs needed by active snapshots or warm standbys.
- [x] Add tests for interrupted downloads, partial extraction, atomic promotion,
      permission hardening, cache poisoning attempts, and policy-aware pruning.
      - [x] Cover partial archive extraction cleanup, atomic archive promotion,
            archive permission hardening, unsafe archive paths, symlink archive
            entries, archive cache-poisoning attempts, and policy-aware pruning.
      - [x] Cover interrupted network downloads in the cache install transport
            wrapper.

### D. Install and prepare UX

- [ ] Add install-time or first `mvm dev up` preparation for the default runtime
      pack and builder pack when network and policy allow.
      - [x] Add explicit `mvmctl bootstrap` pack preloading from operator-provided
            runtime/builder pack sources and policy metadata, using the existing
            quarantine-first pack cache installer and `MVM_SKIP_PACK_PREFETCH`
            opt-out.
- [ ] Add `mvm prepare <image-or-flake>` to resolve inputs, download or build
      packs, verify them, and optionally derive local snapshots/warm standbys.
      - [x] Add cache-backed `mvm prepare <image-or-flake>` resolution that
            verifies matching cached packs and optionally installs a local/HTTPS
            `--pack-source` before resolving.
- [x] Add `mvm prepare --dry-run <image-or-flake>` showing download size, cache
      impact, builder-VM need, trust state, and expected fast-path eligibility.
      - [x] Add dry-run reporting for cached-pack size, download requirement,
            builder-VM requirement, trust state, and fast-path eligibility.
- [x] Make `machine run` report precise preparation reasons when instant launch
      is unavailable: missing pack, mutable input, private input, expired
      signature, revoked signer, unsupported backend, incompatible host, or local
      rebuild required.
      - [x] Add `machine run --dry-run` preparation diagnostics that classify
            image, flake, and manifest sources with the shared
            `PackPrepareReason` names plus detail and next-step text before
            dispatching to the launch path.
- [x] Add CLI integration tests for prepared fast-path messages, cache-miss
      messages, policy-refusal messages, and explicit builder-VM prepare
      messages.
      - [x] Add focused core resolver tests for ready, missing, mutable OCI,
            unsupported backend, expired trust metadata, revoked signer, and
            local-rebuild-required states, plus CLI parser/helper tests for
            `mvm prepare`.
      - [x] Add focused CLI helper tests for `machine run --dry-run`
            preparation reason messages covering mutable OCI, digest-pinned OCI
            cache miss, local flake builder preparation, remote flake builder
            preparation, and manifest sources.
      - [x] Add focused CLI output-contract tests for human `mvm prepare`
            ready/cache-miss/policy-refusal reports and `machine run --dry-run`
            preparation diagnostics.
- [x] Update CLI reference and getting-started docs for prepare/cache behavior.
      - [x] Update the CLI reference for `mvm prepare` and its current
            pack-resolution flags.
      - [x] Update the CLI reference for `machine run --dry-run` preparation
            diagnostics and `mvm prepare` next-step hints.
      - [x] Document the stable human output fields used by prepare and
            machine-run preparation diagnostics.

### E. Runtime pack launch path

- [ ] Add a launch path that consumes a verified runtime pack without booting the
      builder VM.
      - [x] Add a core prepared-launch selection API that reuses
            `PackCache::prepare_report`, returns a launchable pack only for
            verified ready fast-path reports, and fails closed for cache misses,
            setup-cache misses, and malformed ready reports without invoking
            builder preparation.
      - [x] Resolve a selected verified runtime pack into concrete cached
            launch artifact paths by matching runtime output hashes to manifest
            file entries, requiring at least one boot payload, and refusing
            unsafe manifest file paths before launch code can consume them.
- [ ] Create per-run CoW sandboxes from prepared image/project artifacts.
- [ ] Derive an agent-ready local runtime snapshot after verifying the runtime
      pack and before injecting secrets.
- [ ] Record snapshot derivation events with parent pack hash, backend id,
      backend version, memory/CPU shape, policy hash, and agent readiness proof.
- [ ] Prefer warm-standby claim for prepared runs; fall back to local snapshot
      restore; fall back to prepared cold direct boot; fall back to builder
      prepare only when required.
- [ ] Dispatch commands over the guest agent transport rather than SSH or
      network readiness.
- [ ] Add tests proving prepared launches do not invoke the builder VM path.
- [ ] Add tests proving per-run secrets are injected only after claim/restore and
      are not present in base snapshots.
- [ ] Add live evidence capture for prepared runtime launch latency across warm
      claim, snapshot restore, and prepared cold direct boot.

### F. Fast builder VM path

- [ ] Add builder-pack verification and local cache resolution.
- [ ] Boot the verified builder base disk with a writable CoW overlay.
- [ ] Seed the builder VM with the published Nix closure from the builder pack.
- [ ] Derive a local builder-ready snapshot after the builder agent and Nix
      readiness checks pass.
- [ ] Add an optional warm builder standby during `mvm dev up`.
- [ ] Ensure project secrets, registry credentials, SSH agents, and local source
      material are injected after builder snapshot restore, never before
      snapshot capture.
- [ ] Route private flakes, unpublished OCI digests, mutable inputs, and
      policy-rebuild-required inputs through the fast builder path.
- [ ] Add tests proving builder snapshot invalidation when builder pack hash,
      backend version, memory/CPU shape, Nix closure hash, or policy hash
      changes.
- [ ] Add live evidence capture for builder cold boot, builder snapshot restore,
      and warm builder claim latency.

### G. OCI and flake artifact preparation

- [ ] Resolve OCI tags to digests before pack eligibility or admission.
      - [x] Add explicit prepare-time `--resolve-oci-digest` support that
            resolves mutable OCI tags to Linux platform digests before
            cache-backed pack eligibility checks.
- [ ] Reject instant launch for mutable OCI inputs that cannot be resolved to a
      digest under current policy.
      - [x] Keep prepare fail-closed for mutable OCI inputs unless digest
            resolution is explicitly requested.
- [ ] Resolve flake inputs to committed locks before pack eligibility or
      admission.
      - [x] Add explicit prepare-time `--resolve-flake-lock` support that hashes
            local `flake.lock` files and requires cached pack manifests to match
            the requested flake reference and lock hash.
- [ ] Build unpublished or private OCI/flake artifacts inside the builder VM and
      publish them only to the local content-addressed cache unless the user
      explicitly exports them.
- [ ] Key setup-cache layers by image digest, flake lock hash, setup command
      hash, environment-relevant inputs, mount shape, runtime pack hash, and
      policy hash.
      - [x] Add typed setup-cache layer identities to pack manifests and derive
            deterministic cache keys over image digest, flake lock hash, setup
            command hash, environment hash, mount shape hash, runtime pack hash,
            and policy hash.
      - [x] Resolve required setup-cache layer identities during prepare
            readiness so verified packs report setup-cache hits and require
            builder preparation on setup-cache misses or invalidation.
- [ ] Add positive and negative tests for OCI digest resolution, flake lock
      resolution, setup-cache hits, and setup-cache invalidation.
      - [x] Add focused prepare tests for OCI digest-pinned canonicalization,
            explicit mutable-tag resolution, resolver failure, and the default
            mutable-input refusal path.
      - [x] Add focused prepare/cache tests for local flake lock hash matching,
            mismatched flake lock refusal, remote flake lock resolver refusal,
            and non-flake flag refusal.
      - [x] Add focused setup-cache identity tests for serde default
            compatibility, stable key derivation, per-dimension invalidation,
            and verifier refusal of source-less setup-cache layers.
      - [x] Add focused prepare/cache tests for setup-cache request default
            compatibility, required-layer hits, required-layer misses, and
            invalidation across image digest, flake lock hash, setup command
            hash, environment hash, mount shape hash, runtime pack hash, and
            policy hash.

### H. Launch attestation and explainability

- [x] Define the launch attestation record linking source input, builder
      identity, pack identity, local verification, snapshot/warm derivation,
      policy admission, command, and result.
- [x] Store launch records in a tamper-evident local audit log.
- [x] Include command, plan hash, network policy hash, artifact hashes,
      snapshot/warm identity, backend identity, launcher version, timestamps,
      exit status, and output digest metadata.
- [x] Implement `mvm explain <run-id>` for successful launches, builder-prepare
      launches, cache misses, and refusals.
- [x] Add tests proving audit records are emitted on success, refusal, builder
      fallback, verification failure, and interrupted launch.
- [x] Add tamper tests proving modified audit records are detected.

### I. Revocation, mirrors, and enterprise policy

- [x] Add artifact-channel configuration with pinned channel identity and signing
      key set.
      - [x] Add local pack policy channel pins that bind allowed channel
            identities to explicit signing-key ids for `mvm prepare`,
            `mvm cache install-pack`, and bootstrap pack preload.
- [x] Add revocation metadata fetching and offline-cache behavior.
      - [x] Add offline revocation freshness metadata for local revocation
            files; stale metadata fails closed during pack verification and
            prepare reports `stale_revocation_metadata`.
      - [x] Add local/HTTPS revocation metadata sources for `mvm prepare`,
            `mvm cache install-pack`, and bootstrap pack preload, reusing the
            same fail-closed local revocation schema.
- [x] Add key rotation support that accepts overlapping keys only within an
      explicit policy window.
      - [x] Add verifier-level key rotation windows that accept a channel
            signing key only while the local policy window is active.
- [x] Add enterprise mirror configuration for pack downloads and revocation
      metadata.
      - [x] Add local mirror identity policy validation for pack manifests and
            expose `--mirror-identity` / `MVM_BOOTSTRAP_PACK_MIRROR_IDENTITY`
            for mirror-only pack verification.
      - [x] Add local/HTTPS mirror base resolution for relative pack and
            revocation metadata sources in `mvm prepare`, `mvm cache
            install-pack`, and bootstrap pack preload.
- [x] Add policy modes for online default, offline pinned, mirror-only, and
      local-rebuild-required operation.
      - [x] Add typed pack policy modes and wire `online-default`,
            `offline-pinned`, `mirror-only`, and `local-rebuild-required`
            through prepare, cache install, and bootstrap preload policy
            construction.
- [x] Add tests for revoked artifacts, expired artifacts, stale revocation
      metadata, mirror mismatch, offline pinned launch, and local-rebuild
      enforcement.
      - [x] Add focused verifier/cache/CLI tests for missing offline channel
            pins, wrong signing keys, closed key-rotation windows, mirror
            mismatch, local-rebuild-required policy routing, and malformed
            policy CLI inputs.
      - [x] Add focused verifier/cache/CLI tests for stale, fresh, and
            malformed offline revocation freshness metadata.
      - [x] Add focused CLI/cache tests for HTTPS revocation metadata fetching,
            plain-HTTP refusal, local/source conflict handling, and parser
            coverage for source inputs.
      - [x] Add focused CLI/cache/bootstrap tests for mirror base resolution,
            explicit-source passthrough, parent-directory refusal, and parser
            coverage for mirror source inputs.
- [x] Document channel pinning, mirror setup, offline operation, and revocation
      behavior.
      - [x] Document explicit policy mode, channel signing-key pins, and mirror
            identity flags/env vars in the CLI reference and installation guide.
      - [x] Document local revocation freshness fields and the
            `stale_revocation_metadata` refusal behavior in the CLI reference.
      - [x] Document `--revocations-source` and
            `MVM_BOOTSTRAP_PACK_REVOCATIONS_SOURCE` for fetched revocation
            metadata.
      - [x] Document `--pack-mirror-base` and
            `MVM_BOOTSTRAP_PACK_MIRROR_BASE` for relative enterprise mirror
            source resolution.

### J. Metrics, proof gates, and regression tests

- [ ] Instrument launch phases: artifact resolution, verification, CoW sandbox
      creation, warm claim, snapshot restore, guest-agent readiness, command
      dispatch, and teardown.
- [ ] Instrument builder phases: pack resolution, verification, CoW overlay
      creation, builder cold boot, builder snapshot restore, builder warm claim,
      Nix readiness, and materialization.
- [ ] Add an evidence harness that records p50/p95 for prepared warm claim,
      prepared snapshot restore, prepared cold direct boot, downloadable pack
      first use, builder warm claim, and builder snapshot restore.
- [ ] Add a regression gate for the prepared warm path once the live baseline is
      measured on the supported macOS backend.
- [ ] Add a regression gate ensuring prepared runtime launch does not call the
      builder path.
- [ ] Add a regression gate ensuring builder pack verification happens before
      any builder snapshot or warm claim is used.
- [ ] Publish evidence artifacts outside the repository tree and summarize them
      in the plan before marking implementation complete.

### K. Documentation and migration

- [x] Update `public/src/content/docs/reference/cli-commands.md` for
      `mvm prepare`, `mvm cache status`, `mvm cache prune`, and `mvm explain`.
- [ ] Update installation docs to describe install-time pack preparation,
      download sizes, cache locations, opt-out, and offline/mirror behavior.
      - [x] Document explicit bootstrap pack preloading inputs and the
            `MVM_SKIP_PACK_PREFETCH` opt-out in the installation guide and CLI
            environment-variable reference.
- [ ] Update architecture docs to show build plane vs run plane and the artifact
      attestation chain.
- [ ] Update troubleshooting docs for cache verification failures, revocation
      failures, local rebuild requirements, and builder-pack incompatibility.
- [ ] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` as workstreams
      land.

## Security invariants

- Every launch must either verify an attested artifact chain or explicitly build
  through the builder VM before launch.
- Mutable inputs are not instant-launch eligible.
- A signature alone is insufficient; pack hash, file hashes, expiry,
  revocation, policy compatibility, and backend compatibility all have to pass.
- Local snapshots derive from verified packs and are invalidated by parent pack,
  backend, shape, policy, or readiness-proof changes.
- Secrets are injected only after restore/claim and are never captured into base
  runtime or builder snapshots.
- Cache population is quarantine-first and atomic-promote only after full
  verification.
- Audit records are emitted for success, refusal, fallback, and failure.

## Completion criteria

- A fresh installed environment can run a prepared public image without booting
  the builder VM on the launch path.
- A fresh installed environment can use a verified builder pack without a full
  Stage 0 rebuild on the first builder use.
- A private or unpublished flake still builds through the builder VM and records
  that fact in launch attestation.
- `mvm explain <run-id>` can reconstruct the artifact, policy, snapshot/warm,
  backend, and command chain for representative success and refusal cases.
- Security tests cover tampered packs, revoked signatures, expired metadata,
  poisoned cache entries, mutable inputs, and secret-before-snapshot prevention.
- Live evidence records prepared warm-claim, prepared snapshot-restore,
  prepared cold-direct-boot, builder warm-claim, and builder snapshot-restore
  timings.

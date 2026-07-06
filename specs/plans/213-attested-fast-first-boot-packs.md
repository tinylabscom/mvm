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

- [ ] Extend the release pipeline to produce runtime packs for each supported
      host architecture/backend pair.
- [ ] Extend the release pipeline to produce builder packs for each supported
      builder architecture.
- [ ] Include seeded Nix closures for common mvm build and materialization paths
      in builder packs.
- [ ] Emit SBOMs, checksums, signatures, provenance, and pack manifests for every
      release pack.
- [ ] Add release verification checks that fail closed when any pack lacks a
      manifest, signature bundle, checksum, SBOM, or expected version metadata.
- [ ] Add a reproducibility verification job that rebuilds at least one published
      runtime pack and one published builder pack from source pins and compares
      output hashes.
- [ ] Document the release artifact matrix and channel semantics in the release
      notes or packaging reference.

### C. Hardened local artifact cache

- [ ] Add a content-addressed pack cache under the existing mvm cache helpers,
      respecting `MVM_CACHE_DIR` and XDG isolation.
- [ ] Download and extract packs into quarantine paths before atomic promotion.
- [ ] Enforce restrictive permissions on cache directories and promoted pack
      contents.
- [ ] Reverify manifest, hashes, signatures, expiry, revocation, and policy
      compatibility before every use.
- [ ] Add cache indexes for pack hash, kind, architecture, backend, channel,
      expiry, size, and last-used time.
- [ ] Implement `mvm cache status` showing local packs, readiness, size, expiry,
      revocation state, and instant-launch eligibility.
- [ ] Implement `mvm cache prune` with policy-aware deletion that refuses to
      remove packs needed by active snapshots or warm standbys.
- [ ] Add tests for interrupted downloads, partial extraction, atomic promotion,
      permission hardening, cache poisoning attempts, and policy-aware pruning.

### D. Install and prepare UX

- [ ] Add install-time or first `mvm dev up` preparation for the default runtime
      pack and builder pack when network and policy allow.
- [ ] Add `mvm prepare <image-or-flake>` to resolve inputs, download or build
      packs, verify them, and optionally derive local snapshots/warm standbys.
- [ ] Add `mvm prepare --dry-run <image-or-flake>` showing download size, cache
      impact, builder-VM need, trust state, and expected fast-path eligibility.
- [ ] Make `machine run` report precise preparation reasons when instant launch
      is unavailable: missing pack, mutable input, private input, expired
      signature, revoked signer, unsupported backend, incompatible host, or local
      rebuild required.
- [ ] Add CLI integration tests for prepared fast-path messages, cache-miss
      messages, policy-refusal messages, and explicit builder-VM prepare
      messages.
- [ ] Update CLI reference and getting-started docs for prepare/cache behavior.

### E. Runtime pack launch path

- [ ] Add a launch path that consumes a verified runtime pack without booting the
      builder VM.
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
- [ ] Reject instant launch for mutable OCI inputs that cannot be resolved to a
      digest under current policy.
- [ ] Resolve flake inputs to committed locks before pack eligibility or
      admission.
- [ ] Build unpublished or private OCI/flake artifacts inside the builder VM and
      publish them only to the local content-addressed cache unless the user
      explicitly exports them.
- [ ] Key setup-cache layers by image digest, flake lock hash, setup command
      hash, environment-relevant inputs, mount shape, runtime pack hash, and
      policy hash.
- [ ] Add positive and negative tests for OCI digest resolution, flake lock
      resolution, setup-cache hits, and setup-cache invalidation.

### H. Launch attestation and explainability

- [ ] Define the launch attestation record linking source input, builder
      identity, pack identity, local verification, snapshot/warm derivation,
      policy admission, command, and result.
- [ ] Store launch records in a tamper-evident local audit log.
- [ ] Include command, plan hash, network policy hash, artifact hashes,
      snapshot/warm identity, backend identity, launcher version, timestamps,
      exit status, and output digest metadata.
- [ ] Implement `mvm explain <run-id>` for successful launches, builder-prepare
      launches, cache misses, and refusals.
- [ ] Add tests proving audit records are emitted on success, refusal, builder
      fallback, verification failure, and interrupted launch.
- [ ] Add tamper tests proving modified audit records are detected.

### I. Revocation, mirrors, and enterprise policy

- [ ] Add artifact-channel configuration with pinned channel identity and signing
      key set.
- [ ] Add revocation metadata fetching and offline-cache behavior.
- [ ] Add key rotation support that accepts overlapping keys only within an
      explicit policy window.
- [ ] Add enterprise mirror configuration for pack downloads and revocation
      metadata.
- [ ] Add policy modes for online default, offline pinned, mirror-only, and
      local-rebuild-required operation.
- [ ] Add tests for revoked artifacts, expired artifacts, stale revocation
      metadata, mirror mismatch, offline pinned launch, and local-rebuild
      enforcement.
- [ ] Document channel pinning, mirror setup, offline operation, and revocation
      behavior.

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

- [ ] Update `public/src/content/docs/reference/cli-commands.md` for
      `mvm prepare`, `mvm cache status`, `mvm cache prune`, and `mvm explain`.
- [ ] Update installation docs to describe install-time pack preparation,
      download sizes, cache locations, opt-out, and offline/mirror behavior.
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

## Slice 1 — tracer bullet: seed the persistent builder store from a verified pack

**Status: designed 2026-07-06; not yet built.**

The first vertical proves the whole pack path end-to-end while landing
independently of the two unmerged mega-stacks (Plan 214 backend unification and
Plan 227 hvf snapshot/restore). It slices WS-B, WS-C, and WS-F thin and defers
E/G/H/I/J/K.

### Framing decisions (settled in brainstorm)

- **Backend-agnostic artifacts, hvf lands first.** Pack artifacts (builder base
  disk, builder kernel, seeded store image) come from the shared
  `nix/images/builder-vm/` flake and are byte-identical across backends, so the
  manifest lists every compatible backend in `backend_compatibility`. The local
  fast-boot/seed path is wired for the hvf backend first (macOS-26 default, no
  Homebrew prerequisites, and the strategic destination); libkrun/Linux wiring is
  a later additive slice.
- **`PackBackend` gains an `hvf` variant.** `verify_pack_at` matches
  `backend_compatibility` against `LocalPackPolicy.backend`, so the enum must be
  able to name the in-house/HVF backend regardless of the agnostic framing. This
  is the one schema change slice 1 makes.
- **Value comes from the seeded store, not a memory snapshot.** hvf has no
  snapshot primitive yet (Plan 227 WS-E). With the Stage 0 store now persistent
  on macOS, the cost a pack eliminates is the multi-minute Stage 0 store
  population, not VM boot. Slice 1 therefore ships no memory snapshot and no
  resident warm-standby.
- **Warm is measured, not assumed.** After the seeded store lands, slice 1 boots
  the hvf builder cold with the warm store and measures it live on available
  hardware. Resident warm-standby (a full hvf resident host-VM lifecycle) becomes
  slice 2, gated on that measurement showing cold-boot is insufficient.
- **Seed format: ready-to-mount ext4 Nix-store image.** The pack ships a
  materialized store image, not a NAR closure. The fast path is then verify +
  place + write the persistent-store reuse marker — zero seed-boot — reusing the
  reuse machinery already on main. A NAR-import variant is a later refinement if
  ADR-097 ratification demands strict NARs-only publishing.
- **Seed scope: the default `dev up` / `build image` dev-shell closure.** The
  first-hit path for a fresh install. Private flakes and OCI still route through
  the normal builder path; OCI `run --image` is already builder-VM-free
  (materialized in-process host-side) and needs no pack.
- **Rollout: opt-in `MVM_BUILDER_PACK=1`.** Default path stays byte-identical
  until the live measurement proves the pack path, then a later slice flips the
  default. Source-checkout builds never take the pack path (they build from
  in-repo flakes); the flag is a no-op wherever `find_builder_vm_flake()` returns
  a local flake, enforced the same way release-artifact download is gated today.

### ADR-097 amendments this slice requires

ADR-097 is Proposed; slice 1 ratifies it with two edits (a separate docs change):

1. Add the in-house/HVF backend to the backend set packs may target.
2. Clarify §5 so a content-addressed, deterministically-rebuildable store image
   is a publishable Nix output, not host-derived local-only state. Memory
   snapshots remain local-only. `pack-hash-as-identity` is unchanged.

### Units (each independently testable)

**Unit 1 — pack producer (WS-B thin).** A CI/release step plus a local
example/xtask tool that takes the builder-VM flake outputs (base disk + builder
kernel) and a materialized seeded store image for the dev-shell closure, and
emits a signed `Builder` `PackManifest` + file set. Consumes the existing
`mvm_core::packs` types unchanged except the new `PackBackend::Hvf`. Output: one
`aarch64-darwin` builder pack.
Tests: produced pack round-trips through `verify_pack_at` green; tamper on each
file + manifest field goes red.

**Unit 2 — content-addressed pack cache (WS-C thin).** `place → quarantine dir →
verify_pack_at → atomic rename-promote` under `mvm_core::config` cache helpers
(`mvm_cache_dir`), permission-hardened (0700). Interface:
`resolve_pack(kind, arch, backend) -> Result<VerifiedPackDir>`.
Tests: interrupted download, partial extraction, atomic promotion, permission
hardening, poisoned-entry rejection — all with a locally-produced pack, no
network.

**Unit 3 — seed materializer + flag-gated hvf boot (WS-F thin).** Given a
`VerifiedPackDir`, lay the seeded store image + base disk into the
`~/.cache/mvm/builder-vm/` layout the persistent-store reuse path recognizes,
write the reuse marker, then boot the hvf builder with the warm store behind
`MVM_BUILDER_PACK=1`. Emit phase timing to capture the live measurement.
Tests: materialize lands the exact layout + marker the reuse path expects;
flag-off = byte-identical default path; source-checkout = no-op. Live: one
measured `dev up` with the pack vs. cold Stage 0 on this Mac.

### Data flow

```
release CI -> signed builder pack -> download -> quarantine -> verify_pack_at
  -> atomic promote -> materialize seeded store + reuse marker
  -> hvf boot (warm store, MVM_BUILDER_PACK=1) -> measured first build
```

### Slice-2 trigger

If the measured hvf cold-boot-with-warm-store is too slow to feel "warm," slice 2
adds a resident hvf warm-standby (an `HvfPersistentHostVm` lifecycle + warm
claim, analogous to the libkrun resident builder), reusing the backend-agnostic
`mvm_core::residency` policy layer. Otherwise slice 1 already delivered warm.

### Deferred follow-ups (surfaced during Unit 1 review)

- **Typed output hashes are attested, not cross-checked.** The verifier validates
  that per-file hashes match content, but the typed `kernel_hash` / `rootfs_hash`
  / `builder_image_hash` etc. are caller-asserted and never re-derived from the
  named files by either the producer or `verify_pack_at`. A pack could therefore
  carry a typed output hash that disagrees with the file it names and still
  verify. Low risk for slice 1 (the file-level hash still pins every byte), but
  the producer should eventually derive the typed hashes from the file set, or
  the verifier should cross-check them. Tracked here, not fixed in slice 1.

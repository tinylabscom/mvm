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
      (`default-microvm` job in `.github/workflows/release.yml` produces +
      keyless-signs + publishes a runtime pack — kernel + verity-sealed rootfs +
      sidecars — per arch, on a version-tag push whose version matches the crate.)
- [ ] Extend the release pipeline to produce builder packs for each supported
      builder architecture.
- [ ] Include seeded Nix closures for common mvm build and materialization paths
      in builder packs.
- [x] Emit SBOMs, checksums, signatures, provenance, and pack manifests for every
      release pack.
      (Both the builder-pack and runtime-pack producers emit a store-path SBOM,
      a per-arch checksums manifest listing the pack files, a cosign
      `--new-bundle-format` signature bundle, and the pack manifest.)
- [x] Add release verification checks that fail closed when any pack lacks a
      manifest, signature bundle, checksum, SBOM, or expected version metadata.
      (builder-pack **and** runtime-pack completeness gates in
      `packaging/release/verify-release-assets.sh` — each pack must be COMPLETE
      or entirely ABSENT; a partial or checksum-mismatched pack fails closed.)
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
      Partial: `mvm prepare [--dry-run]` ships for the host default runtime
      pack (no positional input yet — see Deferred below).
- [x] Add `mvm prepare --dry-run <image-or-flake>` showing download size, cache
      impact, builder-VM need, trust state, and expected fast-path eligibility.
      Scoped to the host default runtime pack: reports the same readiness/
      reason as the non-dry-run mode (no download/build side effect exists yet
      to preview) — see Deferred below.
- [x] Make `machine run` report precise preparation reasons when instant launch
      is unavailable: missing pack, mutable input, private input, expired
      signature, revoked signer, unsupported backend, incompatible host, or local
      rebuild required. `mvm_core::pack_cache::diagnose_pack` surfaces the first
      rejection `resolve_pack` would otherwise swallow; `not_instant_reason`
      maps it to one of these precise causes for the default (no `--manifest`/
      `--image`/`--runtime-pack`) launch path's build-fallback message.
- [x] Add CLI integration tests for prepared fast-path messages, cache-miss
      messages, policy-refusal messages, and explicit builder-VM prepare
      messages. Coverage: `not_instant_reason` unit tests cover Ready/
      NoCompatiblePack/several `Rejected` reasons (architecture, backend,
      expiry, revocation, untrusted key, tamper); `mvm prepare --help`/
      `--dry-run` CLI parse tests. No CLI-level "prepared fast-path" (Ready)
      integration test exists — it needs a real promoted+keyless-verified pack
      fixture, which no test in the tree constructs offline (same limitation
      noted for the auto-prefer accelerator).
- [ ] Update CLI reference and getting-started docs for prepare/cache behavior.

#### Deferred

Arbitrary `mvm prepare <image-or-flake>` (resolve + download + build +
snapshot) is gated on §C (the content-addressed pack download cache) and §F
(builder-prepare). This slice delivers the host-default-runtime-pack-scoped
`mvm prepare [--dry-run]` plus precise `machine run` not-instant reasons only;
`prepare` takes no positional argument yet.

### E. Runtime pack launch path

- [ ] Add a launch path that consumes a verified runtime pack without booting the
      builder VM.
- [ ] Create per-run CoW sandboxes from prepared image/project artifacts.
- [ ] Derive an agent-ready local runtime snapshot after verifying the runtime
      pack and before injecting secrets.
- [ ] Record snapshot derivation events with parent pack hash, backend id,
      backend version, memory/CPU shape, policy hash, and agent readiness proof.
- [x] Prefer warm-standby claim for prepared runs; fall back to local snapshot
      restore; fall back to prepared cold direct boot; fall back to builder
      prepare only when required.
      **Finding:** the warm-standby claim, replenish, and saved-state-snapshot
      path is source-agnostic — it derives its compatibility key from the
      resolved `VmStartConfig` (kernel + rootfs + resources), never from the
      `ImageSource` variant. A pack-sourced prebuilt launch therefore already
      participates in the warm pool and saved-state snapshot exactly like any
      admitted workload, with no pack-specific plumbing; a dedicated
      template-style snapshot path for prebuilt sources would duplicate the
      existing saved-state standby mechanism (rejected as redundant). Locked in
      by `runtime_pack_prebuilt_config_is_warm_eligible_and_keys_on_pack_identity`
      (asserts a pack config keys on the pack's own kernel identity and stays
      claim-eligible). Backend caveat: warm-pool participation is bounded by which
      VMM implements the standby pool (libkrun today); extending it to the other
      workload backends is separate backend work, not a pack concern.
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

#### §I progress — builder-pack revocation consumer (2026-07-08)

- [x] Installed builder-pack resolution now refreshes a project-signed
      `pack-revocations.json` from the `revocations` release, caches it under
      `~/.cache/mvm/pack-revocations/` with a 24-hour refresh / 7-day offline
      tolerance / `404` bootstrap state, and unions fetched entries with the
      operator's `pack-trust.json` revocations.
- [x] Tests: absent cache pair and a garbage cosign bundle both fail open on
      availability while refusing to apply an unverifiable fetched list.

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

**Progress:** Unit 1 landed (`PackBuilder` producer + `PackBackend::Hvf`). Unit 2
landed (content-addressed `pack_cache` — verify + atomic promote). Unit 3 landed
as the corrected **attested builder-image download materializer** (see the "Slice 1
correction" section) — flag-gated on `MVM_BUILDER_PACK`, offline-tested. Follow-up
F landed the **configurable trust root** (`mvm-core::pack_trust` + a
`mvm_keys_dir()/pack-trust.json` loaded on the host): the attested path now
verifies against a real on-disk trust root instead of an empty store, proven
end-to-end (produce → promote → resolve → verify → materialize), with an absent or
malformed trust file staying inert and falling through to the plain download. An
embedded release-key default (so it works with no config) remains for the
release/trust workstream.

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
- **Quarantine orphans have no reaper.** The pack-cache promote path stages into
  a `.incoming/<unique>` quarantine dir and cleans it on the error path, but a
  panic or process kill between the copy and the atomic rename leaves the
  quarantine dir behind. Readers skip `.incoming`, so this is disk-usage only, not
  a correctness or safety issue. A sweep of stale quarantine dirs belongs with the
  existing prefix-agnostic cache reaper rather than in this slice.

## Slice 1 correction (2026-07-06): Stage-0 target retired → attested builder download

Recon during Unit 3 design (plus an isolated live probe) invalidated the
original Unit 3 target and re-pointed the slice. Recorded here so the earlier
"seed the persistent builder store" framing above is understood as superseded
for the installed path.

### What we learned

- **The builder-image acquisition path is source-vs-installed split.**
  `resolve_builder_vm_bootstrap_action` returns `BuildFromSource` (which runs
  Stage 0 — the multi-minute Nix store population) only on a **source checkout**;
  an **installed binary** with no in-repo builder flake takes `DownloadPublished`
  and never runs Stage 0. The pack path is (correctly) a no-op on source
  checkouts, so a Stage-0-store materializer would have **no consumer on the
  installed binaries the pack is for**. The multi-minute figure motivating the
  slice was a source-checkout cost.
- **The installed builder's base `/nix/store` ships inside `rootfs.ext4`** as the
  overlay lowerdir (`mvm-host-vm-init` mounts `/nix` = overlay(seed lowerdir,
  persistent `nix-store-<arch>.img` upperdir)). The upperdir is formatted empty
  on first boot and holds only net-new paths. So there is no separately-seedable
  base store; the base closure rides in the published rootfs seed, already
  Nix-DB-registered via `/nix-path-registration`.
- **`DownloadPublished` already delivers the fast base but with no attestation.**
  `download_builder_vm_image` fetches `vmlinux` + `rootfs.ext4` under a plain
  per-arch SHA-256 checksum — no signature, no content-addressing, no revocation.
  That is the real gap the pack schema (Unit 1) + verified cache (Unit 2) close.

### Corrected Unit 3 — attested builder-image download (supersedes the Stage-0-seed materializer)

Unit 3 becomes the **attested-download materializer**: given a verified Builder
`VerifiedPackDir` carrying `vmlinux` + `rootfs.ext4` (+ `kernels/`, `cmdline.txt`),
place them into `BUILDER_DIR/<arch>` — the exact directory `DownloadPublished`
writes — and write the `.mvm-source.sha256` / `.mvm-artifacts.sha256` /
`.mvm-provenance.json` markers so `builder_vm_source_cache_ready` reports ready
and the next resolve takes `UseCached`. Gated behind `MVM_BUILDER_PACK=1`; a no-op
on source checkouts (`find_builder_vm_flake().is_ok()`) and byte-identical to
today when off. The flag routes the `DownloadPublished` arm
(`perform_builder_vm_download_published`) through the materializer instead of the
plain checksum fetch.

Offline-testable exactly like Units 1–2: promote a synthetic Builder pack via
`PackBuilder`/`pack_cache::promote`, materialize into a temp `out_dir`, and assert
the placed files + markers make `builder_vm_source_cache_ready` return true; plus
flag-parse and source-checkout-no-op predicate tests. The **network fetch** of the
attested pack from a release channel (trust store + URL scheme) is deferred to the
release/trust workstreams (WS-B/I) — this unit is the local verify-and-place core.

### Speed spun out to a measurement-gated pipeline follow-up

"Fast first build" is decoupled from provenance. The installed first-build cost is
the closure delta beyond the published rootfs seed; the structurally-clean lever is
**fattening that published seed closure** at build time (delivered through the
existing download + the attested pack above), not a runtime store materializer. It
must be sized by a clean benchmark on a quiet box (the shared dev box was too
contended, and an isolated harness broke the builder's virtiofs share wiring), so
it is tracked as a follow-up, not part of this slice.

### Deferred follow-ups (surfaced during Unit 3 review)

- **Attested materializer writes markers the installed path ignores.** The
  installed-binary readiness gate is `validate_builder_vm_stage0_artifacts`
  (placed `vmlinux` + `rootfs.ext4`), not the `.mvm-source.sha256` fingerprint
  marker — that marker is only consulted on the source-checkout path, which the
  pack path excludes. The materializer currently reuses the shared source-cache
  sidecar writer, so it emits superfluous markers and, worse, stamps
  `.mvm-provenance.json` with `source_kind: "source_checkout_stage0"` — wrong for a
  verified download. Cleanup: place the two artifacts + validate against the
  installed gate, and either drop the sidecar write on this path or thread a
  distinct attested-origin kind through the shared readiness predicate (which the
  source-checkout path also depends on). Cosmetic-only today (the label never gates
  the installed readiness decision), so deferred. **Revisited: still deferred.** The
  only atomic stage→rename primitive (`promote_builder_vm_stage0_cache`) hard-requires
  all three sidecars — it bails when the fingerprint/artifact-digest/provenance
  markers are missing or mismatched and re-asserts `builder_vm_source_cache_ready`
  after the rename — and the source-checkout local-build path calls the same
  function. Dropping the sidecar write on the attested path would require forking that
  primitive or loosening its shared contract, so it is not cleanly separable and stays
  deferred until the attested-origin kind is threaded through the shared predicate.
- **Attested materializer is production-inert until trust keys land.** The verify
  context is built with an empty trust store and empty allowed-channels, so on a
  real binary `resolve_pack` always returns `None` and the flag path falls through
  to the plain checksum download (fail-open, safe). The end-to-end verify→place
  chain is proven under test injection; wiring the real release-channel trust store
  + policy is the release/trust workstream, not this slice.
- **`policy_hash` convention is duplicated producer↔consumer.** ✅ Resolved.
  Extracted `mvm_core::packs::host_pack_policy_hash(arch)` (single owner, unit-tested
  against a known arch); the producer (`mvm-build::builder_pack`) and the host consumer
  (`mvm-cli` `host_pack_verify_inputs`) both call it instead of recomputing
  `Sha256Hex::from_bytes(arch.nix_system().as_bytes())` inline.

## Slice 2 (2026-07-07): release signing custody — un-inert the installed pack path

Slice 1 shipped the pack chain production-inert: on a real installed binary the
trust store is empty, so `resolve_pack` always returns `None` and the flag path
falls through to the plain SHA-256 download. Slice 2 closes the two Slice-1
deferrals — the **embedded release-trust default** and the **release-pipeline
wiring** — under the custody model settled in ADR-097 §9 (keyless public channel
via GitHub OIDC → Fulcio → Rekor; ed25519 `pack-trust.json` unchanged as the
operator/fleet lane).

The design decisions (settled before this slice; see ADR-097 §9):

- Public release packs are keyless-signed under the CI workflow OIDC identity; the
  detached Sigstore bundle rides beside the pack as a sidecar over the exact
  manifest bytes. No long-lived signing key exists.
- Verification pins **both** the Fulcio issuer and an **exact-match** subject
  identity (Sigstore has no glob/regex), plus the Rekor inclusion proof. The
  concrete identity is built at verify time by interpolating the binary's own
  version into a compiled-in **template**
  (`…/.github/workflows/<release>.yml@refs/tags/v<version>`), exactly as
  `crypto::image_verify` already does — so a binary trusts only packs from its own
  release tag. The compiled-in material is a *list of templates* (not a scalar) so
  a repo/workflow rename migrates by add-then-drop; the version is never listed.
- The keyless verifier is a separate outer verifier that reuses the existing
  `mvm_core::crypto::image_verify::verify_signed_payload(payload, bundle, identity,
  issuer)` primitive for the signature/cert/Rekor check, then runs the *same*
  shared structural/hash/policy/expiry/revocation middle as `verify_pack_at`; only
  the signature step differs. It lives in `mvm-core`, gated behind
  `manifest-verify`, with trust inputs (the concrete accepted-identity list,
  issuer, policy, operator config) passed as parameters.
- Embedded keyless root is always active for the public channel; `pack-trust.json`
  is purely additive. The disable/pin-to-operator switch is deferred to §I.
- Revocation stays config-driven (`PackTrustConfig.revocations`) this slice;
  fetching the live `revocation_channel` is deferred to §I.

### Unit 1 — keyless verifier + manifest authority shape (`mvm-core`, `manifest-verify`-gated)

- [x] Make a pack self-declare its signing authority (settled reshape): add
      `SignatureFormat::Sigstore`; the bundle's `format` is the authority
      declaration. A `Sigstore` pack carries empty `signatures` (the detached
      sidecar is authoritative) and a `signing_key_id` set via a new
      `KeyId::from_identity(&str)` (sha256 of the signing identity, 32 hex — a
      stable well-formed id for revocation keying and audit, not a pubkey hash), so
      no fake ed25519 key is invented. Downgrade safety falls out: the ed25519
      `validate_signature_bundle` already rejects a non-`Ed25519` format, and the
      keyless path rejects a non-`Sigstore` format.
- [x] Factor `validate_manifest` into `validate_manifest_structural` (everything
      except `validate_signature_bundle`) + the per-authority signature-shape check.
      Shared middle both verifiers call = `validate_manifest_structural` +
      `verify_files` + `verify_pack_hash` + `verify_revocation`; the signature-shape
      and signature-verify steps stay per-authority.
- [x] Add `verify_pack_keyless_at(manifest, root, policy, cosign_bundle,
      keyless_trust, revocations)`: check `format == Sigstore` + empty signatures,
      call `image_verify::verify_signed_payload(manifest.canonical_bytes, bundle,
      identity, issuer)` for each accepted identity in `keyless_trust` (exact-match;
      succeed on any), then run the shared middle. `keyless_trust` (accepted-identity
      list + issuer) is a parameter; no `mvm-cli` dep. Populate
      `TrustMetadata.transparency_log` from the verified Rekor entry.
- [x] Tests: valid bundle + pinned identity verifies; wrong issuer rejected; wrong
      subject/SAN rejected; tampered manifest rejected; absent/bad Rekor inclusion
      proof rejected; expired cert rejected; a keyless pack presented to the ed25519
      verifier (and vice versa) is rejected — no downgrade; shared-middle rejections
      still fire (revoked signer, expired trust, arch/backend/policy mismatch, pack
      hash mismatch).

### Unit 2 — embedded identity allow-list + trust-root wiring

- [x] Add a compiled-in `RELEASE_IDENTITY_TEMPLATES` constant (issuer + a list of
      subject templates like `https://github.com/<org>/<repo>/.github/workflows/<release>.yml@refs/tags/v{version}`),
      validated by test, multi-entry for identity migration. A helper interpolates
      the binary's `CARGO_PKG_VERSION` into each template to build the concrete
      exact-match accepted-identity list. Fulcio/Rekor roots come from the vendored
      Sigstore trust root via `verify_signed_payload` (no separate wiring).
- [x] Build the host keyless verify context: embedded allow-list always active;
      `pack-trust.json` additive for ed25519 publishers/channels/revocations. Update
      `host_pack_verify_inputs` (and any runtime consumer) to construct the keyless
      context when `manifest-verify` is on, ed25519-only otherwise.
- [x] Un-inert the installed pack path: with the embedded allow-list present,
      `resolve_pack` on an installed binary verifies a real release pack instead of
      always returning `None`; source checkouts stay a no-op.
- [x] Tests: allow-list constant is well-formed; a pack signed by the pinned
      identity verifies against the embedded default with no on-disk config; an
      off-pattern identity is rejected; an additive `pack-trust.json` still adds
      ed25519 publishers alongside the embedded keyless root.

### Unit 3 — release pipeline: produce, sign, publish

- [x] Extend the release workflow so that per supported arch/backend it builds the
      builder pack via `mvm-builder-pack-tool --keyless`, signs the manifest with
      keyless `cosign sign-blob` under the workflow OIDC identity (official cosign
      action; `id-token: write`), and publishes the sidecar bundle + SBOM +
      checksums + manifest alongside the existing `vmlinux`/`rootfs.ext4` assets.
      (Runtime pack producer/publish deferred — builder pack first.)
- [ ] Restrict the signing job to protected tag refs / a protected environment so
      the pinned subject identity cannot be minted from an arbitrary ref.
- [x] Add the release verification gate (plan §B) that fails closed when any pack
      lacks a manifest, bundle, checksum, SBOM, or expected version metadata.
      (`verify-release-assets.sh` builder-pack gate: complete-or-absent, checksum-
      matched; self-tested + CI-linted.)
- [ ] Validate the workflow off release tags via `gh workflow run --ref <branch>`
      (the release/security workflows are tag/nightly-gated and PR-invisible).

### Unit 4 — consume the published pack (network leg) — completion step

- [x] Route the installed `DownloadPublished` arm through an attested fetch:
      `fetch_release_builder_pack_staging` downloads manifest + cosign bundle +
      artifacts into a temp staging dir, `promote_staged_builder_pack` keyless-
      verifies + promotes into the pack cache, then the existing resolve
      materializes — gated on `manifest-verify` + the `MVM_BUILDER_PACK` selection,
      fail-open to the plain download otherwise.
- [x] Tests: `promote_staged_builder_pack` fail-closed on garbage/missing cosign
      bundle (cache untouched) + malformed manifest error; the network GET is thin
      (`download_file`) and proven in CI, not offline. Positive end-to-end verify
      needs a real cosign bundle → CI/tag-time.

> Unit 4 overlaps plan §C/§D and may spill into a Slice 3 if Units 1–3 land large;
> Units 1–3 alone discharge both Slice-1 deferrals (embedded default + pipeline).

### mvmd / fleet interop (explicit — ADR-097 §9)

- [ ] Keep the keyless verifier in `mvm-core`, `manifest-verify`-gated, with trust
      inputs as parameters, so mvmd reaches it by enabling one feature on its
      `mvmctl` dep (the mvmd-side feature flip is tracked in the mvmd repo, not here).
- [ ] Keep the identity allow-list and the future pin/disable behavior as data and
      policy, not hardcoded control flow, so a fleet layers its own trust policy on
      top. The ed25519 operator lane is the fleet-internal signing lane.

### Deferred (named, out of Slice 2)

- Disable-public-channel / pin-to-operator-only, offline-pinned, mirror-only,
  enterprise policy modes → §I.
- Live revocation-channel fetch + offline-cache behavior → §I.
- Runtime-pack keyless launch path (§E) beyond producing/publishing the runtime
  pack in Unit 3.

### Units 1–2 status: COMPLETE (2026-07-07)

Landed on `worktree-plan-213-release-signing-custody`, TDD + subagent-driven,
final whole-branch security review clean (no Critical/Important):

- U1: `KeyId::from_identity` (`e4d4df15`), `SignatureFormat::Sigstore` (`5dbf9392`),
  `validate_manifest_structural` split (`10835671`), `verify_pack_keyless_at` +
  `KeylessTrust` + keyless shape gate (`08d7c5d9`).
- U2: `release_trust` embedded identity templates + channels (`9ce91a08`),
  `PackVerifyCtx` keyless strategy + bundle-sidecar carry/reserve (`aec75ab7`),
  un-inert the installed `mvm-cli` path + `keyless_release_policy` (`48d02464`).

Verified: mvm-core `1562` tests under `manifest-verify`, mvm-cli attested suite
`11/11` (both features) / `10/10` (ed25519-only); default build stays
runtime-free (no `tokio`); both feature paths compile; downgrade-safe both
directions; no fabricated-positive tests (the keyless-signature success path is
proven by Unit 3's pipeline, not offline).

**Operational note for Unit 3:** the keyless path is `manifest-verify`-gated and
the root `default` feature set does NOT include it — the un-inert behavior only
engages in a build that pulls `manifest-verify` (the `user` bundle). The release
pipeline (and the published binaries) MUST build with that feature or the
embedded root stays inert.

### Review follow-ups (Minor, deferred with a home)

- ✅ **Cross-bind `signing_key_id` to the verifying keyless identity** — the
  keyless verifier now only considers accepted identities whose
  `from_identity` equals the stamped `signing_key_id`, and refuses a pack whose
  id matches none (`SignerIdentityMismatch`) before any signature is examined.
  The signature and the id revocation keys on can no longer name different
  signers — the prerequisite for trustworthy keyless revocation (§I).
- **Keyless materialization error short-circuits the ed25519 fallback** — a
  placement (not resolution) error in the keyless attempt propagates and skips
  the ed25519 attempt before falling through to the plain download. Fail-safe
  (same cache, ends at download); tighten when Unit 4 reworks the attempt
  ordering around the network fetch.

### Units 3–4 status: builder-pack pipeline + fetch LANDED (2026-07-07)

- U3 (`b185523f`): `release.yml` `builder-vm-image` job now installs Rust + cosign,
  exports `STORE_PATH` to `$GITHUB_ENV`, generates a nix-closure SBOM, runs
  `mvm-builder-pack-tool --keyless` to emit a Sigstore-authority manifest under the
  workflow OIDC identity (`--identity …@${github.ref}`), `cosign sign-blob`s it, and
  publishes `builder-vm-{arch}.pack-manifest.json` + `.bundle` + `.sbom.txt`.
- U8 producer (`ceb28d14`): `PackBuilder::new_keyless`/`build_sigstore` (mvm-core),
  `build_keyless_builder_pack` (mvm-build), tool `--keyless` mode.
- U4 fetch (`d15136e4`): download → keyless-verify → promote into the pack cache,
  wired fetch-on-miss into `attempt_attested_builder_pack`.

**Validated:** producer smoke-test (exact release CLI invocation → valid Sigstore
manifest), fetch fail-closed tests, `release.yml` YAML + actionlint clean, published
asset names == fetch asset names. **NOT validated locally (tag-time only):** cosign
OIDC signing, the nix image build + SBOM step, and end-to-end publish→download→verify.
Prove on the next tagged release (or `gh workflow run` against the branch, which the
release job's dry-run guards partially exercise).

### Units 3–4 follow-ups

- ✅ **Release verification gate (§B)** — `verify-release-assets.sh` now fails the
  release closed on a partial / checksum-mismatched / unlisted builder pack
  (complete-or-absent), with a self-contained fixture test wired into CI Lint.
- ✅ **cosign bundle format** — the Rust `sigstore-verify` stack rejects the legacy
  `cosign sign-blob --bundle` output; every Rust-verified signing step (builder
  pack + dev-image manifest) now signs `--new-bundle-format`, proven live by the
  pack-signing smoke round-tripping both paths.
- **Protected environment for the signing job** so the pinned SAN can't be minted
  from an arbitrary ref (beyond the existing tag-push gate).
- **Producer SBOM URI is `file://<local path>`** (unverified provenance metadata,
  harmless) — add a `--sbom-uri` so the published manifest records the release URL.
- **`PackBuilder::build()` panics on a keyless-constructed builder** — a
  programmer-error `.expect`, unreachable from current callers; make illegal states
  unrepresentable (typed authority) when the producer is next touched.
- **Runtime-pack producer/publish** (only the builder pack is wired).
- **gh workflow run validation** on the branch before the first real tag.

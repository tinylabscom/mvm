# ADR 050: Verity posture for pulled OCI images

- Status: Proposed
- Date: 2026-05-14
- Owner: MVM Project
- Related: ADR-002 (microVM security posture, claim 3), ADR-005 (image acquisition), ADR-014 (builder VM via libkrun), ADR-041 (claim-safe sandbox parity), Plan 74 W1, Plan 74 §Risks R3, mvmd ADR-0020 (OCI images as microVM workloads)

## Context

Plan 74 W1 adds `mvmctl image pull <ref>` so users can launch
arbitrary OCI images in microVMs without a host Docker daemon.
The pull path materializes an OCI image to an ext4 rootfs and
registers it as a first-class template.

The project's existing claim 3
([`CLAUDE.md` "Security model"](../../CLAUDE.md))
is **"a tampered rootfs ext4 fails to boot,"** enforced by:

- `nix/flake.nix::verityArtifacts` — runs `veritysetup format`
  deterministically against the rootfs, emits `rootfs.verity`
  sidecar + `rootfs.roothash`.
- `mvm-verity-init` initramfs — built once, reused per image, runs
  as PID 1, mounts dm-verity over the rootfs, panics on
  block-level tamper.
- `mvm.roothash=<hex>` on the kernel cmdline, passed by every
  backend's `start_with_verity` path.
- `probe_verity_sidecar` (`crates/mvm-backend/src/microvm.rs`)
  conditionally attaches the sidecar at `/dev/vdb` and the
  initramfs as `initrd`.

Today every production launch goes through this path because every
production image is Nix-built. OCI input is arbitrary — the user
supplies a registry reference, mvm pulls layers, unpacks to ext4,
and launches. Without further policy, claim 3 silently weakens: a
pulled image may have no verity sidecar at all, and
`probe_verity_sidecar` returns `(None, None)` instead of panicking.

Two architectural options for keeping (or relaxing) claim 3 under
OCI ingest:

**Option A — Pull-time verity generation.** Every pulled image gets
a sidecar + roothash generated at pull time. Claim 3 remains
unchanged: every production launch carries verity.

**Option B — Documented carve-out.** Pulled images live in an
"unverified" template lane. Claim 3 narrows to
"Nix-built and prebuilt images." Audit chain (claim 8) is offered
as the integrity story for pulled images.

This ADR picks before W1 codes.

## Decision

**Option A — pull-time verity generation, by default, in the
production profile.** A `--no-verity` opt-out is available in the
dev profile only. Production-profile admission rejects images
without a verity sidecar.

### Generation flow

1. `mvmctl image pull <ref>` runs inside the libkrun builder VM
   (Plan 72 default). The builder VM has `veritysetup` available
   as part of its base closure — adding it costs a single
   `cryptsetup` dependency that's already transitively needed for
   `nix/flake.nix::verityArtifacts`.
2. After layer unpack produces `rootfs.ext4`:
   - Run `veritysetup format --data-block-size=4096
     --hash-block-size=4096 rootfs.ext4 rootfs.verity` and capture
     the roothash.
   - Write `rootfs.roothash` next to the rootfs in the template
     directory, same shape as Nix-built templates.
3. `probe_verity_sidecar` already detects the pair; no plumbing
   change in `mvm-backend`.
4. Template registry records `(requested_ref, resolved_digest,
   source_registry, cache_scope, verity_roothash)`. The roothash
   becomes a content-addressable identifier — re-pulling the same
   digest hits the verity cache.

### Caching

Layer fetch is already content-addressed by digest. Verity
generation is deterministic with pinned block sizes and pinned
zero salt. Cache key: `sha256(layer-digests-sorted)`. Cache hit
skips both the unpack and the verity generation. Cache lives
under `~/.cache/mvm/oci/verity-by-digest/<digest>.{verity,roothash}`,
mode 0700 directory per claim W1.5.

### Production-profile admission

Plan 74 W1 already specs production-profile mutable-tag rejection
(`policy::profile::production` rejects `image pull` with a tag,
allows only digest pins). This ADR adds a parallel rule:

- Production profile rejects `oci.launch` for any template whose
  registry entry lacks `verity_roothash`.
- The `--no-verity` flag is silently dropped in production
  profile with an admission-time error citing this ADR.

### Dev-profile escape

`mvmctl image pull --no-verity <ref>` skips verity generation in
the dev profile only. Documented as "faster first pull;
boot-time tamper detection unavailable for this template." The
public sandbox-parity status page's `oci-ingest` row names this as
a Preview-state limitation while W1 stabilizes.

### Why not Option B (carve-out)

Audit chain (claim 8) proves **provenance** — the image came from
the named registry at the named digest, the launch was admitted by
the host signer. Verity (claim 3) proves **integrity at boot** —
the bytes on disk match the cryptographic hash that was good
yesterday. These cover different threats:

| Threat                                              | Audit catches? | Verity catches? |
| --------------------------------------------------- | -------------- | --------------- |
| Wrong image (bad provenance)                        | Yes            | No              |
| On-disk corruption (cosmic ray / FS bug)            | No             | Yes             |
| Local-host tamper after pull                        | No             | Yes             |
| Concurrent shared-cache poisoning                   | No             | Yes             |
| Supply-chain tamper in the registry                 | Partial (digest pinning) | Yes (after first good pull) |

Option B leaves four of the five rows uncovered. Conflating
"audit covers it" with "verity covers it" produces a two-tier
trust story that's hard to message and easy for users to misread.
ADR-041 §"Non-goals" already forbids
"bypassing verified artifact checks for developer ergonomics" —
Option B is on the spectrum of that.

## Consequences

### Positive

- Claim 3 invariant unchanged. One boot path, one trust story,
  one production-profile admission gate.
- The `probe_verity_sidecar` code path is exercised by every
  launch — no "is this path even tested in prod?" risk.
- Verity cache is content-addressable, so the cost amortizes
  across pulls of the same digest. Layer reuse already gives us
  this for image content; the verity cache extends it.

### Negative

- **First pull is slower.** `veritysetup format` against a 200 MB
  rootfs runs in a few seconds; for very large images (1+ GB)
  it can reach tens of seconds. Mitigated by per-digest caching
  and by the libkrun builder VM doing the work off the main
  thread (Plan 72 default).
- **`veritysetup` becomes a builder-VM closure dep.** Already
  transitively present via `cryptsetup` (used by
  `verityArtifacts`); adding it explicitly increases the builder
  VM's Stage 0 closure marginally. Per the active builder-VM
  cost discussion, every new `rustPlatform.buildRustPackage`
  doubles transient sandbox cost — `veritysetup` is C, not Rust,
  so it pays once and doesn't compound.
- **Verity-cache invalidation has to be airtight.** A stale
  sidecar paired with a rebuilt rootfs is a verity panic at
  boot. Cache key includes the layer-digest set; layer-digest
  collision is cryptographically impossible.

## Non-goals

- Verity on `--add-dir` writable mounts. Those are explicitly
  mutable (claim W6); `dm-verity` is not the right tool.
- Verity on snapshot upper layers. Snapshots are HMAC-sealed with
  a monotonic-epoch replay-store (claim 8 / instance pause+resume
  semantics); different mechanism, different trust story.
- Online verity regeneration for in-flight images (e.g. mutating
  a pulled rootfs on the host before launch). The pull-and-seal
  contract is immutable: any modification requires a new pull or
  a snapshot.
- Verifying the OCI manifest's own digest as part of claim 3.
  That's claim-8-territory (signed audit of the resolve event).

## Open questions

- **`veritysetup` versioning.** Resolved by #223: both
  `nix/images/builder-vm/flake.nix` and
  `nix/images/runtime-overlay/flake.nix` pin cryptsetup 2.8.6 by
  release tarball hash so `veritysetup format` cannot drift
  silently on nixpkgs bumps.
- **Image-size DoS at pull time.** A malicious registry could
  serve a 100 GB manifest. Layer-size + total-rootfs caps belong
  in Plan 74 W1's R10 (OCI layer unpack attack surface)
  mitigation, not this ADR; they bound the verity-generation cost
  upstream.

## Implementation Plan

Tracked in [`specs/plans/74-claim-safe-sandbox-parity.md`](../plans/74-claim-safe-sandbox-parity.md)
§W1. Plan 74 §Risks R3 closes when this ADR ships and W1's task
list adopts pull-time verity by default.

W1 task additions on top of plan 74 as-written:

- `veritysetup` pinned in the builder-VM flake closure
  (`nix/images/builder-vm/flake.nix`).
- `crates/mvm-build/src/oci_to_rootfs.rs::generate_verity` —
  runs `veritysetup format` after ext4 emission, parses roothash
  from stdout, writes both files to the template directory.
- Verity-cache directory layout under
  `~/.cache/mvm/oci/verity-by-digest/`, mode 0700.
- `mvm-policy::profile::production` admission rule rejecting
  `oci.launch` when `template.verity_roothash.is_none()`.
- `--no-verity` dev-profile-only CLI flag with admission-time
  rejection in production profile, citing this ADR.
- Tests:
  - **Positive path.** Pull `alpine:3.19` (digest-pinned), launch
    via `mvmctl up --image`, verify dm-verity panics on a
    flipped data block in the rootfs (same regression shape as
    Plan 27 W3 §runbook step 4).
  - **Cache hit.** Re-pull the same digest, assert no
    `veritysetup` invocation.
  - **Production admission.** `MVM_PRODUCTION=1 mvmctl image
    pull --no-verity` exits non-zero with the documented error.
  - **Sidecar tamper.** Manually corrupt `rootfs.verity` between
    pull and launch; assert kernel panics before userspace.

The `oci-ingest` row on the public sandbox-parity page records
the verity posture in the per-claim "what would move it to
Shipped" note.

## Claim 10 — OCI image provenance (consolidated from specs/claims/claim-10-oci-image-provenance.md)

---
claim: 10-oci-image-provenance
status: Shipped
gated_phrases:
  - "any OCI image"
  - "any container image"
  - "OCI image provenance"
  - "mvmctl image pull"
  - "mvmctl image export"
  - "mvmctl up --image"
  - "mvmctl run --image"
  - "mvm-oci"
  - "OCI ingest"
  - "bidirectional OCI"
  - "OCI registry"
exempt_paths:
  - "specs/**"
  - "CHANGELOG.md"
  - ".github/**"
  - "memory/**"
  - "public/src/content/docs/contributing/adr/**"
  - "public/src/content/docs/security/sandbox-parity-status.md"
  - "xtask/src/check_doc_claims.rs"
  - "crates/mvm-oci/**"
  - "Cargo.toml"
  - "Cargo.lock"
  - "crates/mvm-cli/Cargo.toml"
  - "crates/mvm-cli/src/commands/image.rs"
  - "crates/mvm-cli/src/commands/vm/audit_chain.rs"
  - "crates/mvm-cli/src/commands/vm/exec.rs"
  - "crates/mvm-build/src/oci_to_rootfs/**"
  - "crates/mvm-build/tests/oci_unpack_attacks.rs"
  - "crates/mvm-build/tests/oci_unpack_common/**"
  - "crates/mvm-build/tests/oci_ext4_materialization.rs"
  - "crates/mvm-build/tests/oci_verity_sealing.rs"
  - "public/src/content/docs/reference/cli-commands.md"
  - "crates/mvm-libkrun/fuzz/rust-toolchain.toml"
---

# Claim 10 — OCI image provenance is recorded in the admission audit chain

## Assertion

Every `mvmctl run --image <ref>` admission emits an audit-chain entry
recording:

- The registry host that served the image
- The repo path
- The reference as supplied (tag or digest)
- The resolved manifest digest (sha256)
- The list of layer digests
- The current verification status
- The trust policy in effect

`mvmctl audit verify` continues to detect drift on the audit chain.
Tampering with any field of an OCI provenance entry breaks the
chain signature.

## CI gate that ratifies the claim

Plan 85 Phase E/F ships focused CLI unit coverage:

- Cached image resolution returns a provenance record with registry,
  repo, supplied ref, resolved digest, layer digest list, trust policy,
  and verification status.
- `AuditEmitter::emit_oci_provenance` writes `plan.oci_provenance`
  with those labels and `verify_audit_chain` verifies the resulting
  signed chain.
- `mvmctl run --image` admits an execution plan before launch and
  emits `plan.admitted` followed by `plan.oci_provenance`.
- `--prod` policy still refuses mutable references before pull or
  boot.
- Production OCI policy parses registry allow-lists and trusted
  cosign identities, rejects signature opt-outs, rejects denied
  registries before verification, and rejects missing or invalid
  signatures.

## Status transitions

- **2026-05-14**: claim filed at status `Planned` (this PR).
- **2026-05-20 / Plan 85 Phase E**: status flips to `Preview` because
  `mvmctl image pull` persists provenance metadata and
  `mvmctl run --image` emits a chain-signed `plan.oci_provenance`
  admission event. Cosign / registry policy remains tracked in #407.
- **2026-05-20 / Plan 85 Phase F**: status flips to `Shipped` because
  production OCI pulls and `run --image --prod` require a
  digest-pinned reference, an OCI registry policy, and cosign
  verification of the resolved digest before cache admission or boot.

## Why this claim needs a gate

Until the CI gate above passes, the docs/website/README must not
claim mvm verifies OCI image provenance. The claim is on the
roadmap — `Planned` — and the gated phrases list above blocks
premature use.

The phrase list is conservative on purpose: anything that mentions
the OCI pull, export, or ingest surface gets caught. Once a phrase
is admitted (status `Shipped`), the gate disengages and the docs
team can use it freely.

## Cross-refs

- ADR-002 §"Security model" — claims 1–8 (pre-plan-75) and 9 (deps).
- OCI provenance planning — defines this claim in its security
  implications section.
- CLAUDE.md §"Security model" — claim 10 line landed when Plan 85
  finalization flipped the plan status to `Shipped` (2026-05-26).

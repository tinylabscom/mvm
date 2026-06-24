# ADR-097 — Attested downloadable runtime and builder packs for fast first launch

**Status:** Proposed
**Date:** 2026-06-24
**Relates to:** [ADR-041](041-signed-audited-execution-plans.md),
[ADR-046](046-builder-vm-via-libkrun.md),
[ADR-071](071-stage0-bootstrap-trust-model.md),
[ADR-073](073-warm-snapshot-prior-art-adoption-boundary.md),
[ADR-086](086-relocatable-dependency-free-host-bundle.md),
[ADR-089](089-builder-vm-resident-control-plane.md),
[ADR-095](095-slim-microvm-kernel.md)

## Context

mvm's product promise has two requirements that can pull against each other:

1. **Attestable deterministic microVMs.** Workloads built from OCI images and
   Nix flakes must be traceable back to pinned inputs, deterministic build
   machinery, signed plans, and auditable launch decisions.
2. **Fast first-use developer experience.** A user should not wait for a fresh
   builder VM, Stage 0 bootstrap, Nix store population, kernel/image build, rootfs
   materialization, and guest boot before seeing a shell or command result.

The current architecture lets the builder VM sit on the critical path for fresh
OCI and Nix work. That is correct for determinism, but poor for first-use
latency. The mistake would be to remove Nix or the builder VM from the product;
the better split is to remove them from the hot launch path when their outputs
are already known and attestable.

The key product question is not only "is this artifact signed?" It is:

> Can a user prove exactly what launched, where it came from, what policy
> admitted it, and whether local state changed it?

That requires an attestation chain from source inputs through artifact
publication, local verification, snapshot/warm derivation, launch admission, and
command execution.

## Decision

### 1. Nix remains the build authority

Nix remains the canonical mechanism for producing deterministic mvm runtime and
builder artifacts. OCI tags are resolved to digests before build or admission.
Flake inputs are locked before build. The builder VM remains the Linux execution
boundary for local Nix evals/builds, OCI materialization, and private or
unpublished project artifacts.

The launch path changes: when a requested runtime, builder, image, or project
artifact is already published and policy-compatible, the host verifies and
consumes it instead of booting the builder VM to recreate it.

### 2. Publish attested downloadable packs

mvm publishes content-addressed, signed packs produced by CI or another
controlled builder:

- **Runtime pack** — slim kernel, initramfs or agent rootfs, guest agent,
  launcher compatibility metadata, and capability declarations.
- **Builder pack** — deterministic builder VM base disk, builder kernel/init
  artifacts, seeded Nix closure for common mvm build paths, builder agent, and
  builder capability declarations.
- **Image/project pack** — optional prepared OCI or flake output artifacts,
  rootfs/layer metadata, setup-cache layers, and admission sidecars.

Every pack carries a manifest with:

- Pack kind, schema version, target architecture, backend compatibility, and
  required host capabilities.
- Input identities: flake lock hashes, derivation paths, NAR hashes, OCI image
  digests, setup command hashes, policy hashes, source revisions, and toolchain
  versions.
- Output identities: content hashes for every file, aggregate pack hash,
  closure hash, rootfs hash, kernel hash, initramfs or agent-rootfs hash, and
  builder-image hash where applicable.
- Provenance: builder identity, build environment identity, build timestamp,
  reproducibility status, SBOM reference, and signature bundle.
- Trust metadata: signing key id, expiry, revocation channel, transparency-log
  reference when available, and artifact-channel identity.

The pack hash, not a mutable channel name, is the runtime identity. Channels may
point to packs, but launches record the resolved pack hash.

### 3. Local launch verifies first, builds only on cache miss or policy demand

The host runtime has three launch states:

| State | Behavior |
|---|---|
| Prepared and verified locally | Create CoW sandbox, claim warm VM or restore local snapshot, launch |
| Downloadable and policy-compatible | Download, verify, populate cache, derive local snapshot or warm standby, launch |
| Unavailable, private, mutable, or policy-rebuild-required | Use the builder VM prepare path, then launch from the produced artifact |

This removes builder-VM time from first launch only when a suitable attested
artifact is already local or downloadable. It does not weaken the guarantee for
novel local flakes, private OCI sources, mutable tags that cannot resolve to a
digest, or enterprise policies that require local rebuild verification.

### 4. Builder VM becomes a fast prepared capability

The builder VM remains core to the product, but it is itself delivered as an
attested pack and prepared for fast use:

- The base builder disk is read-only and verified by content hash.
- Local builder use creates a writable CoW overlay.
- The builder boots to a minimal builder-agent-ready state.
- The host creates a local builder-ready snapshot after verifying the builder
  pack and before injecting project secrets.
- A warm builder standby may be kept resident for developer sessions.

The published artifact is the deterministic builder disk/kernel/init identity.
Memory snapshots are local derived artifacts because they depend on host,
backend, and version details.

### 5. Snapshots and warm standbys are local derived artifacts

mvm does not treat published memory snapshots as globally reproducible artifacts.
Instead:

1. Verify a signed runtime or builder pack.
2. Boot it locally to an agent-ready state.
3. Record a local snapshot derivation event containing parent pack hash, host
   architecture, backend id, backend version, memory/CPU shape, policy hash, and
   agent readiness proof.
4. Use that local snapshot or warm standby for fast launches.

Snapshots must be created before per-run secrets, registry credentials, SSH
agents, project-private material, or user data are injected. Per-run secrets are
mounted or sent only after restore/claim and are never captured into base
snapshots.

### 6. Launch attestation is first-class

Every launched microVM produces a launch attestation record. The record links:

```
source inputs
-> build derivation or OCI digest
-> builder identity
-> artifact pack
-> local verification
-> local snapshot or warm standby derivation
-> admission policy decision
-> command execution record
```

Each arrow is represented by a hash, signature, policy decision, or audit event.
The launch record includes the exact command, plan hash, network policy hash,
artifact hashes, snapshot/warm identity, backend identity, launcher version,
time, and result.

This record is stored in a tamper-evident local audit log. Future remote
transparency logging may mirror selected records, but the local record is the
minimum viable audit surface.

### 7. The CLI explains fast-path eligibility and trust

mvm exposes user-facing explanations instead of silent fallback:

- `mvm prepare <image-or-flake>` fetches/builds/verifies artifacts and warms the
  runtime where policy allows.
- `mvm cache status` shows local packs, sizes, expiry, revocation status, and
  whether instant launch is ready.
- `mvm explain <run-id>` explains what launched, what admitted it, which
  artifact and snapshot were used, and why the builder VM was or was not needed.
- `machine run` reports preparation reasons when instant launch is unavailable:
  missing pack, expired signature, revoked signer, unsupported backend, local
  rebuild required, mutable input, private input, or incompatible policy.

### 8. Cache and update behavior is fail-closed

The artifact cache is content-addressed and permission-hardened. Downloads and
extractions happen in quarantine paths, are fully verified, and are promoted
atomically only after all hashes and signatures match. Every use revalidates the
pack manifest and policy compatibility before launch.

Artifacts have expiry and revocation metadata. mvm supports key rotation,
artifact-channel pinning, enterprise mirrors, offline mode, and local rebuild
verification. A stale but validly signed artifact is not trusted forever unless
policy explicitly permits that channel and expiry state.

## Consequences

**Positive**

- First launch can avoid builder-VM boot and Nix materialization when the needed
  artifact is already local or downloadable.
- Nix remains the deterministic source of truth for runtime, builder, OCI, and
  flake-derived artifacts.
- The builder VM remains a core feature, but becomes a prepared/warm capability
  rather than a mandatory first-command dependency.
- Launches become more auditable: users can prove the exact artifact, policy,
  snapshot, backend, and command involved in a run.
- Enterprise users get a clean model for mirrors, channel pins, local rebuild
  requirements, and offline operation.

**Negative / costs**

- The release pipeline becomes security-critical: pack manifests, signatures,
  SBOMs, revocation, expiry, and transparency references must be correct.
- Local cache management becomes a user-visible product surface with disk,
  network, and cleanup expectations.
- Snapshot identity and invalidation become part of the trust model.
- Some first launches remain slow by design: private flakes, unpublished OCI
  digests, mutable inputs, and policies that require local rebuilds still need
  the builder VM prepare path.
- The CLI must clearly distinguish "instant because prepared and attested" from
  "preparing deterministically before launch."

## Alternatives considered

- **Remove Nix from the development launch layer entirely.** Rejected. It would
  weaken the product's deterministic and attestable build promise. The correct
  move is to consume Nix-produced artifacts on the hot path, not to replace Nix.
- **Always build locally in the builder VM.** Rejected as the default. It is the
  strongest local-rebuild story but makes fast first-use UX impossible on fresh
  machines and wastes work for public, already-built artifacts.
- **Ship only runtime packs, not builder packs.** Rejected. The builder VM is a
  user-visible capability and must also have a fast prepared path.
- **Publish memory snapshots as release artifacts.** Rejected. Memory snapshots
  are backend/version/host-shape sensitive and may capture state that should
  remain local. Publish deterministic disk/kernel/init artifacts and derive
  snapshots locally.
- **Trust signed packs without launch records.** Rejected. Artifact attestation
  alone does not prove what was launched or whether local state modified it.

## Required follow-up

Plan 213 implements this decision: pack schema, release publishing, cache
verification, runtime fast path, builder fast path, audit/explain surfaces, and
latency/security gates.

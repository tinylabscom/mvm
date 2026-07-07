# ADR-097 — Attested downloadable runtime and builder packs for fast first launch

**Status:** Proposed
**Date:** 2026-06-24 (amended 2026-07-07: §9 release signing custody)
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

### 9. Release signing custody: keyless public channel, operator-supplied keys for everything else (amendment 2026-07-07)

Sections 2 and 8 leave "signing key id" and "key rotation" abstract. This
amendment settles the custody model concretely, because whatever trust root ships
compiled into a released binary is expensive to change and must be the
destination, not a placeholder. There are two trust authorities, split by who
produced the pack:

**Public mvm release channel — keyless.** Release packs published by the mvm
project carry no long-lived signing key. Continuous integration signs each pack
manifest under its workflow's OpenID Connect identity: the identity token is
exchanged for a short-lived Fulcio certificate, the manifest bytes are signed
with the certificate's ephemeral key, and the signature is recorded in the Rekor
transparency log. The signature travels beside the pack as a detached bundle
(certificate + signature + inclusion proof). This is the same posture the OCI
image path already commits to (`crypto::image_verify`), so it adds no new trust
surface mvm did not already accept.

Verification is offline and pins **both** halves of the identity:

- the certificate must chain to the embedded Fulcio root (from the vendored
  Sigstore trust root, TUF-managed);
- the certificate's identity must match an entry in a compiled-in **allow-list**
  — issuer `https://token.actions.githubusercontent.com` and a subject pattern
  scoped to the release workflow on a protected tag ref;
- the Rekor inclusion proof must verify against the embedded log root.

Pinning the subject identity is load-bearing: a verifier that accepts any
Fulcio-issued certificate is weaker than a fixed key, because any holder of any
OIDC token could then sign. The allow-list is a list, not a scalar, on purpose —
it is the rotation mechanism (see below).

What this buys over a long-lived key in CI: there is no key to exfiltrate, and
every release signature is publicly logged, so a CI compromise that mints a valid
pack is detectable after the fact rather than silent. What it still trusts: the
CI provider's OIDC identity, the Sigstore roots, and — critically — a correct
subject pin. A compromised release workflow can still produce a legitimately
signed pack; keyless makes that event auditable, it does not prevent it.

**Operator / enterprise / fleet-internal — ed25519, unchanged.** The existing
`packs::verify_pack_at` path, keyed off an out-of-band `PackTrustConfig`
(`~/.mvm/keys/pack-trust.json`: publisher ed25519 pubkeys, channels,
revocations), is the bring-your-own-trust-root lane. It is untouched by this
amendment. A fleet or air-gapped operator that builds its own packs signs them
with an operator key and distributes that pubkey through this config. This is
also the mvmd production lane (see interop below).

**Verification structure.** The keyless check does not replace or complicate the
ed25519 verifier. It is a separate outer verifier that (1) verifies the detached
bundle over the exact manifest bytes against the embedded Fulcio/Rekor roots and
the pinned identity allow-list, then (2) runs the same manifest structural, file
hash, pack hash, policy compatibility, expiry, and revocation checks the ed25519
path already performs. Only the signature-key step differs. The shared middle is
factored into one function both entry points call so they cannot diverge. The
keyless verifier lives in `mvm-core`, gated behind the `manifest-verify` feature
(which pulls the Sigstore verify stack and no async runtime), with its trust
inputs — identity allow-list, local policy, and the operator config — passed as
parameters.

**Embedded trust root shape.** The mvm-specific embedded material is only the
identity allow-list, expressed as a compiled-in constant and validated by test;
the Fulcio and Rekor roots come from the vendored Sigstore trust root. The
embedded keyless root is always active for the public channel, so a stock install
verifies release packs with no configuration. `pack-trust.json` is purely
additive on top of it — it adds ed25519 publishers, channels, and revocations; it
does not gate or disable the embedded keyless root. A switch to disable the public
channel or pin to operator-only roots (offline-pinned, mirror-only, enterprise
modes) is deferred to the revocation/enterprise workstream (§I) and must not be
foreclosed here.

**Rotation.** The keyless public channel needs no key rotation — certificates are
ephemeral. Only the *identity* migrates (a repository rename, a subject-pattern
change, a new channel), and that is handled by carrying more than one entry in the
allow-list: add the new identity, ship the binary, drop the old identity a release
or two later. There is no key-overlap window to manage. Operator ed25519 rotation
already works by listing multiple publishers in `pack-trust.json`.

**Revocation.** This amendment keeps revocation config-driven through
`PackTrustConfig.revocations`, as shipped. Fetching a live revocation channel
(the `TrustMetadata.revocation_channel` URL each manifest already records) with
offline-cache behavior is deferred to §I; the URL is recorded but not yet
fetched.

**mvmd / fleet interop (explicit).** Multi-tenant fleet orchestration (mvmd)
consumes these types through the `mvmctl` facade and is a first-class target of
this design, not an afterthought:

- The pack types and the ed25519 `verify_pack_at` are in `mvm-core`'s default
  surface, so mvmd has them today. The keyless verifier is `manifest-verify`-
  gated; mvmd reaches it by enabling that one feature on its `mvmctl` dependency —
  a feature flip, not an architectural change.
- The two-authority split maps directly onto the deployment split: keyless is the
  public mvm project channel; the ed25519 operator lane is the fleet-internal
  channel, where mvmd builds packs in its builder VM, signs with an operator key,
  and distributes the pubkey via the `pack-trust.json`-shaped config.
- The deferred disable/pin switch is the mvmd production knob: a fleet generally
  should not blind-trust the public release identity. Two constraints on this
  slice preserve that path: the keyless verifier stays in `mvm-core` with trust
  inputs as parameters (so mvmd supplies fleet roots without touching `mvm-cli`),
  and the identity allow-list plus the future pin/disable behavior stay data and
  policy rather than hardcoded control flow.

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

The §9 custody amendment is implemented by the Plan 213 release-signing follow-on
(Slice 2): the `manifest-verify`-gated keyless verifier and embedded identity
allow-list in `mvm-core`, the release-pipeline signing/publishing step, and the
mvmd interop constraints above.

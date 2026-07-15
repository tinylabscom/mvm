# ADR 050: Verity posture for pulled OCI images

- Status: Proposed
- Date: 2026-05-14
- Owner: MVM Project
- Related: ADR-001 (microVM security posture, claim 3), ADR-004 (image acquisition), ADR-007 (builder VM via libkrun), ADR-014 (claim-safe sandbox parity), Plan 74 W1, Plan 74 §Risks R3, mvmd ADR-0020 (OCI images as microVM workloads)

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
ADR-014 §"Non-goals" already forbids
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

- ADR-001 §"Security model" — claims 1–8 (pre-plan-75) and 9 (deps).
- OCI provenance planning — defines this claim in its security
  implications section.
- CLAUDE.md §"Security model" — claim 10 line landed when Plan 85
  finalization flipped the plan status to `Shipped` (2026-05-26).


## Consolidated from ADR-052 — User-defined base image registry — cosign-signed templates beyond v1's closed list

## Status

Proposed. Design for Plan 73 **Followup G** ("Per-language base image
registry beyond v1's closed list"), which Plan 73 records as
*"blocked on trust-model design + a signing flow that doesn't exist
yet."* This ADR proposes the trust model + signing flow so the
followup can be unblocked and phased into G.1 → G.4 (see §Phasing).

No code lands with this ADR. The implementation phases ship as
separate followup PRs once this design is accepted.

## Context

v1's [`mvm_sdk::runtime::resolve_base_image`](../../crates/mvm-sdk/src/runtime.rs)
ships a fixed list:

```rust
"python-3.12" => &["python312"],
"python-3.13" => &["python313"],
"node-22"     => &["nodejs_22"],
"node-lts"    => &["nodejs"],
"minimal"     => &["bash", "coreutils"],
_             => return Err(LowerError::UnknownBaseImage(...)),
```

That closed list is correct for the v1 surface — every entry maps
to a nixpkgs package that the workload's rootfs derivation already
trusts. But it leaves any user who wants a richer base template
with no extension path:

- `my-org/python-with-cuda` (Python 3.12 + CUDA + cuDNN preinstalled)
- `my-org/datadog-agent-base` (Python 3.12 + Datadog agent baked in)
- `vendor/node-22-with-playwright` (Node 22 + headless Chrome)
- `lab/python-3.13-rc` (a Python release the closed list doesn't
  yet name)

Today these users have two bad options: fork mvm and patch the
closed list, or carry an out-of-band rootfs that bypasses
`resolve_base_image` entirely. Both lose the security posture
guarantees ADR-001 makes about how a base image lands on disk.

The SDK port plan §"Well-known base-image trust" explicitly called
this out as a v1 deferral, and Plan 73 Followup G tracks it. The
gap has been "trust-model design": *how* does mvm know that
`my-org/python-with-cuda` is a base template it's willing to
resolve, given that the publisher is not mvm itself?

## Decision

User-defined base templates are first-class artifacts that ship
**cosign-signed**, **manifest-described**, and **trust-grant-gated**.
mvm trusts the signature, not the publisher's identity — adding a
new publisher is a one-line `mvmctl image trust <fingerprint>`.

The closed list stays as a no-trust-required fast path. Custom
templates flow through a separate `resolve_base_image` branch that
requires an explicit trust grant to resolve.

### Trust unit: the template, not the publisher

A trust grant binds a **cosign public-key fingerprint** to "any
template signed by this key resolves." Multiple publishers can be
trusted simultaneously; each lives under its own fingerprint. The
mvm install never auto-trusts a publisher — every entry is an
explicit user action mirroring `mvmctl trust add` for bundle
publishers (see `crates/mvm-cli/src/commands/trust/`).

This is intentionally simpler than the bundle-publisher trust
store: bundles use 32-byte raw Ed25519 keys at
`~/.mvm/trusted-publishers/<key_id>.pub`. Templates use cosign
because the artifact being signed (a rootfs sha256) is the standard
OCI-shape blob cosign already verifies; reusing cosign avoids
inventing a parallel signing format for the same job.

### Registry layout

Mirrors the sealed-volume layout from ADR-014 §"Sealed artifact
layout" so the supervisor can treat both as the same shape of
admission input:

```text
~/.mvm/base-images/<fingerprint>/<template_name>/
├── rootfs.sha256                # 64-hex sha256 of the rootfs blob
├── rootfs.ext4                  # the actual rootfs (or a local symlink
│                                #  to a content-addressed store)
├── template.toml                # manifest (see schema below)
├── template.toml.sig            # cosign signature over template.toml
├── sbom.cdx.json                # CycloneDX 1.5 SBOM (optional in G.1,
│                                #  required in G.3)
└── cve.json                     # pip-audit / equivalent (optional G.1,
                                 #  required in G.3)
```

The `<fingerprint>` directory is the cosign public-key fingerprint
that signed `template.toml.sig`. Multiple templates from the same
publisher share the fingerprint dir; templates from different
publishers live under different fingerprints. This makes
`mvmctl image trust <fp>` the only revocation point — removing the
fingerprint invalidates every template under it.

### Manifest schema (`template.toml`)

```toml
schema_version = 1
name           = "my-org/python-with-cuda"
arch           = "aarch64-linux"     # or "x86_64-linux"
language       = "python"            # or "node" | "rust" | "none"
base_image_ref = "oci://ghcr.io/my-org/python-with-cuda@sha256:abc...def"
# or:
# base_image_ref = "nix:github:my-org/cuda-templates#python-3.12-cuda"

signing_pubkey_fingerprint = "SHA256:7gM3...rPq"
rootfs_sha256              = "0123abcd...4567"

# optional fields, required under --prod (see §Lifecycle gates)
cve_scan_at = "2026-05-14T12:00:00Z"
sbom_sha256 = "fedc...0987"
attestation = "sigstore-bundle.json"

# forward-compat with ADR-014 (claim 9): a base template can declare
# its own dependency volumes that the supervisor verifies as part of
# admitting the workload.
[[dependencies]]
volume_hash    = "abc123..."
manifest_sha256 = "def456..."
mount_path     = "/opt/cuda"
```

`#[serde(deny_unknown_fields)]` on the deserialized
`TemplateManifest` ensures a future publisher that adds new fields
fails closed on an older mvm host — same rule as the existing
host↔guest types in ADR-001 claim 5.

### CLI surface

Four new verbs under `mvmctl image`:

```text
mvmctl image push <template.toml> [--rootfs <path>] [--registry <url>]
    Validate template.toml, hash the rootfs, sign with the host's
    cosign key, and write to ~/.mvm/base-images/<fp>/<name>/.
    With --registry, also pushes to a user-supplied registry URL
    (mvm itself does not host one — see §Non-goals).

mvmctl image list [--all | --installed]
    --installed (default): list templates resolvable on this host.
    --all: also list known templates we have no trust grant for
            (purely informational; not resolvable).
    Output: <name>  <arch>  <fingerprint>  <trust state>

mvmctl image rm <fingerprint>/<template_name>
    Remove a local registry entry. Does not revoke trust — to
    revoke, use `mvmctl image trust rm`.

mvmctl image trust add <fingerprint> [--pubkey <path>]
mvmctl image trust ls
mvmctl image trust rm <fingerprint>
    Manage the cosign trust store at
    ~/.mvm/trusted-image-keys/<fingerprint>.pub.
    Mirrors `mvmctl trust` for bundle publishers; lives in a
    separate dir to keep the trust scopes orthogonal (a publisher
    you trust to ship bundles is not automatically a publisher you
    trust to ship base images, and vice versa).
```

### `resolve_base_image` extension

```rust
pub fn resolve_base_image(template: &str) -> Result<Image, LowerError> {
    // 1. v1 closed-list fast path (no trust required).
    if let Some(image) = resolve_closed_list(template) {
        return Ok(image);
    }

    // 2. User-defined registry. Required: a trust grant for the
    //    signing fingerprint *before* the manifest is even parsed.
    if let Some(entry) = registry::find_by_name(template)? {
        trust::require_grant(&entry.fingerprint)?;          // E_UNTRUSTED_KEY
        cosign::verify(&entry.manifest, &entry.signature)?; // E_BAD_SIGNATURE
        let manifest = TemplateManifest::parse(&entry.manifest_bytes)?;
        verify_rootfs_sha256(&entry.rootfs, &manifest)?;    // E_ROOTFS_MISMATCH
        return Ok(Image::from_manifest(manifest));
    }

    Err(LowerError::UnknownBaseImage(template.to_string()))
}
```

The order matters: trust grant first, then signature verify, then
manifest parse. An untrusted publisher's manifest is never
deserialised — `deny_unknown_fields` cannot save you if you've
already dispatched on attacker-controlled JSON.

### Lifecycle gates

Mirroring ADR-014 §"Lifecycle gates":

**Publish-time (inside `mvmctl image push`):**

1. **Manifest validation** — schema_version, arch, name format
   (`<org>/<name>` with no path traversal), pubkey fingerprint
   matches the signing key in `--cosign-key`.
2. **Rootfs hash** — recomputed from disk; must match
   `manifest.rootfs_sha256`.
3. **CVE scan (--prod)** — if `--prod`, the rootfs is mounted
   read-only in the builder VM and scanned via the same pipeline
   ADR-014 uses for app-deps volumes. High/critical findings fail
   closed. Under `--dev`, the scan runs but only warns.
4. **SBOM emission (--prod)** — `cyclonedx-cli` over the rootfs's
   `/var/lib/dpkg` or `/nix/store` index produces
   `sbom.cdx.json`. Hash recorded in `template.toml.sbom_sha256`.
5. **Cosign sign** — `template.toml` is signed; the signature
   lands beside it.

**Admission-time (inside `resolve_base_image`):**

1. **Trust grant present** — `~/.mvm/trusted-image-keys/<fp>.pub`
   exists. Otherwise fail with `E_UNTRUSTED_KEY`.
2. **Cosign verify** — `template.toml.sig` verifies against the
   trusted pubkey. Otherwise `E_BAD_SIGNATURE`.
3. **Schema check** — `schema_version` matches a known version;
   `deny_unknown_fields` rejects forward-incompatible publishers.
4. **Rootfs hash recompute** — actual rootfs sha256 must match
   the manifest's recorded value. Otherwise `E_ROOTFS_MISMATCH`.
5. **Dependencies admission (if any)** — each
   `[[dependencies]]` entry routes through Followup A's
   `verify_sealed_volume` path. A custom template can therefore
   ship preinstalled deps that the supervisor still admits under
   claim 9.

### Closed-list invariant

The v1 closed list stays in `resolve_base_image` as branch 1.
Adding a name to the closed list still requires an mvm release —
it is the "this is trusted by mvm itself, no user action needed"
path. Custom templates always require an explicit
`mvmctl image trust add`, and are visually distinct in
`mvmctl image list` output.

A template name that collides with a closed-list entry (e.g. a
publisher who tries to ship `python-3.12`) resolves to the
closed-list entry — the fast path runs before the registry lookup.
This prevents a malicious publisher from shadowing a trusted name
even if the user has granted trust to that publisher.

### Forward-compat with claim 9 (ADR-014)

A base template's `[[dependencies]]` entries are sealed volumes in
the ADR-014 shape. The supervisor's admission verifier (Followup A)
already calls `verify_sealed_volume` for workload-level deps; it
calls the same code for template-level deps. The audit-chain entry
records both the template fingerprint *and* every dependency
volume_hash, so `mvmctl audit verify` detects drift in either
layer.

This means a custom template like `my-org/python-with-cuda` can
ship CUDA as a hash-locked, attestation-checked, CVE-scanned
volume baked into the template — and the supervisor's existing
posture extends to it without new code.

## Threat model

### Threats in scope

| Threat | Mitigation |
|---|---|
| Malicious template publisher ships a backdoored rootfs | Cosign-signing + explicit `mvmctl image trust add`. mvm trusts the signature, not the publisher's claimed identity. |
| Trust-store compromise (attacker drops a pubkey under `~/.mvm/trusted-image-keys/`) | Out of scope for mvm in v1 — handled by host filesystem perms (`~/.mvm` is mode 0700 per ADR-001 §"Security model"). Future hardening: trust-store entries chain-signed by `host-signer.ed25519`. |
| Stolen signing key | Cosign + Sigstore rekor (transparency log) gives a path to detection; full revocation is out of scope for v1 but the schema reserves an `attestation` field for the Sigstore bundle that makes the rekor lookup possible. |
| Manifest forward-incompat field smuggling | `#[serde(deny_unknown_fields)]` on `TemplateManifest`; same posture as ADR-001 claim 5. |
| Rootfs tampered after signing | `rootfs_sha256` recompute at admission. |
| Name shadowing of closed-list entries | Closed-list fast path runs before registry lookup. |
| Dependency-volume tampering | Routed through ADR-014 `verify_sealed_volume`; the supervisor cannot tell a template-declared volume from a workload-declared volume, so the existing claim-9 enforcement applies uniformly. |

### Non-goals

- **A public registry server.** `mvmctl image push --registry`
  targets a user-supplied URL (HTTPS bucket, OCI registry,
  GitHub release). mvm does not host one. Discovery is
  out-of-band — README links, internal docs, etc.
- **Multi-tenant trust delegation.** One mvm install = one trust
  store. There is no "org-wide trust grant" or LDAP-style
  delegation. Sharing trust across a team means each team member
  runs `mvmctl image trust add` with the same fingerprint.
- **Automatic key rotation.** Rotating a publisher's signing key
  means `mvmctl image trust rm <old> && mvmctl image trust add
  <new>`. Templates signed under the old key stop resolving.
- **Cross-arch template resolution.** A template's `arch` field
  must exactly match the host's. There is no `arch=any` shim and
  no on-demand recompile; that's the publisher's job.

## Phasing

The work splits into four sequential followups, each landable as a
separate PR. Each phase has a clear test gate so a partial
landing is still releasable.

### G.1 — Registry directory + `mvmctl image list/rm`

**Scope:** filesystem layout, manifest parser (without
verification), `mvmctl image list` reading
`~/.mvm/base-images/`, `mvmctl image rm` to delete an entry.
No signing, no trust, no resolver wiring.

**Test gate:** hand-author a `template.toml` + dummy rootfs under
`~/.mvm/base-images/<fp>/<name>/`; `mvmctl image list --installed`
shows it; `mvmctl image rm <fp>/<name>` removes it.

### G.2 — `mvmctl image trust` + cosign verification

**Scope:** trust-store at `~/.mvm/trusted-image-keys/`, the
`mvmctl image trust add/ls/rm` verbs, cosign-verify-against-trust
plumbing. `mvmctl image list --installed` now annotates each entry
with `[trusted]` / `[untrusted]`. `resolve_base_image` is *not*
extended yet — manifests are verifiable but not resolvable.

**Test gate:** sign a `template.toml` with cosign;
`mvmctl image trust add <fp>` followed by `list --installed`
shows `[trusted]`; tampering with `template.toml` makes a
follow-up `list` flip back to `[untrusted: bad sig]`.

### G.3 — `mvmctl image push` + sealed-template upload

**Scope:** the publish path — manifest validation, rootfs hash
compute, optional CVE scan + SBOM emission in the builder VM
(reusing ADR-014 plumbing), cosign sign, write to the registry
dir. Optional `--registry <url>` pushes the sealed bundle
externally.

**Test gate:** `mvmctl image push template.toml --rootfs r.ext4
--cosign-key mykey.pem` produces a valid registry entry that
G.2's `list --installed` shows as `[trusted]`. With `--prod` and
a known-CVE rootfs, `push` fails closed before publishing.

### G.4 — `resolve_base_image` extension + supervisor binding

**Scope:** the actual resolver branch from §"Decision". Once
G.4 lands, `@mvm.app(image="my-org/python-with-cuda")`
resolves; `mvmctl up` boots the workload from the
publisher-supplied rootfs; the supervisor admission verifier
records the template fingerprint + every declared deps volume
in the chain-signed audit log.

**Test gate:** a workload that names a trusted custom template
boots cleanly; the same workload after `mvmctl image trust rm
<fp>` fails with `E_UNTRUSTED_KEY` before any backend is
dispatched; the audit chain records both events.

After G.4, Followup G is closed and the Plan 73 entry can be
marked done.

## Consequences

**Positive.**

- Closes the last user-facing gap in the v1 SDK surface that
  required forking mvm or carrying an out-of-band rootfs.
- The trust model reuses cosign + Sigstore — no novel signing
  scheme to audit. The mvm-side code is "verify a signature in a
  trust store and parse a manifest."
- Forward-compat with ADR-014 falls out for free: template-level
  deps are workload-level deps from the supervisor's perspective.
- Phasing is incremental — G.1 is shippable in a day; each
  subsequent phase is additive and reverts cleanly.

**Costs.**

- Two trust stores (`~/.mvm/trusted-publishers/` for bundles,
  `~/.mvm/trusted-image-keys/` for templates) increases user
  surface. Justification: the two scopes are genuinely
  orthogonal (see §"CLI surface"). Folding them into one would
  create a worse failure mode — a publisher trusted for one
  scope automatically trusted for the other.
- Custom templates can pin to specific CVE-scan timestamps but
  cannot pin to "freshest CVE feed." That's the same trade ADR-014
  makes for app-deps volumes; the `mvmctl deps audit` re-audit
  mechanism (Plan 73 Followup C) will extend to templates in a
  later followup once base templates exist in production.
- `mvmctl image push` introduces a host-local cosign key
  requirement that v1's closed list did not have. Users who only
  consume mvm-published images never need this key. Publishers
  do; that's the deal.

**Out of scope (named explicitly).**

- A public template registry server.
- Multi-tenant trust delegation.
- Automatic key rotation.
- Cross-arch / on-demand recompile.

## References

- ADR-001 — `specs/adrs/001-microvm-security-posture.md` —
  claims 1–8 (no regressions: the rootfs verity claim 3, the
  audited plan claim 8, the deny-unknown-fields claim 5, and the
  `~/.mvm` 0700 posture all apply unchanged).
- ADR-014 — `specs/adrs/014-signed-audited-execution-plans.md` —
  the audit-chain consumer that records template resolutions in
  G.4.
- ADR-014 — `specs/adrs/014-signed-audited-execution-plans.md` — the
  sealed-artifact layout this ADR mirrors, and the
  `verify_sealed_volume` primitive G.4 reuses for template-level
  deps.
- Plan 73 Followup G — `specs/plans/73-sdk-port-followups.md` —
  the followup this ADR unblocks.
- `crates/mvm-sdk/src/runtime.rs` —
  `resolve_base_image` (the function G.4 extends).
- `crates/mvm-cli/src/commands/trust/` — the bundle-publisher
  trust verb pattern that `mvmctl image trust` mirrors.
- `crates/mvm-sdk/src/compile/deps_audit.rs` — the volume-sealing
  primitives the dependencies field in `template.toml` rides on.


## Consolidated from ADR-074 — VM name-registry is the source of truth; converge at CLI entry, not a resident daemon

## Status

Proposed. Records the architectural posture behind Plan 170; WS-A code
lands in PR #688. Supersedes nothing — it formalizes a model the codebase already
half-implements (`VmNameRegistry` + `cache prune --reap-orphans` + the TTL
`reaper`) and makes the resolution rule explicit.

## Context

mvm's local runtime state lives in two places that can drift apart:

1. The **persistent registry** — `VmNameRegistry` at
   `{mvm_share_dir}/vm-names.json` (`crates/mvm/src/vm/name_registry.rs`):
   what mvm *believes* is running.
2. **On-disk runtime reality** — per-VM state dirs, `libkrun.pid`, vsock
   sockets, TAP devices (`mvm-core/src/config.rs` helpers): what is *actually*
   running.

Today the two are reconciled only **manually** (`mvmctl cache prune
--reap-orphans`) and **lazily** (drift is discovered when a command trips over
it, then fails). Every recurring stale-state bug in the project's history —
the libkrun.pid-vs-socket race, the Stage 0 stale-crate bail, the
degraded-builder-store `dev up` loop, the stale-`pause`-against-a-vanished-VM
error — is the same root cause: **no component owns making reality match the
registry, proactively.**

A sibling single-machine sandbox control plane resolves exactly this with a
"converge persistent-store → runtime on every boot" pass, because it is a
long-lived daemon. mvm's local path is **one-shot CLI invocations**, so a
"reconcile on boot" goroutine has no boot to hook. Two questions, then:

- **Which side wins on conflict?**
- **When does convergence run, given there's no resident process?**

## Decision

**The registry is the source of truth; runtime reality is converged to it.**
A record with a dead process means "tear the leftovers down and deregister,"
not "adopt the orphan." Orphan state with no record is reaped. A record
pointing at vanished state is dropped. Convergence is idempotent — running it
twice is a no-op.

**Convergence runs at CLI entry for state-touching commands, not in a resident
daemon.** Any command that reads or mutates VM lifecycle (`up`, `start`,
`run`, `console`, `down`, `status`, `dev *`, `pause`/`wake`) first runs a
**cheap** convergence pass (registry read + PID-liveness stat only — never
spawns a VM, never touches Nix). Read-only, VM-agnostic commands skip it. An
explicit `mvmctl reconcile` verb exposes the same pass observably, and
`MVM_SKIP_RECONCILE=1` is the documented escape hatch (never set in CI).

The **resident** reaper loop (`mvm_hostd::supervisor::reaper`) stays where it
is — spawned by mvmd's supervisor daemon and the MCP dispatcher — and consumes
the *same* convergence + sweep library. There is exactly one convergence
implementation; the difference between local and fleet is only *who ticks it*
(CLI entry vs. daemon timer), never *what it does*.

## Consequences

- **A whole bug class becomes a non-event.** Stale records self-heal at the
  next state-touching command instead of surfacing as a confusing failure
  three layers down.
- **Convergence must be cheap and pure-logic-first** (testable without a real
  backend, mirroring the existing `reaper::sweep` shape) — otherwise it taxes
  every CLI invocation. The PID-liveness-only budget is a hard constraint, not
  a guideline.
- **It must fail open, not closed.** A convergence error must warn and proceed
  with the requested command, never block it — a bookkeeping sweep that bricks
  `mvmctl down` would be worse than the drift it fixes.
- **Observability:** convergence actions and idle/pressure lifecycle
  transitions emit to the shared local audit log via `audit_emit!`
  (consistent with ADR-014 / the Stage 0 audit contract), so density and
  self-heal behavior are auditable and `audit verify` still chains.
- **Boundary preserved:** this is host-side lifecycle bookkeeping only. It
  never touches the guest trust boundary or any of claims 1–15.

## Alternatives considered

- **A resident local daemon that converges on a timer.** Rejected: mvm's local
  UX is a stateless CLI; a background daemon is a new failure surface, a new
  thing to install/supervise, and contradicts the one-shot model. mvmd already
  *is* the resident process for fleet use.
- **Runtime reality wins (adopt orphans into the registry).** Rejected: an
  orphan process whose record is gone has lost its admission context
  (`ExecutionPlan`, audit chain); adopting it would resurrect a workload
  outside the signed-admission path. Reaping is the only safe direction.
- **Keep reconciliation manual (`cache prune` only).** Rejected: that is the
  status quo whose lazy-discovery failure mode this ADR exists to end.


## Consolidated from ADR-097 — Attested downloadable runtime and builder packs for fast first launch

**Status:** Proposed
**Date:** 2026-06-24 (amended 2026-07-07: §9 release signing custody)
**Relates to:** [ADR-014](014-signed-audited-execution-plans.md),
[ADR-007](007-vmbackend-single-trait.md),
[ADR-004](004-sealed-signed-builder-image.md),
[ADR-025](025-warm-snapshot-prior-art-adoption-boundary.md),
[ADR-028](028-relocatable-dependency-free-host-bundle.md),
[ADR-020](020-host-services-broker.md),
[ADR-007](007-vmbackend-single-trait.md)

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
- the certificate's identity must **exactly** match one of a small set of
  accepted identities — issuer `https://token.actions.githubusercontent.com` and
  a subject equal to the release workflow on the release tag. Sigstore's identity
  policy is exact-match only (no glob/regex — wildcarding identity would be a
  trust regression), so the subject is not a pattern: the verifier constructs the
  concrete accepted identity by interpolating the binary's own version into a
  compiled-in **template** (`…/.github/workflows/<release>.yml@refs/tags/v<version>`)
  at verify time, exactly as the OCI image path (`crypto::image_verify`) already
  does. A binary therefore trusts only packs from its own release tag;
- the Rekor inclusion proof must verify against the embedded log root.

Pinning the subject identity is load-bearing: a verifier that accepts any
Fulcio-issued certificate is weaker than a fixed key, because any holder of any
OIDC token could then sign. The compiled-in material is a **list of templates**,
not a scalar, on purpose — that list is the identity-migration mechanism (see
below); the version is always interpolated from the running binary.

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
ephemeral. Only the *identity* migrates (a repository rename, a workflow-file
rename), and that is handled by carrying more than one template in the compiled-in
list: add the new template, ship the binary, drop the old one a release or two
later. The release version is not a migration concern — it is always the running
binary's own version, interpolated into every template. There is no key-overlap
window to manage. Operator ed25519 rotation already works by listing multiple
publishers in `pack-trust.json`.

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

---
title: "ADR-052: User-defined base image registry — cosign-signed templates beyond v1's closed list"
status: Proposed
date: 2026-05-14
related: ADR-002 (microVM security posture); ADR-041 (signed audited ExecutionPlan); ADR-041 (app-deps audit pipeline); plan 73 Followup G
---

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
guarantees ADR-002 makes about how a base image lands on disk.

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

Mirrors the sealed-volume layout from ADR-041 §"Sealed artifact
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

# forward-compat with ADR-041 (claim 9): a base template can declare
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
host↔guest types in ADR-002 claim 5.

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

Mirroring ADR-041 §"Lifecycle gates":

**Publish-time (inside `mvmctl image push`):**

1. **Manifest validation** — schema_version, arch, name format
   (`<org>/<name>` with no path traversal), pubkey fingerprint
   matches the signing key in `--cosign-key`.
2. **Rootfs hash** — recomputed from disk; must match
   `manifest.rootfs_sha256`.
3. **CVE scan (--prod)** — if `--prod`, the rootfs is mounted
   read-only in the builder VM and scanned via the same pipeline
   ADR-041 uses for app-deps volumes. High/critical findings fail
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

### Forward-compat with claim 9 (ADR-041)

A base template's `[[dependencies]]` entries are sealed volumes in
the ADR-041 shape. The supervisor's admission verifier (Followup A)
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
| Trust-store compromise (attacker drops a pubkey under `~/.mvm/trusted-image-keys/`) | Out of scope for mvm in v1 — handled by host filesystem perms (`~/.mvm` is mode 0700 per ADR-002 §"Security model"). Future hardening: trust-store entries chain-signed by `host-signer.ed25519`. |
| Stolen signing key | Cosign + Sigstore rekor (transparency log) gives a path to detection; full revocation is out of scope for v1 but the schema reserves an `attestation` field for the Sigstore bundle that makes the rekor lookup possible. |
| Manifest forward-incompat field smuggling | `#[serde(deny_unknown_fields)]` on `TemplateManifest`; same posture as ADR-002 claim 5. |
| Rootfs tampered after signing | `rootfs_sha256` recompute at admission. |
| Name shadowing of closed-list entries | Closed-list fast path runs before registry lookup. |
| Dependency-volume tampering | Routed through ADR-041 `verify_sealed_volume`; the supervisor cannot tell a template-declared volume from a workload-declared volume, so the existing claim-9 enforcement applies uniformly. |

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
(reusing ADR-041 plumbing), cosign sign, write to the registry
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
- Forward-compat with ADR-041 falls out for free: template-level
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
  cannot pin to "freshest CVE feed." That's the same trade ADR-041
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

- ADR-002 — `specs/adrs/002-microvm-security-posture.md` —
  claims 1–8 (no regressions: the rootfs verity claim 3, the
  audited plan claim 8, the deny-unknown-fields claim 5, and the
  `~/.mvm` 0700 posture all apply unchanged).
- ADR-041 — `specs/adrs/041-signed-audited-execution-plans.md` —
  the audit-chain consumer that records template resolutions in
  G.4.
- ADR-041 — `specs/adrs/041-signed-audited-execution-plans.md` — the
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

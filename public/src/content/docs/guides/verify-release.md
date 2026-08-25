---
title: Verifying Release Artifacts
description: How to verify that an mvmctl release binary was built by the official CI pipeline using cosign keyless signing.
---

# Verifying Release Artifacts

Every `mvmctl` release is signed using [Sigstore cosign](https://docs.sigstore.dev/cosign/overview/) with keyless OIDC signing. This means:

- **No secret key is stored anywhere** — signatures are tied to the GitHub Actions OIDC token used at release time.
- **Verification proves provenance** — the artifact was built by the official `release.yml` workflow, from the `tinylabscom/mvm` repository, at a specific tag.
- **Tamper detection** — any modification to the binary after signing will cause verification to fail.

Each release includes, alongside the `.tar.gz` archives:

| File | Purpose |
|------|---------|
| `checksums-sha256.txt` | SHA256 digests for all archives (verified automatically by `mvmctl env update`) |
| `mvmctl-<target>.tar.gz.bundle` | Cosign signature bundle for each platform archive |
| `sbom.cdx.json` | Software Bill of Materials (CycloneDX JSON) |
| `sbom.cdx.json.bundle` | Cosign signature bundle for the SBOM |
| `runtime-overlay-<arch>.tar.gz.bundle` | Cosign signature bundle for the runtime overlay (verified in-binary before install) |
| `sdk-sidecar-<arch>.tar.gz.bundle` | Cosign signature bundle for the SDK sidecar (verified in-binary before install) |

Every bundle is a [Sigstore bundle](https://docs.sigstore.dev/about/bundle/)
(`--new-bundle-format`). There is one format across the whole release — the
in-binary verifier `mvmctl` uses for the overlay and sidecar reads only this
shape, and `cosign verify-blob --bundle` takes it directly.

---

## Prerequisites

Install cosign:

**cosign v2.4 or newer** is required — that is when Sigstore-bundle support
landed in `verify-blob`. Older cosign cannot read this release's bundles and
there is no legacy fallback.

```bash
# macOS
brew install cosign

# Linux (Debian/Ubuntu)
apt install cosign

# Or download from https://github.com/sigstore/cosign/releases
```

---

## Verifying a Release Binary

1. Download the archive and its bundle from the [GitHub releases page](https://github.com/tinylabscom/mvm/releases):

```bash
# Replace <version> and <target> as appropriate
VERSION=v0.7.0
TARGET=aarch64-apple-darwin  # or x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu

curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/mvmctl-${TARGET}.tar.gz"
curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/mvmctl-${TARGET}.tar.gz.bundle"
```

2. Verify the signature:

```bash
cosign verify-blob \
  --bundle "mvmctl-${TARGET}.tar.gz.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/.*" \
  "mvmctl-${TARGET}.tar.gz"
```

A successful verification prints:

```
Verified OK
```

Any failure means the artifact was not produced by the official pipeline and **should not be trusted**.

---

## Verifying the SBOM

```bash
curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/sbom.cdx.json"
curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/sbom.cdx.json.bundle"

cosign verify-blob \
  --bundle sbom.cdx.json.bundle \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/.*" \
  sbom.cdx.json
```

---

## Verifying Checksums

`mvmctl env update` automatically downloads `checksums-sha256.txt` and verifies the SHA256 digest of the downloaded archive before installing. No manual step needed.

To verify manually:

```bash
curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/checksums-sha256.txt"
shasum -a 256 --check <(grep "mvmctl-${TARGET}.tar.gz" checksums-sha256.txt)
```

## Verifying the runtime overlay release assets

Overlay-backed workloads consume a separate readonly guest-runtime artifact from
the same release. To verify it manually:

```bash
VERSION=v0.18.0
ARCH=aarch64   # or x86_64

curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/runtime-overlay-${ARCH}.tar.gz"
curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/runtime-overlay-${ARCH}.tar.gz.sha256"

shasum -a 256 --check "runtime-overlay-${ARCH}.tar.gz.sha256"
tar xzf "runtime-overlay-${ARCH}.tar.gz"
sha256sum --check checksums-sha256.txt
```

When `mvmctl build runtime-overlay build --source download` installs this
payload into `~/.mvm/cache/runtime-overlay/<version>/<arch>/`, it first
verifies the tarball, then verifies the extracted inner files against the
embedded `checksums-sha256.txt`, and later required-overlay boots recheck those
cached file hashes before attach. A drifted cache entry is refused.

## Runtime overlay update model

Verification tells you the release assets are authentic; rollout still follows
the runtime contract:

- stopped VMs pick up an updated version-matched overlay on the next start
- running VMs keep the runtime they booted with until restart
- mvm does not hot-remount a different runtime overlay into a live guest

Plan restarts accordingly when moving production workloads onto a new release.

## Runtime overlay rollout checklist

Use this checklist when promoting a release that changes guest runtime
binaries:

1. Verify the `mvmctl` archive for the target tag.
2. Verify the matching runtime-overlay assets for the same tag and
   architecture.
3. Preload the overlay cache with
   `mvmctl build runtime-overlay build --source download` on hosts that should
   pick up the release immediately.
4. Restart stopped VMs when you want them to adopt the new runtime overlay.
5. Restart already-running VMs only during a planned maintenance window; they
   keep the runtime they booted with until then.

This is a next-boot rollout, not a live remount rollout.

## Runtime overlay rollback

If you must roll back a release:

1. Downgrade `mvmctl` to the older release.
2. Ensure the matching older runtime-overlay assets are available again, either
   by re-running `mvmctl build runtime-overlay build --source download` for the
   older tag or by restoring the older cached artifact under
   `~/.mvm/cache/runtime-overlay/<version>/<arch>/`.
3. Restart affected VMs so they boot with the downgraded, version-matched
   overlay.

Do not expect a running VM to switch runtime versions in place. Rollback takes
effect on restart, the same way rollout does.

---

## What Cosign Keyless Signing Guarantees

| Claim | How it's enforced |
|-------|------------------|
| Built by GitHub Actions | `--certificate-oidc-issuer https://token.actions.githubusercontent.com` |
| From the `tinylabscom/mvm` repo | `--certificate-identity-regexp .../tinylabscom/mvm/...` |
| By the release workflow | `--certificate-identity-regexp .../release.yml...` |
| At a specific git tag | The OIDC token embeds the `ref` claim |

A compromised CDN or GitHub Releases page cannot forge a valid signature without the GitHub Actions OIDC token, which is only issued during an actual workflow run on the real repository.

---

## Verifying the Builder Image Manifest

Every release also publishes a cosign-keyless-signed manifest for the builder image (consumed by `mvmctl bootstrap` / `mvmctl pack download builder` and mvmd's pool-build pipeline). The manifest is the trust anchor — it carries SHA-256 of every image artifact, the Nix store hash, the source git SHA, and the SHA-256 of every flake lockfile, all bound by one cosign signature.

mvmctl verifies this automatically on every builder-pack fetch (`mvmctl bootstrap`, or the first `machine build` / `machine run --flake ...` that needs the builder VM). To verify manually:

```bash
VERSION=v0.14.0  # replace with the release you're verifying
ARCH=aarch64     # or x86_64

curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/builder-vm-${ARCH}.pack-manifest.json"
curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/builder-vm-${ARCH}.pack-manifest.json.bundle"

cosign verify-blob \
  --bundle "builder-vm-${ARCH}.pack-manifest.json.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/${VERSION}" \
  "builder-vm-${ARCH}.pack-manifest.json"
```

A successful verification prints `Verified OK`. After verification, every artifact whose SHA-256 is recorded in the manifest can be checked with `sha256sum` and the manifest's value:

```bash
jq -r '.artifacts[] | "\(.sha256)  \(.name)"' "builder-vm-${ARCH}.pack-manifest.json" \
  | sha256sum --check
```

:::note[What changed]
This section used to also cover a dev-image variant, verified locally via
`mvmctl dev import-image`. That command was removed along with `mvmctl dev`;
the dev-image pack class has no publish/fetch path today. See
[Air-gapped Bootstrap](airgapped-bootstrap) for the current air-gapped path
(signed `.mvmpkg` bundles).
:::

### Recall (revocation list)

A separate `revocations` release tag publishes a cosign-signed `revoked-versions.json`. mvmctl checks this list on every builder-pack fetch and refuses to use any image whose version is recalled. The recall reason is surfaced verbatim in the failure message, pointing at the upgrade path.

```bash
curl -LO "https://github.com/tinylabscom/mvm/releases/download/revocations/revoked-versions.json"
curl -LO "https://github.com/tinylabscom/mvm/releases/download/revocations/revoked-versions.json.bundle"

cosign verify-blob \
  --bundle revoked-versions.json.bundle \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/tinylabscom/mvm/.github/workflows/revocations.yml@refs/tags/revocations" \
  revoked-versions.json
```

The revocations tag is signed by a *separate* OIDC identity (`revocations.yml`) so a leaked image-signing cert can't fabricate a permissive recall, and vice versa. Domain separation by design.

Published builder packs use the same `revocations` channel for additive
recalls. When the installed attested builder-pack path is active, `mvmctl`
refreshes `pack-revocations.json` and `pack-revocations.json.bundle` into
`~/.mvm/cache/pack-revocations/` every 24 hours, tolerates up to 7 days of
offline staleness, treats `404` as bootstrap state, and unions any fetched
entries with the operator's local `pack-trust.json` revocations. A fetched list
that fails cosign verification is ignored rather than applied.

### Emergency escape hatches

Two environment variables disable parts of the verification pipeline. Both print loud warnings; both are documented for emergency rotation only:

| Variable | Disables | Use case |
|----------|----------|----------|
| `MVM_SKIP_HASH_VERIFY=1` | SHA-256 check on artifact bytes (existing W5.1) | Mid-flight corruption while the publish flow is broken |
| `MVM_SKIP_COSIGN_VERIFY=1` | Cosign signature check on manifest + revocation list | Sigstore-side outage where TUF root or Rekor is unavailable |

The two are independent — setting one doesn't disable the other. SHA-256 still runs even with cosign disabled, and vice versa.

---
title: Verifying Release Artifacts
description: How to verify that an mvmctl release binary was built by the official CI pipeline using cosign keyless signing.
---

# Verifying Release Artifacts

Every `mvmctl` release is signed using [Sigstore cosign](https://docs.sigstore.dev/cosign/overview/) with keyless OIDC signing. This means:

- **No secret key is stored anywhere** — signatures are tied to the GitHub Actions OIDC token used at release time.
- **Verification proves provenance** — the artifact was built by the official `release.yml` workflow, from the `auser/mvm` repository, at a specific tag.
- **Tamper detection** — any modification to the binary after signing will cause verification to fail.

Each release includes, alongside the `.tar.gz` archives:

| File | Purpose |
|------|---------|
| `checksums-sha256.txt` | SHA256 digests for all archives (verified automatically by `mvmctl update`) |
| `mvmctl-<target>.tar.gz.bundle` | Cosign signature bundle for each platform archive |
| `sbom.cdx.json` | Software Bill of Materials (CycloneDX JSON) |
| `sbom.cdx.json.bundle` | Cosign signature bundle for the SBOM |

---

## Prerequisites

Install cosign:

```bash
# macOS
brew install cosign

# Linux (Debian/Ubuntu)
apt install cosign

# Or download from https://github.com/sigstore/cosign/releases
```

---

## Verifying a Release Binary

1. Download the archive and its bundle from the [GitHub releases page](https://github.com/auser/mvm/releases):

```bash
# Replace <version> and <target> as appropriate
VERSION=v0.7.0
TARGET=aarch64-apple-darwin  # or x86_64-apple-darwin, x86_64-unknown-linux-gnu, etc.

curl -LO "https://github.com/auser/mvm/releases/download/${VERSION}/mvmctl-${TARGET}.tar.gz"
curl -LO "https://github.com/auser/mvm/releases/download/${VERSION}/mvmctl-${TARGET}.tar.gz.bundle"
```

2. Verify the signature:

```bash
cosign verify-blob \
  --bundle "mvmctl-${TARGET}.tar.gz.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/.*" \
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
curl -LO "https://github.com/auser/mvm/releases/download/${VERSION}/sbom.cdx.json"
curl -LO "https://github.com/auser/mvm/releases/download/${VERSION}/sbom.cdx.json.bundle"

cosign verify-blob \
  --bundle sbom.cdx.json.bundle \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/.*" \
  sbom.cdx.json
```

---

## Verifying Checksums

`mvmctl update` automatically downloads `checksums-sha256.txt` and verifies the SHA256 digest of the downloaded archive before installing. No manual step needed.

To verify manually:

```bash
curl -LO "https://github.com/auser/mvm/releases/download/${VERSION}/checksums-sha256.txt"
shasum -a 256 --check <(grep "mvmctl-${TARGET}.tar.gz" checksums-sha256.txt)
```

---

## What Cosign Keyless Signing Guarantees

| Claim | How it's enforced |
|-------|------------------|
| Built by GitHub Actions | `--certificate-oidc-issuer https://token.actions.githubusercontent.com` |
| From the `auser/mvm` repo | `--certificate-identity-regexp .../auser/mvm/...` |
| By the release workflow | `--certificate-identity-regexp .../release.yml...` |
| At a specific git tag | The OIDC token embeds the `ref` claim |

A compromised CDN or GitHub Releases page cannot forge a valid signature without the GitHub Actions OIDC token, which is only issued during an actual workflow run on the real repository.

---

## Verifying the Dev Image and Builder Image Manifests (plan 36)

Starting with the plan-36 work, every release also publishes a cosign-keyless-signed manifest for the dev image (consumed by `mvmctl dev up`) and the builder image (consumed by mvmd's pool-build pipeline). The manifest is the trust anchor — it carries SHA-256 of every image artifact, the Nix store hash, the source git SHA, and the SHA-256 of every flake lockfile, all bound by one cosign signature.

mvmctl verifies these automatically on every `mvmctl dev up`. To verify manually:

```bash
VERSION=v0.14.0  # replace with the release you're verifying
ARCH=aarch64     # or x86_64
VARIANT=dev      # or builder

curl -LO "https://github.com/auser/mvm/releases/download/${VERSION}/${VARIANT}-image-${ARCH}.manifest.json"
curl -LO "https://github.com/auser/mvm/releases/download/${VERSION}/${VARIANT}-image-${ARCH}.manifest.json.bundle"

cosign verify-blob \
  --bundle "${VARIANT}-image-${ARCH}.manifest.json.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/${VERSION}" \
  "${VARIANT}-image-${ARCH}.manifest.json"
```

A successful verification prints `Verified OK`. After verification, every artifact whose SHA-256 is recorded in the manifest can be checked with `sha256sum` and the manifest's value:

```bash
jq -r '.artifacts[] | "\(.sha256)  \(.name)"' "${VARIANT}-image-${ARCH}.manifest.json" \
  | sha256sum --check
```

### Air-gapped install

`mvmctl dev import-image` runs the same verification against local files for hosts that can't reach github.com. See [Air-gapped Bootstrap](airgapped-bootstrap) for the operator workflow.

### Recall (revocation list)

A separate `revocations` release tag publishes a cosign-signed `revoked-versions.json`. mvmctl checks this list on every `dev up` and refuses to use any image whose version is recalled. The recall reason is surfaced verbatim in the failure message, pointing at the upgrade path.

```bash
curl -LO "https://github.com/auser/mvm/releases/download/revocations/revoked-versions.json"
curl -LO "https://github.com/auser/mvm/releases/download/revocations/revoked-versions.json.bundle"

cosign verify-blob \
  --bundle revoked-versions.json.bundle \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/auser/mvm/.github/workflows/revocations.yml@refs/tags/revocations" \
  revoked-versions.json
```

The revocations tag is signed by a *separate* OIDC identity (`revocations.yml`) so a leaked image-signing cert can't fabricate a permissive recall, and vice versa. Domain separation by design.

### Emergency escape hatches

Two environment variables disable parts of the verification pipeline. Both print loud warnings; both are documented for emergency rotation only:

| Variable | Disables | Use case |
|----------|----------|----------|
| `MVM_SKIP_HASH_VERIFY=1` | SHA-256 check on artifact bytes (existing W5.1) | Mid-flight corruption while the publish flow is broken |
| `MVM_SKIP_COSIGN_VERIFY=1` | Cosign signature check on manifest + revocation list | Sigstore-side outage where TUF root or Rekor is unavailable |

The two are independent — setting one doesn't disable the other. SHA-256 still runs even with cosign disabled, and vice versa.

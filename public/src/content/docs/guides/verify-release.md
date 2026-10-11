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
| `checksums-sha256.txt` | SHA256 digests for all archives (signature and digests verified automatically by `mvmctl env update`) |
| `mvmctl-<target>.tar.gz.bundle` | Cosign signature bundle for each platform archive |
| `sbom.cdx.json` | Software Bill of Materials (CycloneDX JSON) |
| `sbom.cdx.json.bundle` | Cosign signature bundle for the SBOM |
| `mvm-guest-bins-v<version>.tar.gz` | The guest runtime this CLI ships with: the programs and libraries mvm runs inside a guest, for both guest architectures, listed in `checksums-sha256.txt` |
| `mvm-guest-bins-v<version>.tar.gz.bundle` | Cosign signature bundle for the guest runtime (verified in-binary before `mvmctl` reads it) |
| `mvm-guest-bins-v<version>.tar.gz.sha256` and its `.bundle` | The guest runtime's digest, which `mvmctl` checks before the signature |

Every bundle is a [Sigstore bundle](https://docs.sigstore.dev/about/bundle/)
(`--new-bundle-format`). There is one format across the whole release — the
in-binary verifier `mvmctl` uses for the guest runtime reads only this
shape, and `cosign verify-blob --bundle` takes it directly.

Boot images (kernels, root filesystems, the runtime overlay, the SDK sidecar
and the initramfs) are not CLI release assets: they are members of the signed
image set `mvmctl` pins, verified against that set's own signature.

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

## Verifying with an installed mvmctl

If an `mvmctl` is already installed, it can check a downloaded archive without
cosign. The check runs offline against the Sigstore trust root built into the
binary, and accepts only the release workflow at the tag you name:

```bash
mvmctl env verify-release mvmctl-aarch64-apple-darwin.tar.gz --tag v0.18.0-rc.1
```

The bundle is read from `<archive>.bundle` beside the archive unless you pass
`--bundle`. `install.sh` uses this on an upgrade, and `mvmctl env update` runs
the same check before it replaces itself.

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

`mvmctl env update` automatically downloads `checksums-sha256.txt` and its `.bundle`, verifies the manifest's signature under the release tag before reading it, and then checks the SHA256 digest of the downloaded archive against it before installing. No manual step needed.

To verify manually:

```bash
curl -LO "https://github.com/tinylabscom/mvm/releases/download/${VERSION}/checksums-sha256.txt"
shasum -a 256 --check <(grep "mvmctl-${TARGET}.tar.gz" checksums-sha256.txt)
```

## Verifying boot images (the image set)

Boot images — the builder VM, the default workload image, the runtime overlay,
the SDK sidecar, the initramfs and the kernels — are not attached to a CLI
release. They are members of one signed image set published by
[mvm-images](https://github.com/tinylabscom/mvm-images), and `mvmctl` pins that
set in `crates/mvm-core/images.lock`: the release tag, the SHA-256 of the root
manifest `image-set.json`, and the workflow identity that signed it. Every
download checks the root's digest against the pin, the root's cosign bundle
against that identity, then each member's size and digest against the root.

`mvmctl image boot verify` runs that chain over files you already have. To walk
it by hand for the runtime overlay:

```bash
TAG=image-set/v0.1.0   # the release_tag in images.lock
ARCH=aarch64           # or x86_64
BASE="https://github.com/tinylabscom/mvm-images/releases/download/${TAG}"

curl -LO "${BASE}/image-set.json"
curl -LO "${BASE}/image-set.json.bundle"
# Compare against manifest_sha256 in images.lock.
shasum -a 256 image-set.json

cosign verify-blob \
  --bundle image-set.json.bundle \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "https://github.com/tinylabscom/mvm-images/.github/workflows/release.yml@refs/tags/${TAG}" \
  image-set.json

curl -LO "${BASE}/runtime-overlay-${ARCH}.tar.gz"
jq -r --arg name "runtime-overlay-${ARCH}.tar.gz" '
  .members[] | .artifacts[] | select(.name == $name) | "\(.sha256)  \(.name)"
' image-set.json | shasum -a 256 --check
tar xzf "runtime-overlay-${ARCH}.tar.gz"
shasum -a 256 --check checksums-sha256.txt
```

When `mvmctl build runtime-overlay build --source download` installs this
payload into `~/.mvm/cache/image-set/<root-sha256>/runtime-overlay/<member-version>/<arch>/`, it runs the same
chain, then verifies the extracted inner files against the embedded
`checksums-sha256.txt`, and later required-overlay boots recheck those cached
file hashes before attach. A drifted cache entry is refused.

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
2. Verify the runtime overlay in the image set that release pins, for each
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
2. Ensure the older release's runtime overlay is available again, either by
   re-running `mvmctl build runtime-overlay build --source download` with the
   older `mvmctl` (it fetches from the image set that release pins) or by
   restoring the older cached artifact under
   `~/.mvm/cache/image-set/<root-sha256>/runtime-overlay/<member-version>/<arch>/`, where
   `<root-sha256>` is the digest of the image set that release pins.
3. Restart affected VMs so they boot with the downgraded release's overlay.

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

## Verifying the builder image

The builder image is a member of the same image set as every other boot image,
so it is verified the same way: `mvmctl bootstrap` — or the first
`machine build` / `machine run --flake ...` that needs the builder VM — fetches
it and checks it against the signed root before it is cached. To check it by
hand, follow [Verifying boot images](#verifying-boot-images-the-image-set) with
the builder members (`builder-vm-vmlinux-${ARCH}`,
`builder-vm-rootfs-${ARCH}.ext4`) in place of the runtime overlay.

CLI releases up to v0.18 also attached a separately signed builder "pack"
manifest (`builder-vm-<arch>.pack-manifest.json`). Those assets stay on those
releases, but no current `mvmctl` fetches them.

:::note[What changed]
This section used to also cover a dev-image variant, verified locally via
`mvmctl dev import-image`. That command was removed along with `mvmctl dev`;
the dev-image pack class has no publish/fetch path today. See
[Air-gapped Bootstrap](airgapped-bootstrap) for the current air-gapped path
(signed `.mvmpkg` bundles).
:::

### Recall (revocation list)

A separate `revocations` release tag publishes a cosign-signed `revoked-versions.json`. mvmctl checks this list on every builder image fetch and refuses to use any image whose version is recalled. The recall reason is surfaced verbatim in the failure message, pointing at the upgrade path.

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

### Emergency escape hatches

Two environment variables disable parts of the verification pipeline. Both print loud warnings; both are documented for emergency rotation only:

| Variable | Disables | Use case |
|----------|----------|----------|
| `MVM_SKIP_HASH_VERIFY=1` | SHA-256 check on artifact bytes (existing W5.1) | Mid-flight corruption while the publish flow is broken |
| `MVM_SKIP_COSIGN_VERIFY=1` | Cosign signature check on manifest + revocation list | Sigstore-side outage where TUF root or Rekor is unavailable |

The two are independent — setting one doesn't disable the other. SHA-256 still runs even with cosign disabled, and vice versa.

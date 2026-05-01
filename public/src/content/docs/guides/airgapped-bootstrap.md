---
title: Air-gapped Bootstrap
description: How to run mvmctl in environments that can't reach github.com without disabling supply-chain verification.
---

# Air-gapped Bootstrap

mvmctl normally fetches its dev image (kernel + rootfs) and the
project's [cosign-signed manifest](verify-release) from GitHub
Releases. In regulated, government, or otherwise air-gapped
environments where the host can't reach `github.com`, plan 36 ships
a sanctioned trusted path: `mvmctl dev import-image` runs the same
cosign signature + SHA-256 + version-pin + max-age + revocation
verification pipeline against operator-provided local files.

This is the *only* recommended way to run mvmctl in an air-gapped
host. Setting `MVM_SKIP_HASH_VERIFY=1` to bypass the network fetch
disables the supply-chain check entirely, which is exactly the
unsafe escape this path exists to discourage.

## What you need

For your target architecture (`aarch64` or `x86_64`), four files
from the GitHub release page:

| File | Purpose |
|------|---------|
| `dev-image-{arch}.manifest.json` | Cosign-signed manifest — the trust anchor. Records SHA-256 of every other file. |
| `dev-image-{arch}.manifest.json.bundle` | Cosign signature bundle for the manifest. |
| `dev-vmlinux-{arch}` | Kernel binary. |
| `dev-rootfs-{arch}.ext4` | Root filesystem. |

All four come from the same release tag — they're a set. Mismatched
manifest + artifacts will fail SHA-256 verification.

## Workflow

### 1. Fetch the four files from a connected host

On a host that can reach github.com:

```bash
VERSION=v0.14.0  # match the mvmctl version that will consume them
ARCH=aarch64     # or x86_64
BASE="https://github.com/auser/mvm/releases/download/${VERSION}"

for f in \
  "dev-image-${ARCH}.manifest.json" \
  "dev-image-${ARCH}.manifest.json.bundle" \
  "dev-vmlinux-${ARCH}" \
  "dev-rootfs-${ARCH}.ext4"
do
  curl -LO "${BASE}/${f}"
done
```

### 2. (Optional) Verify the manifest before transit

The connected host can verify the manifest now to catch
manifest-only tampering before sneakernet:

```bash
cosign verify-blob \
  --bundle "dev-image-${ARCH}.manifest.json.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/${VERSION}" \
  "dev-image-${ARCH}.manifest.json"
```

Expect `Verified OK`. mvmctl re-runs this check during `import-image`,
so this step is optional — it just gives you a fast-fail before
transferring 200 MB of rootfs over a slow side channel.

### 3. Transfer to the air-gapped host

Sneakernet, internal artifact mirror, signed USB, scp through a jump
host — whatever your environment allows. The four files must arrive
together; any one being modified or replaced in transit will fail
verification on import.

### 4. Import on the air-gapped host

```bash
mvmctl dev import-image \
  --manifest dev-image-aarch64.manifest.json \
  --bundle   dev-image-aarch64.manifest.json.bundle \
  --vmlinux  dev-vmlinux-aarch64 \
  --rootfs   dev-rootfs-aarch64.ext4
```

mvmctl runs the full verification pipeline:

1. Cosign-verify the manifest signature against the project's
   release-workflow OIDC identity.
2. Pin `manifest.version == mvmctl --version` exactly.
3. Warn (don't fail) if the manifest is past its 90-day max-age.
4. Check the revocation list (skipped if cached and offline; see
   below).
5. Verify each artifact's SHA-256 against the manifest's recorded
   digests.
6. Copy the verified bytes into `~/.mvm/dev/prebuilt/v{version}/`.

On success, the next `mvmctl dev up` boots the dev VM from the
imported artifacts without re-running verification or touching the
network.

## Revocation list in air-gapped environments

The project's [revocation list](verify-release#recall-revocation-list)
lives at a separate `revocations` release tag and tells mvmctl that
specific versions have been recalled. mvmctl caches the list under
`~/.cache/mvm/revocations/` and the cache policy is generous for
offline tolerance:

- Cache valid for **24 hours** before refresh.
- **7 days** of cached staleness tolerated when the network is
  unavailable.
- A 404 on the upstream URL is treated as "no recalls today" — not
  an error.

For long-running air-gapped deployments, periodically transfer a
fresh `revoked-versions.json` + `.bundle` pair into
`~/.cache/mvm/revocations/`:

```bash
# On a connected host:
BASE="https://github.com/auser/mvm/releases/download/revocations"
curl -LO "${BASE}/revoked-versions.json"
curl -LO "${BASE}/revoked-versions.json.bundle"

# Transfer both files, then on the air-gapped host:
mkdir -p ~/.cache/mvm/revocations
cp revoked-versions.json ~/.cache/mvm/revocations/
cp revoked-versions.json.bundle ~/.cache/mvm/revocations/
touch ~/.cache/mvm/revocations/revoked-versions.json
```

`mvmctl dev up` will read the cached file, cosign-verify it, and
enforce any matching recall.

## Failure modes

`mvmctl dev import-image` fails closed. The most common errors and
what they mean:

| Error wording | Cause | Fix |
|--------------|-------|-----|
| `Cosign verification failed for the imported manifest` | Manifest + bundle don't match, or manifest was tampered with after signing | Re-export both files together from the same release tag |
| `Imported manifest is for a different mvmctl version` | manifest.version doesn't match `mvmctl --version` exactly | Use a manifest from the matching release; or upgrade mvmctl first |
| `Manifest is for arch X but this host is Y` | Wrong arch | Re-export the manifest for your host arch |
| `kernel SHA-256 mismatch` / `rootfs SHA-256 mismatch` | Artifact tampered or corrupted in transit | Re-transfer the full set; check transit medium |
| `Imported manifest is on the project's revocation list` | The release was recalled | Use a non-revoked release |

Every failure path bumps a Prometheus counter exposed via
`mvmctl metrics --json` (and the `mvmctl status` JSON output). For
fleet operators, plan 23 wires the same counters into mvmd's
reconciliation loop so attack-shaped spikes — rapid
`dev_image_verify_sig_invalid_total` increases across hosts, in
particular — surface as alerts.
---
title: "Releases & downloads"
description: "How mvm's v* release tags publish binaries, kernels, and images — and how each install path consumes them."
---

Every `v*` git tag fires two GitHub Actions workflows that publish a single
GitHub Release:

- **`release.yml`** builds `mvmctl` for the supported release targets,
  packages each as
  `mvmctl-<target>.tar.gz` (binary + `resources/` + man pages), generates
  `checksums-sha256.txt`, cosign-signs every tarball, builds the builder VM,
  default microVM, and runtime-overlay images, and combines those image outputs
  into signed runtime and builder release packs.
- **`kernel-build.yml`** builds the slim builder + workload kernels on native
  aarch64 and x86_64 runners and uploads `vmlinux-<arch>-<variant>` +
  `kernel-<arch>-checksums-sha256.txt`.

## How each install path consumes a release

| Path | What it pulls |
|------|---------------|
| `install.sh` (curl one-liner) | `mvmctl-<target>.tar.gz` + `checksums-sha256.txt` (+ cosign `.bundle` if cosign present) |
| `brew install tinylabscom/mvm/mvmctl` | the same tarball, via the tap formula |
| `cargo install mvmctl` | source from crates.io (published by `publish-crates.yml`) |
| `mvmctl update` | the tarball for the latest release, in-place swap |
| `mvmctl kernel build --source download` | `vmlinux-<arch>-<variant>` + `kernel-<arch>-checksums-sha256.txt`, pinned to the binary's own release tag |

## Attested fast-first-boot packs

The release workflow publishes pack archives for the fast-first-boot cache path
alongside the binary tarballs:

| Pack | Assets |
|------|--------|
| Runtime pack | `mvm-runtime-pack-<arch>-<backend>.tar.gz`, `.tar.gz.sha256`, `.tar.gz.bundle`, `.manifest.json`, `.manifest.json.bundle`, `.provenance.json`, `.provenance.json.bundle` |
| Builder pack | `mvm-builder-pack-<arch>.tar.gz`, `.tar.gz.sha256`, `.tar.gz.bundle`, `.manifest.json`, `.manifest.json.bundle`, `.provenance.json`, `.provenance.json.bundle` |

Runtime packs are produced for the supported release matrix:
`aarch64:vz`, `aarch64:libkrun`, `aarch64:firecracker`, and
`x86_64:firecracker`. Builder packs are produced for `aarch64` and `x86_64`.

Every pack manifest records the release version, git revision, archive SHA-256,
file SHA-256s and sizes, SBOM SHA-256, channel (`github_release`), architecture,
and backend where applicable. `verify-release-assets.sh` is the post-publish
gate: it fails the release if a pack archive, checksum, manifest, provenance
file, signature bundle, SBOM reference, or expected version field is missing or
inconsistent.

## Verifying provenance

All release tarballs and pack manifests/provenance files are cosign-signed
(keyless, GitHub OIDC). To verify manually:

```bash
cosign verify-blob \
  --bundle mvmctl-<target>.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/.*' \
  mvmctl-<target>.tar.gz
```

`install.sh` and `mvmctl update` run this automatically when `cosign` is on
`PATH`.

## Homebrew tap setup (one-time, maintainers)

The `update-homebrew-tap.yml` workflow renders the formula on each release and
pushes it to the `tinylabscom/homebrew-mvm` tap. It clones over HTTPS with
`https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/...`, so the token must
be a **PAT with Contents-write access** to the tap repo — the default
`GITHUB_TOKEN` cannot push to a second repository, and a deploy key would
require switching the clone URL to SSH.

### 1. Create the tap repo

The token is scoped to it, so it must exist first:

```bash
gh repo create tinylabscom/homebrew-mvm --public \
  --description "Homebrew tap for mvmctl"
```

The workflow writes `Formula/mvmctl.rb`; it creates the `Formula/` directory if
absent, so no manual seeding is required.

### 2. Create the token (fine-grained PAT, recommended)

GitHub → **Settings → Developer settings → Personal access tokens →
Fine-grained tokens → Generate new token**:

- **Resource owner:** `tinylabscom` (the org, not a personal account).
- **Repository access:** *Only select repositories* → `tinylabscom/homebrew-mvm`.
- **Permissions → Repository → Contents:** *Read and write*.
- **Expiration:** set a renewal window and calendar a refresh.

Org caveat: the `tinylabscom` org must allow fine-grained PATs, and an org owner
may need to approve the token before it works. If that path is blocked, fall
back to a **classic PAT** with the `repo` scope (broader — prefer fine-grained
when allowed). Copy the token; it is shown once.

### 3. Add the secret to the main repo

The secret lives on `tinylabscom/mvm` (where the workflow runs), named exactly
`HOMEBREW_TAP_TOKEN`:

```bash
gh secret set HOMEBREW_TAP_TOKEN --repo tinylabscom/mvm
# paste the token when prompted (it is not echoed)
```

### 4. Verify

Dispatch the workflow once against an existing release tag (works after this
workflow is on the default branch):

```bash
gh workflow run update-homebrew-tap.yml --repo tinylabscom/mvm -f tag=v0.15.2
gh run watch --repo tinylabscom/mvm
```

On success the tap gets `Formula/mvmctl.rb` and `brew install
tinylabscom/mvm/mvmctl` resolves. If the secret is missing or wrong, the
*Push to tap* step fails loudly (`::error::HOMEBREW_TAP_TOKEN not set`) rather
than silently doing nothing.

After that, every `v*` release auto-updates `Formula/mvmctl.rb` in the tap.

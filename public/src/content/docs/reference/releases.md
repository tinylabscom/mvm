---
title: "Releases & downloads"
description: "How mvm's v* release tags publish the CLI, how boot images reach it from the pinned image set, and how each install path consumes them."
---

Every `v*` git tag fires **`release.yml`**, which builds `mvmctl` for the
currently published targets (`aarch64-apple-darwin`,
`x86_64-unknown-linux-gnu`, and `aarch64-unknown-linux-gnu`), packages each as
`mvmctl-<target>.tar.gz` (binary + adjacent host helpers + `resources` + man
pages), generates `checksums-sha256.txt`, cosign-signs the tarballs, the
manifest and the SBOM, attests build provenance, and publishes one GitHub
Release. It does not build, mirror or re-sign boot images: those come from the
image set pinned by `crates/mvm-core/images.lock`, published by
[`mvm-images`](https://github.com/tinylabscom/mvm-images), as described in
[Image releases and the support window](#image-releases-and-the-support-window).

## Promotion: a release reaches users only after a fresh install boots

`release.yml` publishes every tag as a GitHub prerelease. A stable tag stays
one until the `first-run-smoke` job has installed it the way a new user
would — the tag's own `install.sh`, pinned to the tag, into a throwaway `HOME`,
builder bootstrap included — and run the README's first command,
`mvmctl machine run --image alpine -- echo <token>`, with stdin closed and a
time budget. It then boots twice more from the same `HOME`, each with its own
token and budget. The second boot is the first to take the runtime overlay and
initramfs from the cache rather than from the download it has just made, so it
must print its token and must not replace any file the first boot cached. The
third binds an SDK host service (`--host-service host.time.v1`), which downloads
the published SDK sidecar, and the guest must find the SDK library under
`/mvm/sdk`. A release binary refuses or fetches again any of these artifacts
whose `VERSION` is not its own, and only the later boots reach that check. The
smoke runs on the self-hosted Apple Silicon runner (HVF) and on a
hosted Linux runner with KVM (Firecracker). When every lane prints its tokens,
`promote-release` makes the tag a full release and GitHub's latest, and
dispatches the site deployment that bakes it into `https://runmvm.com/install.sh`
as the offline fallback. A release candidate runs the same smoke and stays a
prerelease.

Until then nothing moves a user onto the tag: `install.sh` installs the newest
full release, `mvmctl env update` follows GitHub's latest marker, and the
served installer's fallback still names the previous release. A red smoke
leaves the tag staged; the fix ships as a new tag. The same check runs locally
with `just e2e::smoke-fresh-install [version]`, leaving `~/.mvm` and `~/.local`
alone.

The lanes live in `.github/workflows/first-run-smoke.yml`, which `release.yml`
calls. To prove them on the real runners before a tag depends on them,
dispatch that workflow against a published tag:
`gh workflow run first-run-smoke.yml --ref main -f tag=v0.18.0-rc.1`. The
installer and the smoke script come from the dispatched ref; the binaries and
artifacts come from the tag. That exercises the runners, the installer, and
that tag's first run. It does not exercise code that has not been released yet:
for that, tag a release candidate, which runs the same lanes and stays a
prerelease.

## How each install path consumes a release

| Path | What it pulls |
|------|---------------|
| `install.sh` (curl one-liner) | the newest full `v*` release publishing `mvmctl-<target>.tar.gz` (or `MVM_VERSION`): that tarball + `checksums-sha256.txt` + its `.bundle` |
| `brew install tinylabscom/mvm/mvmctl` | the same tarball, via the tap formula |
| `cargo install mvmctl` | source from crates.io (CLI binary only; no adjacent helper bundle) |
| `mvmctl env update` | the tarball for the latest release, in-place swap |
| `mvmctl build kernel build --source download` | the kernel member of the pinned image set, verified against its signed root |
| `mvmctl build runtime-overlay build --source download` | `runtime-overlay-<arch>.tar.gz` from the pinned image set, verified against its signed root; the tarball contains `overlay.ext4`, `overlay.verity`, `overlay.roothash`, `VERSION`, and `checksums-sha256.txt`, installed into `~/.mvm/cache/image-set/<root-sha256>/runtime-overlay/<member-version>/<arch>/` |

## Image releases and the support window

Boot images — the builder VM, the default and rootless workload images, the
workload and Stage 0 kernels, the runtime overlay and the SDK sidecars — are
built and signed in [`tinylabscom/mvm-images`](https://github.com/tinylabscom/mvm-images)
and published as `image-set/v*` releases. Each release carries one signed
root, `image-set.json`, that names every member by digest and size. Image
changes land in `mvm-images`. The `mvm` tree's own image flakes under
`nix/images/` were deleted, together with the `release-boot-image.yml` and
`kernel-build.yml` workflows that published from them; the `mvm` tree cannot
build an image, and a request for one says so rather than failing on a missing
flake.

Which URLs a CLI reads depends on its version:

| `mvmctl` version | Builder VM, default image, kernels, Stage 0 | Runtime overlay, SDK sidecar, initramfs |
|---|---|---|
| v0.17.0 and earlier | its own `v{version}` release on `tinylabscom/mvm` | its own `v{version}` release |
| v0.18.0-rc.1 | `tinylabscom/mvm` release `boot-image/v0.1.5`, signed by `release-boot-image.yml` | its own `v{version}` release |
| releases cut after 2026-09-24, before the in-tree images were deleted | the `mvm-images` `image-set/v*` release pinned by the binary's `images.lock`, admitted only after the root verifies against that release's `release.yml` identity | its own `v{version}` release, whose copies `release.yml` mirrored from the same pinned set |
| every later release | the same pinned `image-set/v*` release | the same pinned `image-set/v*` release; the CLI's own release carries no image assets |

Nothing in that table is deleted. `boot-image/v*` and every `v*` release stay
published, so an older CLI keeps finding the bytes it was built against. What
changes over time is what is published next:

- **Mirroring (ended).** CLI releases used to attach the pinned set's assets
  under the names CLI releases had always carried, re-signed after the release
  verified them against the signed root. Once the runtime overlay, SDK sidecar
  and initramfs were fetched from the image set directly, the mirror was
  removed; CLI releases from then on carry no image assets.
- **Legacy producer retirement.** No new `boot-image/v*` release is published:
  the producer was deleted with the in-tree image flakes. The `legacy` entry in
  `images.lock`, which records that producer's release and signing identity,
  stays until 2026-12-31 and is removed in the first release after that date.
  It is a record for the support window, not a fallback: no current CLI
  selects it.
- **Pin updates.** `update-image-pin.yml` runs every Monday at 09:23 UTC and on
  demand. It verifies the newest `image-set/v*` root's keyless signature and
  opens a pull request that advances `images.lock`; it never merges. The merge
  queue's boot lanes then fetch, verify and boot the proposed set before it
  lands. An image-only change therefore needs a pin update, not a CLI release.
- **Rollback.** Selecting an earlier image set is an `images.lock` change back
  to an existing, verified `image-set/v*` release. Rolling a current CLI back
  to `boot-image/v*` is not possible: those releases publish no signed root for
  the lock to pin.

## Member identity

The runtime overlay, the SDK sidecars and the initramfs that `mvmctl` fetches
from the image set are identified by the signed root its `images.lock` pins,
not by the CLI's own version. Each member carries the `VERSION` of the `mvm`
workspace that `mvm-images` built it from, which is usually not the version of
the CLI that later pins the set.

`mvmctl` files each member under the digest of that root —
`~/.mvm/cache/image-set/<root-sha256>/` for the runtime overlay and SDK
sidecars, `~/.mvm/cache/initramfs/image-set/<root-sha256>/` for the
initramfs — and records the member's own `VERSION`, read from the verified
bytes, beside it. A later boot expects that recorded version and makes every
other check unchanged. A cached member from a root the binary no longer pins is
not used; the pinned root's member is fetched instead.

Whether a host can run a set is decided by the compatibility the signed root
declares — the guest-agent protocol range and the builder cache contract —
which is checked before any member is fetched. A CLI version bump therefore
does not need a new image set. A change to the declared compatibility does.

Artifacts built from a selected `mvm-images` checkout, or from this source tree,
are still checked against the running CLI's version.

## Runtime overlay assets

The shared guest-runtime overlay is a member of the image set:

- `runtime-overlay-<arch>.tar.gz`

It is the readonly guest-runtime payload consumed by
overlay-backed boots — part of the shipped surface for the backends that admit
`RequiredOverlay`, not an optional side channel or a developer-only cache
convenience.

The tarball is verified against the signed root before extraction. Inside it,
the canonical payload is still per-file checked: `overlay.ext4`,
`overlay.verity`, `overlay.roothash`, `VERSION`, and an inner
`checksums-sha256.txt`. When `mvmctl` installs that payload into
`~/.mvm/cache/image-set/<root-sha256>/runtime-overlay/<member-version>/<arch>/`, every required-overlay boot
re-hashes those cached files before attach and refuses to mount the overlay if
the cache entry has drifted.

Only **guest-executed** runtime binaries belong in this artifact. Host-side
helpers and supervisors still ship in the `mvmctl-<target>.tar.gz` bundle next
to `mvmctl`.

## Runtime overlay rollout contract

Operationally, runtime-overlay updates are a **release + restart** story:

- A fresh boot on an admitted backend resolves the runtime overlay of the image
  set the running `mvmctl` pins, re-verifies the cached artifact checksums,
  and mounts it read-only inside the guest.
- A stopped VM picks up the overlay the host now resolves on its next
  `machine start` or `machine restart`.
- A running VM keeps the overlay version it already booted with until restart.
- mvm does **not** hot-remount or live-swap a different runtime overlay into an
  already-running guest.

That means the normal rollout path is:

1. Publish the new `mvmctl` release, pinning an image set whose declared
   compatibility covers it.
2. Update hosts to that release.
3. Restart overlay-backed VMs when you want them to adopt the new runtime.

## Rollback / downgrade behavior

Rollback follows the same pinning rule:

- If you downgrade `mvmctl` to an earlier release, the host resolves the
  runtime overlay that earlier release pins (or, for releases that predate the
  image set, published on its own release).
- Running VMs are unchanged until restart.
- Restarted VMs come back on the downgraded version's overlay, assuming the
  matching assets are still available and verified.

If a backend cannot safely consume the runtime overlay for a given boot shape,
it must fail closed rather than silently falling back to a writable or
version-skewed runtime path.

## Verifying provenance

All release tarballs are cosign-signed (keyless, GitHub OIDC). To verify
manually:

```bash
cosign verify-blob \
  --bundle mvmctl-<target>.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/.*' \
  mvmctl-<target>.tar.gz
```

`install.sh` and `mvmctl env update` run this automatically when `cosign` is on
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

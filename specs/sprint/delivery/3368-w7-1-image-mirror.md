# W7.1 — CLI releases mirror the locked image set behind a digest gate

Backing: shipped-source
Validation: cargo nextest run -p xtask release_boot_image; cargo nextest run -p mvmctl --test release_assets

Issue #3368, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md` W7.1.

## What was broken

`release.yml` attached the boot image to each CLI release by downloading the
lock's boot tag from `GITHUB_REPOSITORY`. Since W6 that tag is
`image-set/v0.1.0`, which exists only in `tinylabscom/mvm-images`, so the next
CLI tag would have stopped at "no release with that tag exists". The attached
assets matter to current CLIs, not only old ones: the runtime overlay, SDK
sidecar and initramfs are still downloaded from the CLI's own `v{version}`
release and verified under `release.yml`'s identity.

## What changed

- The release step reads repository, manifest name and tag from `images.lock`,
  downloads the whole pinned set, and has the `mvmctl` it is about to publish
  run `image boot verify --require-complete` over it. `--lock` now defaults to
  the lock compiled into the binary.
- `xtask release-boot-image validate` then checks the 38 legacy-named assets:
  member files by the root's digest and size, checksum manifests and `.sha256`
  sidecars against both their files and the root, and refuses any file
  nothing anchors. Only after both gates do the files reach `artifacts/` and
  get signed.
- `default-microvm-*.sbom.txt` is no longer republished: nothing the root signs
  anchors it, and no code path downloads it.

## Evidence

Run on 2026-09-24 against the published `image-set/v0.1.0`:

- `mvmctl image boot verify --require-complete` (no `--lock`): verified,
  manifest `9bb4f0bf…f2ff`, signer key id `6996feb9248dd8eee1e335470cbff52a`,
  29 artifacts.
- `xtask release-boot-image validate image-set/v0.1.0 <mirror>`: accepted.
- The same with one byte appended to `default-microvm-meta-x86_64.json`:
  refused, naming the file and the checksum manifest it drifted from.

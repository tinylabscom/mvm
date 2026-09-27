# W8 Waves 3+4 — the CLI release stops building images, and nix/images goes

Backing: shipped-source
Validation: cargo nextest run -p mvmctl --test release_assets --test github_actions_extended_e2e

Issue #3366, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md` Waves 3
and 4.

## Wave 3: workflows

- `release-boot-image.yml` and `kernel-build.yml` are deleted.
- `release.yml` no longer builds the initramfs, and no longer mirrors or
  re-signs the image set. The overlay, sidecar and initramfs have come from the
  pinned set since Wave 0.5b.
- The in-tree image legs of `cache-warm.yml`, `ci.yml`, `ci-full.yml`,
  `security.yml` and `kernel-cve-watch.yml` are gone.

Every release that already exists stays published.

`verify-release` checked for a per-archive `.sha256` that the release never
uploads, so it had failed on every CLI release. It now checks each archive
against the signed combined manifest, which is what the installer and
`mvmctl update` compare against.

The lanes the re-pointing touched had never run in CI, so they were dispatched
on this branch before it opened. All passed:

- security run 36298381536: `verified-boot-artifacts` (the claim 3 witness) and
  both sealed-prod lanes
- Extended CI run 36298382873: every hosted no-KVM bootstrap stage

The same dispatch found two failures in the documented-surface suite:

1. The suite's SDK sidecar step needed an `mvm-images` checkout. Waves 1+2
   added one.
2. `mvm-images` `main` had started writing a `builder_boot_abi` compatibility
   field this tree does not parse. The checkout is now taken at the release tag
   the image lock pins.

## Wave 4: tree

- `nix/images/` and `nix/packages/qemu-wasm*` are deleted. The llm-agent recipe
  the examples import moved to `nix/examples/llm-agent`.
- `check-runtime-overlay-version` (along with the `_release-prep` bump of
  `nix/images/version.nix`), `check-kernel-config-budget` and `build-dev-image`
  are retired.
- `check-guest-binary-lists` and `check-kernel-pin-freshness` read what
  remains.
- ADR-030 item 4 now names the selected `mvm-images` checkout as the local build
  source. It keeps the no-silent-substitution and `source: fetched` rules.
- `CLAUDE.md`, `README.md`, the quickstart, the happy paths and the CLI
  reference say image construction lives in `mvm-images`.

## Notes for the next reader

- **The builder source fingerprint is gone.** Waves 1+2 removed it, along with
  `host_binaries::manifest::is_baked_into_rootfs`, including the layer extended
  for #3447 to key on the baked host binaries. It only served the in-tree
  Stage 0 builder key. The pair build's consumed-input key (#3741) is
  untouched.
- **The dev-image warm costs time.** `mvmctl run` with no image now needs an
  image checkout or a cached image. On the Linux lane, the documented-surface
  suite builds the dev default image through the pinned `mvm-images` checkout
  so the Firecracker rootfs byte-identity scenario keeps its witness. That warm
  took 2,543 s in Extended CI run 36327887644, and the in-tree build it
  replaces took about 17 minutes inside the suite. The lane grew by about 25
  minutes (154 against 129 minutes, phase totals). Publishing the dev variant
  as an image-set member would let the lane fetch it instead.

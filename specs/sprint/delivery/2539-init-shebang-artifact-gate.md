# 2539 — gate the bytes the kernel execs, not just their checksum

## What shipped

An artifact-level assertion that a `default-microvm` rootfs carries a `/init`
the kernel can exec, wired into both ends of the release path.

- `nix/packaging/release/assert-init-shebang.sh` — reads `/init` out of an
  unmounted ext4 with `debugfs` (no mount, no loop device, no root) and refuses
  a rootfs whose first bytes are not `#!/bin/sh`.
- `.github/workflows/release.yml` — runs it on the staged image in the
  `default-microvm` job, before the upload. A rootfs that cannot boot never
  becomes a release asset.
- `nix/packaging/release/verify-release-assets.sh` — a new boot-asset section
  requires the `default-microvm` rootfs/kernel/meta trio to be present, listed
  in and matching the signed per-arch checksums manifest, and runs the same
  assertion on the published, re-downloaded image.
- `.github/workflows/ci.yml` — shellchecks the new script, and widens the
  scope regex from `verify-release-assets*.sh` to every `.sh` under
  `nix/packaging/release/`, so a change to the new file is not invisible to CI.

## Why the existing gates could not catch it

Three source-level guards inspect the *generator* (`mk-guest.nix`'s
`lib.throwIf`, `mk_guest_init_shebang_lands_at_byte_zero`, and the substring
test that #2538 removed). Nothing between `nix build` and `gh release create`
opened the ext4, and `verify-release-assets.sh` re-downloaded the published
assets without looking inside them — it checked only the pack sidecars, never
the rootfs itself. A checksum cannot separate a good image from a faithfully
copied broken one, which is why v0.17.0 verified clean for five weeks.

## COMPLETE-or-ABSENT, deliberately

The boot-asset section follows the same contract as the builder and runtime
pack checks. The `release` job publishes under `!cancelled()`, so an image job
that failed leaves these assets absent *on purpose* and the binary download
still ships. Absent is fine; partial, or present-and-unbootable, is not.

## Evidence

Run on Linux (e2fsprogs 1.47.0, matching `ubuntu-latest`):

- `verify-release-assets.test.sh` — 20 passed, 0 failed, including four new
  boot-asset scenarios. The regression case builds a real ext4 whose `/init`
  shebang sits at byte 1 and **re-records its hash**, so the checksum layer has
  nothing to say and only reading `/init` catches it.
- Pointed at the actually-published `v0.17.0` `default-microvm-rootfs-x86_64.ext4`:
  `sha256sum -c` reports `OK`, `/init` reads
  `20 23 21 2f 62 69 6e 2f 73 68 0a`, and the gate rejects it. That is the
  defect and the blind spot demonstrated on one artifact.
- The scenarios are skipped, loudly, where `mkfs.ext4`/`debugfs` are absent
  (macOS), and `--boot-arches ""` switches the gate off there rather than
  reporting a check that never ran.

## Not done here

Booting the staged image before publishing — strictly stronger than a byte
check on x86_64 — is WS1 of the boot-image-lifecycle spec (#2547). This gate
composes with it rather than replacing it: WS1's own stated gap is that the
`aarch64` leg gets a header check rather than a boot, and this is that check,
on both arches.

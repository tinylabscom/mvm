# The builder image key folds only the binaries the image bakes

Backing: shipped-source
Validation: layer_two_folds_exactly_the_manifest_host_binaries

Workstream W0 of `specs/plans/2026-09-24-builder-image-without-host-bins.md`.

Layer 2 of `builder_vm_source_fingerprint` folded the name and SHA-256 of every
binary in `mvmctl`'s Linux payload. Only `HOST_BINARIES` (`mvm-host-vm-init`,
`mvm-builderd`) are installed in the builder rootfs. The seed binaries
(`stage0-init`, `mvm-rootfs-patcher`) and the bootstrap-support binary
(`mvm-egress-client`) never reach it, yet an edit to any of them rebuilt the
builder image through Stage 0.

Layer 2 now folds a payload binary only when the manifest's `HOST_BINARIES`
names it. The baked set is read from that list, not restated.

## Why the unbaked bytes cannot reach the image

- The builder flake maps `mvm.lib.<system>.hostBinaries`, which is
  `nix/lib/mvm-host-binaries.nix`, to `extraFiles`, one file per name
  (`nix/images/builder-vm/flake.nix` `hostBinExtraFilesFor`). It copies
  `hostBinDir + "/<name>"` for each listed name, never the directory.
  `check-mvm-host-binaries-sync` holds that file equal to `HOST_BINARIES`.
- `stage0-init` copies nothing of its own into the output.
  `copy_artifacts_into` copies only the kernel, `rootfs.ext4`, and the
  cmdline and manifest from the `nix build` result.
- `mvm-egress-client` is the Stage 0 egress shim. `stage0-init` forks it from
  `/mvm-bins`, and it carries fetch traffic but no build output. The copy the
  runtime overlay ships is built from source by
  `nix/packages/mvm-egress-client.nix`, not taken from the payload.
- The HVF patcher's inject initramfs installs only the binaries listed in its
  payload manifest, and `resolve_hvf_builder_image` lists
  `mvm-host-vm-init` alone. The patched image has its own key over kernel,
  rootfs and init, and does not read this fingerprint.

## One-time invalidation

The key's value changes for every existing Stage 0 builder cache, so each
contributor's next build rebuilds the builder image once.

## Tests

- `builder_vm_source_fingerprint_ignores_seed_and_support_binary_digests`
- `builder_vm_source_fingerprint_changes_with_each_baked_binary_digest`
- `layer_two_folds_exactly_the_manifest_host_binaries`

They pass stand-in digests through `fingerprint_builder_vm_sources`
and `fold_baked_binary_identities`, so they do not depend on the payload
compiled into the test binary.

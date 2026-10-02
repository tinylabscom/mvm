# mvm-bundler

`mvm-bundler` seals built artifacts into a signed `.mvmpkg`. It is the one
place that decides what an exported bundle contains: the kernel, the rootfs,
an optional initrd, the dm-verity pair when the rootfs has one, and the guest
sidecar the runtime refuses to boot without.

The bundle format is not defined here. Manifest types, canonical signing, and
the archive writer live in `mvm_core::plan::bundle`; this crate turns files on
disk into a manifest and hands both to that writer.

## Who it is for

Any caller holding built artifacts and a key to sign with. It exists so that
`mvmctl bundle export` and a library consumer produce a bundle the same way,
without the library having to link the CLI to get there.

## How it works

1. The caller fills in `BundleExportInputs`: artifact paths, the
   architecture label, the output path, and optionally the profile and the
   resources the workload was sized for.
2. The caller supplies a `BundleSigner`. The host key is one implementation;
   a test or another tool can supply its own.
3. `export_bundle_with_signer` reads the artifacts, records a SHA-256 and a
   role for each, builds the manifest, signs it, and writes the archive.
4. `ExportedBundle` reports where the archive went, how large it is, and
   which key signed it.

A rootfs with half a dm-verity binding, or with no sidecar beside it, is
refused before anything is written. Both would otherwise produce a bundle
that installs cleanly and fails at admission on the host it was sent to.

## Debug summary

Setting `debug_out` writes a JSON document beside the export: the bundle
path, its size and SHA-256, and the manifest as signed. It is for inspecting
what an export produced and is not part of the bundle; nothing reads it back.

## Dependencies

The closure is `mvm-core` plus what it already carries. Verity probing and
template resolution stay with the caller, in `mvm-runtime`, so this crate
does not depend on a backend.

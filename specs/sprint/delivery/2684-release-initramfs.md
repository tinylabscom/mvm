# Publish and live-gate the universal initramfs

Issue #2684 exposed a release-contract gap: installed `mvmctl` knows how to
download the universal initramfs for a CLI version, but the `v*` release train
never published that archive. A production rootfs could therefore be shipped
with its dm-verity sidecars while the initramfs required to mount it was an
unreachable 404.

The CLI release workflow now builds both architectures, packages every member
the existing extractor requires, uploads the exact names produced by
`InitramfsArtifactNames`, and attaches the archives and checksums to the release.
The release job checks the initramfs job's result explicitly: `needs` alone is
not a hard gate when the job uses `!cancelled()`.

## The staged artifact is exercised both ways

Publication makes the sealed path reachable, but it does not prove it boots.
The boot-image train's existing x86_64 KVM gate now runs the staged production
image twice before upload:

1. the existing plain rootfs boot, preserving the independent compatibility
   witness;
2. a sealed boot with the universal initramfs, rootfs verity sidecar, and
   root hash from the same staged build.

The runtime boot harness treats those three sealed inputs as an atomic set and
validates the root hash before constructing `VmStartConfig`. Partial or malformed
configuration fails at the boundary instead of silently degrading to an
unsealed boot.

The boot-image workflow builds only a raw local initramfs for this gate. It does
not publish that copy: versioned initramfs archives belong to the CLI `v*`
release train because that is the version namespace used by the downloader.

## Regression coverage

Workflow tests pin the producer/consumer asset names, both architectures, all
archive members, the hard release-result gate, the two boot invocations, and
the complete sealed environment. Focused harness tests cover absent, complete,
partial, and malformed integrity inputs plus the final launch configuration.

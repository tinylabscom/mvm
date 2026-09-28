# W8 release decoupling — image-set members are identified by the pinned root

Backing: shipped-source
Validation: cargo nextest run -p mvm-fs -p mvm-build -p mvm-client -p mvm-cli --features mvm-build/test-support

Issue #3366, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md`,
"Release decoupling".

## The bug

The runtime overlay, SDK sidecars and initramfs come from the signed image
set that `images.lock` pins, and each carries a `VERSION` file. That file holds
the `mvm` version the image set was built from, not the version of whichever CLI
later pins the set. Every resolver compared it by exact string equality with
`CARGO_PKG_VERSION`.

`image-set/v0.2.1` members say `0.18.0-rc.2`, and `main` is `0.18.0`. So any
0.18.x release binary, which acquires these members by download:

- refused the SDK sidecar with `VersionMismatch`
- downloaded the runtime overlay again on every boot
- failed the initramfs from its second boot on

The documented-surface suite runs from a source checkout, which builds these
artifacts locally, so it could not see the bug.

## The fix

For members acquired from the set:

- **Cache key.** The cache is keyed by the pinned root's sha256, under
  `image-set/<root>/`, instead of by the CLI version. The initramfs keeps a
  `<cache>/initramfs` prefix, which the universal-initramfs boot path
  recognises.
- **Provenance record.** Each entry has a provenance record naming the root,
  role, target and the member's own `VERSION`, which is read from the
  digest-verified bytes. The record is written only after the install
  completes. A record for another root, role or target is refused.
- **Resolution.** The resolver expects the recorded version. Every other
  resolver check still runs.
- **Compatibility.** Compatibility is the signed root's declared range,
  already checked at acquisition.

Pair builds, source builds, the version-keyed cache and seeding from the default
cache keep exact equality with the CLI version. A member `VERSION` becomes a
path segment, so it is limited to a conservative alphabet.

## Tests and evidence

- Tests for each artifact kind:
  - a member at another version installs and resolves from cache with no
    network
  - an entry from another root is not reused
  - the version-keyed and pair routes still refuse a mismatch
- An independent review found no blocker. Its two minor notes are recorded in
  the pull request.
- The download-mode witness is the three-boot first-run smoke (#3782). It fails
  if a second boot re-downloads the overlay or initramfs, and it needs the
  published sidecar in download mode.

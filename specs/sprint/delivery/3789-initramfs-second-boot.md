# Universal initramfs: a partial version-keyed cache dir poisons the second boot

Backing: shipped-source
Validation: cargo test -p mvm-build -p mvm-client (1,424 tests, all green);
`cargo clippy -p mvm-build -p mvm-client --all-targets -- -D warnings`

Issue #3789.

## The bug

The universal initramfs resolved on the first boot after a fresh cache and
failed on the second, for every contributor-channel binary run from a source
checkout. Release-channel binaries were unaffected.

1. First boot: the version-keyed cache misses, the ladder falls through to
   the pinned image set's initramfs member, and the artifact installs under
   `cache/initramfs/image-set/<root>/<member-version>/<arch>/`.
2. The launch path then recorded the guest-source fingerprint into the
   **version-keyed** dir `cache/initramfs/<cli-version>/<arch>/` — a
   directory the resolved artifact does not live in — leaving a partial
   entry (the fingerprint alone).
3. Second boot: the resolver sees the version-keyed dir, finds
   `initramfs.cpio.gz` absent, and reports `MissingEntry`. The
   build/download ladder only fell through on `Missing`, so the error
   propagated and the launch refused.

Witnessed live on Linux x86_64 and aarch64 (rpi1) hosts during the
image-set/v0.2.1 boot witnesses: first Firecracker boot OK, immediate second
boot failed with `initramfs cache entry missing`.

## The fix

- `resolve_or_build_local_initramfs` treats a partial version-keyed entry as
  a recoverable miss, exactly like an absent one, and removes the partial
  dir so the ladder's install is the only writer. A version or size
  disagreement still refuses — those bytes exist and the cache cannot vouch
  for them.
- The launch path records the source fingerprint only when the resolved
  artifact actually lives in the version-keyed directory
  (`record_source_fingerprint_for_resolved`). A pinned-set member's
  provenance is the signed root, not the checkout, so no new partial entry
  is created.

## Tests

- the recoverable-miss predicate: absent and partial entries fall through;
  version and size mismatches refuse
- fingerprint recording writes for a version-keyed local artifact and skips
  a set-member artifact (no partial dir created)

# Refresh host snapshots at machine start

Backing: shipped-source
Validation: check-sprint-append

**Status: COMPLETE**

## Goal

Make both persistent `machine volume mount --host` attachments and transient
`machine run --mount` use one content-addressed directory-to-ext4 cache. A
persistent machine fingerprints its registered source immediately before every
start and refreshes the attached image when the source changed. A missing
source refuses the start instead of silently serving stale bytes.

## Delivery

- [x] Add a materialization-semantic source fingerprint and focused tests for
      byte, mode, symlink, and guest-visible xattr changes.
- [x] Add an immutable, atomically published, verify-on-read mount-image cache
      with read-only direct attachment and writable reflink/copy materialization.
- [x] Persist the source directory and fingerprint with ad-hoc snapshot
      registrations, then refresh them before launch lease acquisition.
- [x] Route transient `--mount` through the same cache and produce the existing
      fingerprint, lookup, and materialization timing spans.
- [x] Cover cache hit/miss, equal-timestamp content changes, missing sources,
      cache tampering, and writable-copy isolation with unit and BDD tests.
- [x] Update CLI/help documentation and the sprint/refactor rollups.
- [x] Run workspace test/check, zero-warning Clippy, gated checks, `just bdd`,
      and live Firecracker validation of edit → stop → restart → changed guest
      bytes.

## Decisions

- Source change means a SHA-256 fingerprint of the filesystem semantics the
  ext4 writer emits. Timestamps are excluded because the emitted image zeros
  them; permission bits and guest-visible xattrs are included because the image
  preserves them.
- A missing registered source is a hard pre-boot refusal. The cached image is
  not an implicit availability fallback.
- Cache images are immutable and verified against a strict manifest plus their
  exact image digest before attachment. Writable registrations receive a
  private reflink/copy and never mutate the cache object.
- An unchanged writable registration keeps its private image so guest writes
  persist across restarts. A host-source change replaces that private image
  from the newly selected cache object.

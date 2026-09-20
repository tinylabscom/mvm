# `mvmctl env update` verifies the release signature in-process

Issue #3272.

`verify_signature` in `crates/mvm-cli/src/update.rs` ran `cosign verify-blob`
and returned `Ok` with a warning when `cosign` was not on `PATH`. So on the one
path that replaces the `mvmctl` binary, the publisher check depended on what the
host happened to have installed, and the SHA-256 it fell back on comes from a
manifest fetched over the same channel as the archive.

It now calls `mvm_build::release_signature::verify_release_archive_signature`
with the CLI release train: the verifier the fetch path and the runtime overlay
already use, against the same embedded trust root. A missing, unparseable, or
foreign-signed bundle refuses the update. No dependency is added; release builds
already carry `manifest-verify`. An `mvmctl` built without it refuses to
self-update and says why, rather than installing unverified.

`--skip-verify` keeps its meaning (skip the signature, keep the SHA-256), and
its help text now says that; it used to say "Skip checksum verification", which
was wrong.

Claim 20 originally named these three paths. The later epic #3277 closure added
the install path: a fresh host authenticates the baked archive against an
installer-carried SHA-256 before using its `mvmctl` when capable. A legacy or
unpinned archive uses a separately hash-pinned temporary cosign and executes no
archive byte before verification. A build without `manifest-verify` remains a
refusing implementation boundary.

The `manifest-verify` tests on these paths never ran in CI: every use of the
feature there was `cargo run --example`. A step in `Lint feature coverage` runs
them now, which is what lets the ledger cite them.

## Witnesses

- `an_archive_without_a_bundle_is_refused`
- `an_archive_with_a_garbage_bundle_is_refused`
- `a_real_release_bundle_verifies_under_its_tag`: the committed
  `v0.18.0-rc.1` bundle verifies under `v0.18.0-rc.1` and is refused under
  `v0.18.0`. This is the test that shows the `v` in the tag and the one in the
  identity template are not doubled.

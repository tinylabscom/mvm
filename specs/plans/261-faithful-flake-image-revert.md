# Faithful flake-image revert

Issue: #1840

Status: COMPLETE

## Scope

Flake image-lineage nodes currently identify the slot and revision but the
restore path can only follow the slot's current revision. This work adds an
exact stored-revision source that resolves the recorded artifact directory,
reconciles its committed `vmlinux` and `rootfs.ext4` hashes, and then routes
the source through the existing admitted transient runner.

Rebuilding the flake is intentionally excluded: it could resolve different
source inputs while claiming to restore the historical image.

## Delivery checklist

- [x] Add lifecycle resolution for a specific manifest slot revision without
      following `current`.
- [x] Add a pinned template image source to the transient runner.
- [x] Reconcile every signed flake-node artifact before boot and reject path
      traversal or missing required boot artifacts.
- [x] Route a successful flake revert through the normal admission callback.
- [x] Add success, missing-revision, and tampered-artifact tests.
- [x] Run workspace format, tests, check, and clippy gates.
- [ ] Publish the verified branch as a pull request.

## Verification

Verification passes:

```text
cargo test -p mvm-cli --lib commands::vm::checkpoint::revert -- --nocapture
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings
```

The branch is ready for pull request review.

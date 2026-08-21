# Artifact acquisition is a distribution contract

Official `mvmctl` binaries no longer infer that they should compile launch
artifacts merely because they are executed from an mvm source checkout. A
compiled distribution channel now decides the automatic default: contributor
builds may build source-matched artifacts, while release builds acquire signed,
published artifacts. Explicit source overrides remain available for deliberate
developer workflows.

The same policy now governs the boot image, workload kernel, universal
initramfs, runtime overlay, and OCI guest runtime. The runtime-overlay release
archive carries all six static OCI guest binaries and their checksums; acquiring
that archive atomically seeds both the overlay cache and the guest-runtime
cache. Structural release tests and the guest-binary-list gate prevent the
producer, installer, and guest injection lists from drifting.

`mvmctl bootstrap` prepares every launch-critical artifact rather than stopping
after the builder VM and kernel. Image pull and every image-backed launch entry
point also pass through the same OCI-runtime preparation seam, after production
digest admission but before materialization.

Contributor cold builds are now a named phase with elapsed-time and cache
feedback. Cargo output is quiet by default and available with `-v`. Intermediate
Cargo output is isolated by canonical worktree identity, so edits in one
checkout reuse dependency compilation without colliding with another checkout;
the installed guest binaries remain keyed by a complete source fingerprint, so
stale output cannot be selected.

## Validation

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `just check-gated`
- `cargo test -p mvm-build --features release-channel --lib official_build_does_not_detect`
- `cargo run -p xtask -- check-guest-binary-lists`
- project builder-VM realization of
  `nix/images/runtime-overlay#runtime-overlay` for `aarch64-linux`, with all
  six published OCI guest shims verified executable

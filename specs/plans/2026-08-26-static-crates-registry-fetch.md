# Static crates registry fetch

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS**

Issue #2904 blocks every source-built Rust derivation used by the builder VM:
the pinned Nix `importCargoLock` downloads through the crates.io API endpoint,
whose current user-agent policy rejects Nix's curl fetcher. The crate CDN serves
the same `/<crate>/<version>/download` path and remains content-addressed by the
checksums already committed in `Cargo.lock`.

## Delivery

- [x] Add one shared `cargoLock` helper that retains the committed lockfile and
      redirects the crates.io registry download base to `static.crates.io`.
- [x] Move every repository `buildRustPackage` derivation onto the helper,
      including the independently evaluated runtime-overlay flake.
- [x] Add a structural regression that rejects a new Rust Nix derivation which
      bypasses the helper or a helper which loses either registry endpoint.
- [x] Prove the focused regression, full Nix-structure test target, formatting,
      and Clippy are green.
- [ ] Merge the repair through the merge queue and confirm issue #2904 closes
      from the merged PR.

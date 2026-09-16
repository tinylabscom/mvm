# Nix hygiene: the version comes from the manifest, and the deferral gate reaches `nix/`

Backing: shipped-source
Validation: cargo run -p xtask -- check-deferrals

`nix/packages/mvmctl.nix` and `nix/packages/mvm-sdk-cdylib.nix` each wrote the
release version as a literal, kept in step only by a `sed` in `_release-prep`.
Both now read `workspace.package.version` from `Cargo.toml` through
`lib.importTOML`, from the same `mvmSrc` their vendored dependencies already
read `Cargo.lock` from, so the read adds no new evaluation input. The `sed` is
gone. `workspace_versioned_packages_read_the_version_from_the_manifest` in
`tests/nix_flake_structure.rs` fails if either recipe goes back to a literal.

The lockfile half of the issue was already done. Vendoring goes through
`nix/lib/static-crates-cargo-deps.nix`, which is nixpkgs' `importCargoLock` over
the committed `Cargo.lock` with fetches moved to the crates CDN. There was never
a `cargoHash`, and the lock has no non-registry sources, so no `outputHashes`
either. The two `[patch.crates-io]` entries are path dependencies under
`third_party/` and never appear as lock sources.

`check-deferrals` walked `crates/`, `xtask/` and root markdown only, which is
exactly where the residue had collected. It now also walks `src/`, every text
file under `nix/`, `install.sh` and the `Justfile`, using the shared
`fs_walk::walk_files` rather than its own recursion. Against the previous tree
it reported two things: five `(TODO)` lines in `nix/profiles/minimal.nix`, and
a `Justfile` recipe comment that named the markers without backticks. The
fixture's five lines were deleted — it runs no services and is never sealed, so
none of per-service uid, setpriv, seccomp, read-only `/etc` or dm-verity applies
to it — and the recipe comment now backticks the markers it names.
`a_marker_planted_under_every_root_is_reported` plants a marker under each root
and fails, naming every root it missed, when the new roots are removed.

`nix/lib/factories/README.md` now states the check/harness boundary. The ops
docs no longer send contributors to Lima or `mvmctl dev up`; `nix/ops/networking/`
was deleted, because it described host bridge and TAP setup in a crate path that
no longer exists, for workloads that no longer have a NIC.

None of the Nix edits was evaluated: `mvmctl` does not use host Nix and neither
did this change. They are verified structurally by the root tests that read
`nix/`, and the version expression is evaluation-equivalent by construction —
it yields the same string the literal did, so neither derivation changes.

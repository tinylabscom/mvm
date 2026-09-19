# The builder image key covers the source mvm-setpriv is compiled from

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -E 'test(/builder_vm_source_fingerprint|setpriv_source/)'

The builder-vm flake installs `mvm-setpriv`, which `nix/packages/mvm-setpriv.nix`
compiles from workspace source (`--package mvm-agentd --bin mvm-setpriv`)
against the workspace `Cargo.lock`. `builder_vm_source_fingerprint` hashed
neither, on the stated grounds that the only Rust in the image was the
embedded host binaries. That was not true of setpriv, so an edit to its source
or to a dependency it pulls in could reuse a stale cached builder image.

The fingerprint gains a fourth layer, derived rather than listed:

- every workspace crate `mvm-agentd` reaches through its manifests (today
  `mvm-agentd`, `mvm-core`, `mvm-contract`, and `mvm-http`, an optional
  `mvm-core` dependency counted because features are not resolved here),
  hashed whole except `tests/`,
  `benches/`, `examples/`, `fuzz/`, hidden entries and `target/`;
- the `Cargo.lock` entries of those crates' non-dev dependency closure, walked
  from each crate's lock entry but seeded only with names its manifest declares
  outside `[dev-dependencies]`, and any `[patch]` path crate the walk reaches;
- the root-manifest tables that change how that closure compiles:
  `[profile.release]`, `[patch]`, and the `[workspace.dependencies]` entries the
  closure declares.

The whole lockfile is still not hashed, so a dependency bump outside the
closure leaves the key alone. A tree without `mvm-agentd`, or a lockfile
missing an entry the closure needs, refuses rather than producing a key from
part of the inputs.

The crate graph and member hashing the build script already used for its
embedded-binary cache move to `crates/mvm-cli/src/workspace_graph.rs`, which
the build script includes by path, so the two keys share one definition of "a
crate's closure". Member hashing now covers the whole crate directory rather
than only `src/` and the manifest — `mvm-contract` compiles
`include_str!("../../data/…")` files that the old hash missed — and the build
script watches exactly the files it hashes.

Tests in `builder_vm_bootstrap_tests.rs` build a synthetic workspace and check
that an edit to `mvm-agentd`, a new file beside its `src/`, an edit to
`mvm-core`, a bump of a locked crate the closure reaches, and a release-profile
change each move the key, while a bump of a crate only an unrelated member
uses, an edit to that member, an `mvm-agentd` integration test, and an
unrelated workspace dependency do not. `setpriv_source` resolves the shipped
workspace in a test, so a lockfile shape the parser cannot follow fails there
first.

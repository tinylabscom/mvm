# The builder image keys name only what the image reads

Backing: shipped-source
Validation: cargo nextest run -p mvm-build -p mvm-cli -p mvm-setpriv -E 'test(/builder_key|mvm_inputs|source_closure|builder_vm_source_fingerprint/) | package(mvm-setpriv)'

Workstreams W9 and W10 of
`specs/plans/2026-09-24-builder-image-without-host-bins.md`. Both narrow a key
that moved on commits which cannot change the builder image.

## W9: `mvm-setpriv` is a leaf crate

The builder image compiles `mvm-setpriv` from source, so the Stage 0
fingerprint's fourth layer hashes that binary's crate closure. Built from
`mvm-agentd`, the closure was `mvm-agentd`, `mvm-core`, `mvm-contract` and
`mvm-http`. `crates/mvm-setpriv` now holds the binary and depends on `libc`
alone.

- `fd_hygiene` moved into the leaf whole; `mvm-agentd` re-exports it, so the
  code has one home. The capability numbers `guest_mount` retains are the
  leaf's constants.
- `nix/packages/mvm-setpriv.nix` builds `--package mvm-setpriv`. A test holds
  that flag to the package the key hashes and to a real `[[bin]]` of it.
- A test holds the shipped closure to the leaf and `libc`.
- The CRNG reseed integration test starts its helper through
  `mvm-setpriv-fixture`, an `mvm-agentd` test binary over the same
  `mvm_setpriv::run`. A test can only name binaries of its own package.

Over the 458 first-parent commits on `main` in the 28 days before 2026-09-25,
layer 4 would have moved on 107 (23%) under the old closure and on 2 under the
leaf. That count is path-level and leaves out `Cargo.lock`.

## W10: the pair's builder image is keyed on the mvm sources it reads

`LocalImageCacheKey` named the paired mvm checkout by commit and dirty state,
so every mvm commit rebuilt a pair-built builder image. The mvm side of the key
is now an `MvmSourceIdentity`:

- `Checkout` — the whole checkout. This is every role except the builder
  image.
- `ConsumedInputs` — the builder image. It is a digest of three things:
  - `BUILDER_FLAKE_NIX_INPUTS`, which now lives in
    `mvm_build::builder_image_inputs` and is the same list the Stage 0
    fingerprint uses;
  - the `mvm-setpriv` closure;
  - while the image checkout bakes host binaries, the `mvm-build` closure and
    `.cargo/config.toml`.

The closure hashing moved from `mvm-cli` to `mvm_build::source_closure` and
`mvm_build::workspace_graph` so both keys share it. `mvm-cli`'s build script
includes `workspace_graph.rs` by path from its new home.

Two guards stop the narrow key from serving a stale image:

- At key time, the image checkout's `images/builder-vm/image.nix` is scanned
  for reads of the mvm tree. If a read is outside the listed inputs, or no read
  is recognised, the key uses `Checkout` and logs why. A test also checks that
  every path `nix/flake.nix` names is listed.
- Lookup and publish re-derive the whole key. For a `ConsumedInputs` key, the
  mvm checkout that the set records is provenance only
  (`MvmCheckoutRule::Provenance` in `mvm_core::image_set`). The image checkout
  is still held exactly.

Over the same 458 commits, measured by path and leaving out `Cargo.lock`, the
pair key moved on all 458 before this change. It would have moved on 203
(44%) with the host binaries still baked. Once the image checkout stops baking
them (the plan's W7), it would move on 28 (6%).

Not verified here: a Nix build of the new recipe, which needs a builder VM,
and a live pair build.

# The SDK sidecar build named a flake nix would not copy whole

`mvmctl build sdk-sidecar build` could not build the sidecar on the HVF builder
path. It failed inside the builder sandbox with

```
error: path '/nix/images/runtime-overlay/flake.nix' does not exist
```

before compiling anything, for the shipped **glibc** sidecar — this was never
specific to the musl variant added alongside it.

## What was wrong

The builder-VM flake reaches out of its own directory to import the workspace's
runtime-overlay flake, resolving the workspace root as `../../..` when
`MVM_WORKSPACE_PATH` is unset. The build named the flake as

```
path:/work/nix/images/builder-vm#packages.<arch>-linux.sdk-sidecar-image
```

and `path:` copies exactly the tree it names into the store. So the relative
walk started at `/nix/store/<hash>-source/` and landed on `/nix` — a real
directory, which is why the error reads as a missing file rather than an escape.

## The fix

Name the whole staged workspace and select the flake inside it:

```
path:/work?dir=nix/images/builder-vm#packages.<arch>-linux.sdk-sidecar-image
```

Nix copies `/work` and evaluates the flake at the subdirectory, so `../../..`
resolves to the copied workspace root. Verified against nix 2.35 with a fixture
whose flake reads a marker file three levels up: the subdirectory form escapes
the copy, the `?dir=` form reads the marker.

This removes the need for an override rather than adding one. Pointing
`MVM_WORKSPACE_PATH` at `/work` also clears the error, but it aims the flake at
a mutable staged tree instead of an immutable store copy, and a build taken that
way failed differently (`E0761`, an ambiguous `audit` module that exists in
neither the checkout nor a fresh `/work` staging copy). That second failure is
unexplained and is *not* addressed here; the fix avoids the mutable path
entirely.

## Why it hid

There are two sidecar build paths and only one set the workspace root.
`stage0-init.rs` exports `MVM_WORKSPACE_PATH=/work`, so it took the env arm and
worked; the builder-VM shell job in
`crates/mvm-cli/src/commands/env/builder_vm/sdk_sidecar.rs` exports `HOME`,
`XDG_*` and `NIX_*` but never that one, so it took the broken relative arm.
Nothing detects the difference until a build reaches for a runtime-overlay
attribute.

The asymmetry is left in place: Stage 0's resolution is unchanged, since making
it share this reference form would make nix copy the whole workspace for every
Stage 0 build — a cost worth measuring before paying, and not needed to fix the
broken path.

## Test

`sidecar_flake_reference_copies_the_workspace_and_selects_the_subdirectory`
pins the reference form for both arches and rejects the subdirectory form by
name. It fails on the pre-fix string, and `cargo mutants` over the file catches
both mutants of the function it covers.

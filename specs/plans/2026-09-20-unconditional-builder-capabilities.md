# Make `mvm-build` builder capabilities unconditional

Backing: shipped-source
Validation: check-sprint-append

**Status: COMPLETE**

## Outcome

Remove the `mvm-build/builder-vm` and `mvm-build/pure-mkfs` composition switches.
Every in-tree VM-driving consumer already enabled both, the shipped closure does
not change, and the disabled arms were unreachable. Keep `mvm-cli`'s Linux
surface switches separate: they still control CLI commands and diagnostics,
while the lower-level library has one honest composition.

Native libkrun linkage remains opt-in in `libkrun-sys`; compiling the Rust
facade does not require a host libkrun installation. Runtime backend selection,
admission, and security behavior are unchanged.

## Workstreams

- [x] Add a no-default-features integration witness that imports and exercises
      the builder selector and Stage 0 host surface.
- [x] Remove the dead builder and pure-materializer cfg arms, compile-out
      refusals, and feature forwards from `mvm-build` and its consumers.
- [x] Preserve the distinct `mvm-cli` flags and Nix package surface, and add a
      repository gate that refuses either retired member feature.
- [x] Pass formatting, focused and workspace tests, Clippy, gated targets,
      repository gates, and BDD; publish the delivery record.
- [x] Pass protected head CI on PR #3550 and prepare the issue-closing change
      for protected merge-queue delivery.

## Validation

- `cargo test -p mvm-build --no-default-features --test unconditional_builder_surface`
- `cargo test -p mvm-build --no-default-features`
- `cargo test -p xtask --features man check_two_surfaces`
- `cargo check -p mvm-cli --no-default-features` with warnings denied
- full repository Definition of Done before the final checkbox moves

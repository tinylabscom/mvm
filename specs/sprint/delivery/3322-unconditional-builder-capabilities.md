# Unconditional builder capabilities (#3322)

`mvm-build` no longer advertises `builder-vm` or `pure-mkfs` as optional
composition switches. Every in-tree VM-driving consumer already enabled both,
so the change removes unreachable compile-out arms without changing the shipped
closure. The builder selector, Stage 0 host API, network helpers, libkrun Rust
facade, and pure ext4 materializer are now one honest library surface.

`mvm-cli` keeps its independent `builder-vm` and `pure-mkfs` switches because
they still control CLI commands and diagnostics. Native libkrun linkage also
remains opt-in inside `libkrun-sys`; making its Rust facade available does not
require a host libkrun installation.

## Regression witnesses

- `unconditional_builder_surface` imports and exercises the builder selector
  and Stage 0 result parser under `mvm-build --no-default-features`.
- `check-two-surfaces` rejects reintroduction of either retired `mvm-build`
  feature.
- The Nix structure witness pins the host package to explicit native-VMM
  linkage without forwarding the retired member feature.
- JSON CLI and workload-address witnesses now give their subprocesses private
  state roots, so earlier test binaries cannot leak audit setup into structured
  output.

## Validation

- `cargo test -p mvm-build --no-default-features`: green, including 1,107
  library tests and the new no-feature integration witness.
- `RUST_TEST_THREADS=1 cargo test --workspace` with a fresh `MVM_HOME`: green,
  including doctests.
- `just ci`: formatting, workspace/all-target Clippy, BDD-target Clippy, model
  gates, 14,672 nextest cases, and doctests green. Its BDD leg exposed the
  workload-address state-isolation defect; after that repair, the full BDD
  suite was rerun separately and passed.
- `just bdd` with a fresh `MVM_HOME`: 67 features; 257 scenarios (256 passed,
  one intentionally skipped); 988 steps (987 passed, one skipped).
- `just check-gated`: Linux all-target cross-check and the feature-gated
  conformance target green.
- `cargo run -p xtask -- check-all`: all 74 repository gates green.
- `cargo check --workspace`, `cargo fmt --all -- --check`, and the focused
  no-default-feature checks are green.
- Feature closure remains at its ratcheted budget of 482 crates.

The remaining delivery step is the protected merge queue; the PR closes #3322
when it lands.

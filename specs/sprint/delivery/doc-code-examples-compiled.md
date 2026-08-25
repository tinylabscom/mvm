# The documented Rust examples are compiled, not trusted

Backing: shipped-source
Validation: cargo test -p mvm-conformance --tests

The CLI gate that landed alongside this covered 421 shell blocks. It left 249
code blocks — 38% of everything the documentation prints — with no verification
at all. The strongest thing the repo had for a Rust snippet was a substring
check asserting the block contained the text `mkGuest`.

A Rust snippet is an API claim, and only a compiler settles an API claim. Grep
cannot: `mvm_client_local::LocalBackend` reads perfectly and names a crate that
has never existed on any branch.

## Mechanism

`crates/mvm-conformance/build.rs` extracts every ```rust block in the
documentation set into `$OUT_DIR`, and `tests/doc_rust_examples.rs` includes it.
`cargo check -p mvm-conformance --tests` then type-checks every example against
the real workspace crates. Nothing calls the generated functions; compiling *is*
the assertion, exactly as a doctest works.

Each generated function carries the doc's `file:line` in a comment directly
above it, so a failure names the line an author has to edit rather than an
offset into a generated file.

Two shapes are handled: a snippet defining `fn main` becomes a module (with
`main` renamed so it is not an entry point), and a statement snippet is wrapped
in an `async fn ... -> Result<(), Box<dyn Error>>` so `?` and `.await` are
legal — the same accommodation rustdoc makes.

`mvm-sdk` and the root `mvmctl` facade became dev-dependencies of
`mvm-conformance`, because the docs teach both and neither could otherwise be
linked. `mvmctl` is pulled with `default-features = false`.

## What the compiler found

None of these would have been caught by any string check:

- **`mvm_client_local` is not a crate.** `LocalBackend` is exported from
  `mvm_client`. Wrong in the Rust quickstart, the SDK reference, and a README
  comment.
- **`resources(1, 256)`** — the real signature takes `rootfs_size_mb` as a third
  argument.
- **`WorkloadBuilder::app` takes an `App`, not a closure.** The IR guide's
  builder example could never have compiled in the form it was written.
- **`println!("{}", m.id)`** — `MachineId` is a newtype over `String` and
  implements no `Display`. Wrong in both the README and the SDK reference, which
  is the shape of a snippet that was copied once and never run.
- **`fn main() -> Result<(), EmitError>`** wrapping `.build()?` — `build()`
  yields `BuildError`, and no conversion between the two exists.
- `mvm_runtime::vm::microvm::{DriveFile, FlakeRunConfig}` — there is no `vm::`
  segment, and `DriveFile` comes from `mvm-vmm`.
- `mvm_sdk::image::nix_packages` — `nix_packages` is re-exported at the crate
  root; there is no public `image` module.
- A JSON block in the hello-app example was an object member, not a document.

The config-secrets snippet additionally referenced three bindings that were
never defined, so it could not have compiled even with correct imports. It is
now a function taking them as parameters, which is both compilable and a
clearer statement of what the caller supplies.

## Red-first

The gate was verified to fail before being trusted: renaming
`LocalBackend::new` to `new_renamed` in the README fails the build citing
`README.md`'s own line, and restoring it returns to green. A compile gate that
has never been seen red is indistinguishable from one that compiles nothing.

## The opt-out has to say why

Six blocks are IR shape sketches carrying a literal `…`; they describe the
shape of `mvm_contract::ir` types rather than being code. They opt out with
```rust,ignore — and the BDD suite requires each to state a reason on its first
line (`// illustrative: …`). An unexplained opt-out is precisely how a wrong
example survives: the marker looks deliberate and nobody can tell whether it
still is.

## Residual risk, stated

Those six sketches are now exempt from the compiler. If `ir::Workload` gains or
renames a field, the sketches drift and nothing goes red. Closing that would
mean diffing the sketch's field names against the real type's serde names —
worth doing, not done here.

TOML and JSON blocks are checked for syntax only. Deserializing the
identifiable ones (`mvm.toml`, launch plan, Workload IR) into their real serde
types, where `deny_unknown_fields` would catch a stale key, is the obvious next
step and is also not done here.

Python and TypeScript examples — 103 blocks — remain unverified.

## Evidence

12 documented Rust examples compile; 38 TOML/JSON blocks parse. The BDD suite
goes from 206 to 208 scenarios and 198 to 200 passing, against the same 7
pre-existing failures (an unbuilt TypeScript SDK `dist/` and an absent codegen
binary) that `origin/main` also has.

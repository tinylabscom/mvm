# capture fixture: rust-hello

This tiny Rust binary is a deterministic project fixture for `mvm-capture`.
It represents the minimum conventional Cargo application that project capture
must recognize and resolve into a runnable workload.

## Who uses it

The capture CLI integration tests and `mvm-capture` fixture tests copy or
inspect this directory. It is not an example intended for publication, and no
production crate links it as a dependency.

## How it works

The manifest declares one dependency-free binary package. `src/main.rs` prints
a stable greeting, while the committed lockfile gives capture a realistic Cargo
project marker without introducing network access or dependency resolution.

Tests point at the fixture relative to the repository root, run capture, and
assert that Rust project detection and workload resolution identify the binary
correctly. Keeping the project deliberately small makes a failed assertion
about capture behavior easy to distinguish from fixture complexity.

## Running it directly

The fixture can be built or run independently when debugging a capture test:

```bash
cargo run --manifest-path tests/fixtures/capture/rust-hello/Cargo.toml
```

The expected output is `hello from captured rust project`.

## Maintenance

Keep the package dependency-free and avoid adding workspace inheritance. If a
test needs a more complex Rust layout, add a separate named fixture so this one
continues to prove the minimal case. Update capture assertions whenever an
intentional fixture change affects the discovered evidence.

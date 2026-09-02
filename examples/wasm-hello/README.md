# wasm-hello

`wasm-hello` is the smallest runnable WebAssembly workload example in the
repository. It demonstrates the file layout and configuration needed to run a
`wasm32-wasip1` program through mvm's WebAssembly backend.

## Who uses it

New users can copy this example when creating a WASI workload. The
`mvm-cli` integration tests use the committed fixture configuration and module
to verify `machine run --hypervisor wasm` behavior without compiling the
example during the test.

## How it works

The Rust program prints `hello from wasm` and exits. A release build targets
`wasm32-wasip1`, producing `target/wasm32-wasip1/release/wasm-hello.wasm`.
The adjacent `mvm.toml` names that module and selects the development profile.

The `fixture/` directory contains a prebuilt module and matching configuration
for deterministic CLI tests. Source changes do not automatically update that
fixture; regenerate and commit it deliberately when the expected workload
changes.

## Build and run

Install the WASI target, build the module, and invoke the explicit wasm backend:

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
mvmctl machine run --hypervisor wasm
```

The wasm backend runs under host `wasmtime`; it does not boot a Linux microVM
or require KVM. The command should print the greeting and return successfully.

## Workspace relationship

This example declares an empty `[workspace]` and is intentionally independent
of the root workspace. That keeps its example-specific release profile and
target build from affecting normal workspace commands.

# mvm-runtime backend fuzz target

This standalone fuzz package exercises the virtio-vsock transport's queue and
descriptor validation in `mvm-runtime`. A guest controls the relevant register
programming and descriptor memory, so the backend must treat every value as
untrusted.

## Who uses it

Runtime and security contributors use this harness when changing virtqueue
geometry, guest-memory access, descriptor walking, or vsock transport state.
Security CI compiles it when fuzz surfaces change. It is not included in a
runtime artifact.

## How it works

`fuzz_virtqueue_geometry` derives a simulated RAM image and a sequence of
register operations from arbitrary input. It drives the same validation and
descriptor traversal code used by the backend, including zero, truncated,
cyclic, oversized, and inconsistent queue configurations.

The invariant is that hostile guest state cannot cause a panic, division by
zero, out-of-bounds memory access, or unbounded descriptor traversal. Invalid
queues are expected to be rejected before the transport consumes them.

## Running it

From this directory, install `cargo-fuzz` and run:

```bash
cargo +nightly fuzz run fuzz_virtqueue_geometry
```

Use `-- -max_total_time=300` for a bounded local smoke run. Convert minimized
findings into focused `mvm-runtime` regression tests as well as corpus inputs.

## Workspace relationship

This crate is excluded from the root workspace and declares an empty local
`[workspace]`. It also repeats the repository's vendored `arrayref` patch
because standalone Cargo graphs do not inherit root workspace patches.

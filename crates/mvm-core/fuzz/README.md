# mvm-core fuzz targets

This standalone `cargo-fuzz` package tests the snapshot-frame parser in
`mvm-core`. Snapshot bytes can come from persisted or transferred state, so the
parser must reject malformed headers and section tables before allocating or
indexing from attacker-controlled values.

## Who uses it

Contributors changing snapshot framing, section bounds, or compatibility logic
run this harness. The security workflow compiles fuzz crates when their inputs
change. This package is test infrastructure only and is never included in an
mvm release artifact.

## How it works

`fuzz_snapshot_frame` passes arbitrary byte slices through the production
snapshot header and section parsing path. It explores truncated frames,
unknown values, extreme counts and lengths, overlapping sections, and otherwise
inconsistent layouts.

The target's primary invariant is that every byte string yields a bounded
`Result` and never panics. Valid frames may parse successfully; malformed frames
must fail without allocating from an unchecked length or reading outside the
provided buffer.

## Running it

Install `cargo-fuzz`, then run from this directory:

```bash
cargo +nightly fuzz run fuzz_snapshot_frame
```

For a short local pass, append `-- -max_total_time=300`. If libFuzzer writes a
crashing artifact, pass that file to the same command to reproduce it before
adding a focused regression test to `mvm-core`.

## Workspace relationship

The root manifest excludes this crate, and its own manifest contains an empty
`[workspace]`. That separation is required because `libfuzzer-sys` links only
through the sanitizer and linker wrapper provided by `cargo-fuzz`.

# arrayref

This directory contains the reviewed source of the upstream `arrayref` crate.
It provides macros for borrowing fixed-size array references and groups of
adjacent array references from slices without copying their contents.

## Who uses it

Several transitive dependencies in mvm's Cargo graphs require `arrayref`. The
root `[patch.crates-io]` entry, plus matching patches in standalone fuzz crates,
forces those graphs to use this vendored source because established registry
releases were yanked. Product code should continue depending on its normal
crate graph rather than importing this directory directly.

## How it works

The macro implementations validate slice bounds and then reinterpret the
selected region as a reference to an array of the requested compile-time size.
The public surface includes immutable and mutable single-array macros, macros
for splitting a slice into several array references, and convenience variants
for extracting arrays at offsets.

Because the result borrows the original slice, no allocation or element copy is
needed. The implementation's unsafe conversions rely on the macros' preceding
bounds checks and on the array length encoded in the destination type.

## Provenance

[`ORIGIN.toml`](ORIGIN.toml) pins the upstream repository and reviewed revision
and records hashes for the manifest, license, and source file. The supply-chain
tests verify both those hashes and that every affected Cargo graph resolves the
vendored package.

Do not modify vendored code casually. Any source update must come from a
reviewed upstream revision, preserve the BSD-2-Clause license, update the origin
hashes, and pass the supply-chain dependency-pin tests.

## Validation

Run its own tests directly with:

```bash
cargo test --manifest-path third_party/arrayref/Cargo.toml
```

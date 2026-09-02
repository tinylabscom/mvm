# am-fs-ext4

This directory vendors `am-fs-ext4` 0.4.0, a pure-Rust ext4 filesystem reader,
writer, verifier, formatter, and C ABI. mvm carries it as a narrowly patched
third-party crate rather than as project-owned application code.

## Who uses it

`mvm-fs` uses this crate only as an independent development and test oracle for
images produced by its own ext4 writer. Tests read generated images through
`am-fs-ext4` so they do not validate the writer solely with its own parser. The
root Cargo patch redirects the crates.io dependency to this reviewed source.

External users of the upstream package may also build its `mkfs_ext4` binary or
link its Rust/C interfaces, but those are not part of mvm's shipped runtime.

## How it works

The library implements ext4 superblocks, block groups, inodes, directories,
extents, journals, extended attributes, checksums, allocation, verification,
and filesystem construction over a block-device abstraction. It exposes:

- an `rlib` for Rust callers;
- a `staticlib` and `fs_ext4_*` functions for C-compatible callers; and
- the `mkfs_ext4` command for standalone filesystem formatting.

The code is cross-platform because it operates on block-device data rather
than mounting filesystems through host kernel APIs.

## Local patch and provenance

[`MVM-PROVENANCE.md`](MVM-PROVENANCE.md) records the upstream source and the
single mvm-carried compatibility change. That change initializes a C character
buffer with `c_char`, allowing compilation on targets where C `char` is
unsigned while preserving the declared ABI.

Do not make unrelated edits here. Prefer upstream fixes, update provenance for
every carried change, and remove the root patch when an equivalent upstream
release is adopted.

## Validation

Run the crate's tests explicitly with:

```bash
cargo test --manifest-path third_party/am-fs-ext4/Cargo.toml
```

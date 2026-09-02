# mvm-fs ext4 fuzz target

This standalone fuzz crate exercises the pure-Rust ext4 image writer provided
by `mvm-fs`. It turns generated file trees and filesystem parameters into ext4
images while checking that hostile shapes cannot make image construction panic
or violate its structural bounds.

## Who uses it

Contributors working on `mvm-fs::ext4`, image layout, directory construction,
or metadata encoding use this target. Security CI compiles the crate when fuzz
surfaces change. It is development-only and is not linked into shipped mvm
binaries.

## How it works

`fuzz_build_image` uses `arbitrary` to derive structured image-building input
from libFuzzer's byte stream. The harness calls the same `build_image` path used
by normal filesystem materialization and checks the writer's never-panic and
structural invariants.

Generated cases cover empty and nested trees, unusual names and contents, and
boundary-sized metadata. Invalid or unsupported requests may return errors;
they must not trigger unchecked arithmetic, out-of-bounds access, or unbounded
allocation.

## Running it

Run the target from this directory with nightly Rust:

```bash
cargo +nightly fuzz run fuzz_build_image
```

Append `-- -max_total_time=300` for a bounded smoke run. A minimized finding
should also become a focused unit or integration regression test in `mvm-fs`.

## Workspace relationship

This manifest is excluded from the root workspace and declares an empty local
`[workspace]`. `cargo-fuzz` supplies sanitizer-specific linker flags required
by `libfuzzer-sys`, so the target cannot participate in an ordinary workspace
build.

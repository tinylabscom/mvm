# libkrun-sys fuzz targets

This standalone `cargo-fuzz` crate exercises the configuration parsers used by
the libkrun supervisor boundary. Its purpose is to prove that arbitrary bytes
received through the supervisor's JSON and control-message inputs are rejected
cleanly rather than causing a panic or reaching libkrun with invalid state.

## Who uses it

Security contributors run these targets when changing `libkrun-sys` parsing or
supervisor startup. The repository's fuzz validation also compiles this crate
when its directory changes. It is testing infrastructure only: it is not
linked into `mvmctl`, a supervisor binary, or a published library.

## How it works

The crate depends on the parent `libkrun-sys` package with default features
disabled. That exposes the pure parsing paths without linking the native
libkrun and libkrunfw libraries into the fuzz runner.

Two libFuzzer entry points are defined:

- `fuzz_supervisor_config` feeds arbitrary JSON to `SupervisorConfig` parsing,
  covering the configuration read from supervisor standard input.
- `fuzz_attach_message` feeds arbitrary bytes to the attach-control decoder,
  covering the same-user Unix-socket message accepted after prelaunch.

Neither target asserts that random input is valid. Their invariant is that all
input produces a bounded success or error result without panicking.

## Running it

Install `cargo-fuzz`, then run a target from this directory:

```bash
cargo +nightly fuzz run fuzz_supervisor_config
cargo +nightly fuzz run fuzz_attach_message
```

Use `-- -max_total_time=300` for a bounded five-minute local run. Reproduce a
saved failure by passing its artifact path after the target name.

## Workspace relationship

This package has its own empty `[workspace]` table and is excluded from the
root workspace. `libfuzzer-sys` requires the sanitizer and linker setup supplied
by `cargo-fuzz`, so normal workspace builds must not try to link it.

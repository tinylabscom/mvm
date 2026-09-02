# mvm-http fuzz target

This standalone fuzz crate hardens the byte-level HTTP response parser in
`mvm-http`. It covers the response head and chunked-transfer framing—the full
surface controlled by an HTTP server before higher-level code sees a response.

## Who uses it

Contributors changing status-line parsing, headers, body framing, redirect
handling, or chunk decoding use this harness. Security CI compiles fuzz crates
when they change. It is not linked into any shipped binary.

## How it works

`fuzz_response_parse` feeds arbitrary bytes to the same pure parsing functions
used by the production client. The committed corpus includes representative
fixed-length, chunked, redirect, no-content, trailer, and conflicting-framing
responses so mutation starts near security-relevant branches.

The parser may accept a complete valid response, request more input, or reject
the bytes. It must never panic, allocate from an unchecked peer-controlled
length, or accept ambiguous framing such as conflicting content-length and
transfer-encoding metadata.

## Running it

Run the target from this directory using nightly Rust:

```bash
cargo +nightly fuzz run fuzz_response_parse
```

Append `-- -max_total_time=300` for a bounded pass, or `-- -runs=0` to replay
the committed corpus without generating new mutations.

## Workspace relationship

The crate is excluded from the root workspace and has an empty `[workspace]`
table of its own. `libfuzzer-sys` requires the linker and sanitizer setup from
`cargo-fuzz`, which is intentionally absent from normal workspace builds.

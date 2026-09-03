# mvm-contract fuzz targets

This standalone fuzz crate hardens the network-flow wire contract shared by
the mvm host and guest. It drives both individual frame decoding and sequences
of frames through the state machine that enforces stream and session rules.

## Who uses it

Contributors changing `mvm-contract` networking types, framing, or FlowMux
state transitions use these targets to explore malformed and adversarial
inputs. Security CI compiles the harness when fuzz surfaces change. The crate
is never shipped and is not a dependency of a product binary.

## How it works

The harnesses call the same `mvm-contract` code used at the host/guest boundary:

- `fuzz_network_flow_decode` treats the input as an encoded network-flow frame
  and exercises length, tag, and payload validation.
- `fuzz_network_flow_state` interprets input as a sequence of operations and
  drives the session/stream state machine through ordering and lifecycle edge
  cases.

Random input is expected to be rejected frequently. A finding is a panic,
unbounded behavior, or an invalid transition being accepted—not an ordinary
parse error.

## Running it

From this directory, run either target with nightly Rust and `cargo-fuzz`:

```bash
cargo +nightly fuzz run fuzz_network_flow_decode
cargo +nightly fuzz run fuzz_network_flow_state
```

A bounded smoke run can append `-- -max_total_time=300`. Keep useful regression
inputs in the matching corpus directory when they reach a previously uncovered
branch.

## Workspace relationship

The package is excluded from the main workspace and declares its own empty
`[workspace]`. This keeps `libfuzzer-sys` out of ordinary builds, where the
sanitizer-aware linker configuration supplied by `cargo-fuzz` is unavailable.

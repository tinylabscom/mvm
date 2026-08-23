# mvm-agentd fuzz targets

`cargo-fuzz` harnesses for the host↔guest JSON protocol surface, per
ADR-001 §W4.2.

## Targets

| target                       | input                                                  | reason                                                                    |
| ---------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------- |
| `fuzz_guest_request`         | `GuestRequest` JSON frame                              | every host→guest RPC lands here                                           |
| `fuzz_sealed_frame`          | `SealedFrame::decode`, the control pre-auth ingress    | runs *before* signature verification                                      |
| `fuzz_entrypoint_event`      | `EntrypointEvent` JSON (host-side stream)              | host's first parser surface for `RunEntrypoint` response frames           |
| `fuzz_authed_path`           | (scenario × payload) pair, signed in-process           | drives `verify_authenticated_frame` past sig check; ensures tampered frames never reach inner deserializer |

## Running locally

```bash
# one-time install
cargo install cargo-fuzz

# run for 5 minutes
cd crates/mvm-agentd
cargo +nightly fuzz run fuzz_guest_request -- -max_total_time=300

# run for an hour, single-thread (matches CI cadence)
cargo +nightly fuzz run fuzz_guest_request -- -max_total_time=3600 -workers=1

# replay corpus only (no new inputs)
cargo +nightly fuzz run fuzz_guest_request -- -runs=0
```

The corpus under `corpus/<target>/` is committed; new findings are
written next to the seeds and should be added to the repo if they
exercise a previously uncovered branch.

## Workspace exclusion

`crates/mvm-agentd/fuzz` is in the root `Cargo.toml`'s `workspace.exclude`
list. `libfuzzer-sys` only links cleanly when invoked through the
cargo-fuzz wrapper, so a plain `cargo build --workspace` would otherwise
fail.

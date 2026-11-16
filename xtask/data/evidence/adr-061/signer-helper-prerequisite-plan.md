# P2: lower the neutral signer-helper client

Backing: preview
Validation: none

Immutable implementation plan for [#5510](https://github.com/tinylabscom/mvm/issues/5510),
inheriting accepted [ADR-061](../../../../specs/adrs/061-crate-layout-by-where-code-runs.md).
Source pin: `8f3803b5c81240641c169d956a172d8dc474db72`.
P1 landed in [#5595](https://github.com/tinylabscom/mvm/pull/5595).
The owner authorized planning and implementation after scoped review, not
publication or landing. Execution results belong in the issue and implementation
report, not amendments to this planning snapshot.

## Goal and scope

As a maintainer extracting host roles, I want the existing signer-helper client
below those roles so host signing and broker clients do not depend on audit
implementation merely to reach the same resident signer process.

Move the complete client into core's optional Unix transport surface. Preserve
the hostd module path by re-export, with no wrapper or duplicate implementation.
The client includes synchronous request transport and asynchronous telemetry
authentication; both move together to preserve inherent methods and private fields.

No process, server, key, config, protocol, admission or authority move. In
particular, combined helper composition and its config default remain for the
later composition slice. No new retry, deadline, response-correlation rule,
error redaction, sender cap, dependency version or default feature. Preserve
the synchronous path's existing behavior rather than silently giving it the
telemetry path's stricter validation.

## Source and consumers

Read the full `crates/mvm-hostd/src/audit_signer/helper_client.rs`, its parent
module, `crates/mvm-core/src/lib.rs`, both crate manifests and workspace Tokio
selection before moving. Core already owns the protocol types, telemetry
transcript validation, signature types and framing. Workspace Tokio currently
selects net, time, sync and multi-thread runtime; no dependency addition is needed.

Preserve imports in these existing consumers:

- `crates/mvm-hostd/src/bin/mvm-host-signer.rs`
- `crates/mvm-hostd/src/host_signer/server.rs`
- `crates/mvm-hostd/src/broker/daemon.rs`
- `crates/mvm-hostd/src/telemetry_collector/mod.rs`
- `crates/mvm-hostd/tests/telemetry_signer.rs`

Refresh callers before execution. No external-library research is needed:
the versions, APIs and behavior are unchanged.

## Contract and implementation sequence

1. Run existing helper-client unit tests and telemetry-signer integration tests
   before relocation. These cover successful signing, missing sockets, helper
   refusal, valid encrypted telemetry, stalled signer deadline/socket cleanup,
   invalid deadlines and confused correlations/keys/algorithms/signatures.
2. Move the complete source and tests to `crates/mvm-core/src/signer_helper.rs`.
   Replace self-crate `mvm_core` paths with `crate`; preserve all executable
   statements otherwise. Expose the module with
   `cfg(all(unix, feature = "hostd-transport"))`. The new public module is
   Unix-only; generic framing remains transport-feature-only and portable.
3. Replace hostd's helper-client module declaration with
   `pub use mvm_core::signer_helper as helper_client`. Hostd already opts into
   transport after P1. Do not introduce Windows support or weaken existing
   Unix availability. Update the transport feature's explanatory comment to
   reflect the client as well as framing; defaults remain empty.
4. Add a Unix integration test using both public type paths, with compile-time
   assignment proving type identity. Exercise an actual bounded helper exchange
   through the facade, including caller-selected cap rejection. Leave telemetry
   integration coverage at hostd to exercise the production facade and server.
5. Compare relocated production statements to the pin after normalizing only
   crate-path imports and comments. Verify no reverse core-to-hostd dependency,
   no lockfile changes and no optional transport activation in guest defaults.
6. Run the checks below and obtain a fresh implementation review. Record exact
   failures/environment corrections; no blanket gate waiver or live claim.

## Lifecycle and security boundary

The trusted host's existing helper remains the key owner. A client owns only
its socket and request. Synchronous calls connect, write, read and drop the
socket with existing error context; no new deadline is introduced. Telemetry
validates the transcript, connects, writes, reads and verifies the response
under one existing deadline. Timeout/cancellation drops its exclusively owned
socket; no background task, retry or key transfer is introduced.

This relocation does not extend shipped backend guarantees or protect against
a compromised active host. UDS fixtures are library evidence, not live VM or
hardware witnesses.

## Validation

Use the worktree environment and cached Cargo home. Invocation-local
`TMPDIR=/tmp` avoids the already-observed macOS UDS path-length limit.

```sh
# Before move
just tests::scoped mvm-hostd audit_signer::helper_client --lib
just tests::scoped mvm-hostd '' --test telemetry_signer

# After move
cargo fmt --all -- --check
cargo check -p mvm-core --no-default-features --lib
cargo check -p mvm-core --no-default-features --features hostd-transport --lib
just tests::scoped mvm-core signer_helper::tests --lib --no-default-features --features hostd-transport
just tests::scoped mvm-hostd '' --test signer_helper_compat
just tests::scoped mvm-hostd '' --test telemetry_signer
just tests::scoped mvm-hostd host_signer --lib
just tests::scoped mvm-hostd broker --lib
cargo run -p xtask -- check-core-runtime-free
cargo run -p xtask -- check-guest-agent-runtime-free
cargo run -p xtask -- check-sdk-transport-free
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
just check::gated
cargo run -p xtask -- check-all
```

## Acceptance

- One client implementation with compatible type identity and all methods.
- Unchanged synchronous wire/error/cap behavior and telemetry verification,
  deadline and cancellation behavior.
- Unix plus explicit transport gating, with default core and guest closures
  remaining runtime-free.
- Existing callers compile unchanged and selected tests and repository gates pass.
- No process/key/server/config/lockfile changes; review confirms the bounded cut.

No unresolved owner design choice is known. Complexity is low for the move,
moderate for compatibility validation. Keep the existing client whole instead
of introducing traits or splitting telemetry into a foreign inherent impl.

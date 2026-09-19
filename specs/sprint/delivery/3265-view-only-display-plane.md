# View-only workload display plane

Issue #3265 delivers P0 of
`specs/plans/2026-09-15-workload-display-plane.md`. A signed plan may grant
`host.display.view.v1`; without that grant, the display socket is neither
projected into the workload spec nor followed by the host stream plane.

## What shipped

- `mvm-contract` owns a bounded, versioned binary `DisplayFrame` contract, its
  image encoding, step identity, domain-separated digest, and the dedicated
  guest-to-host port. The plan projection exposes that port only as
  `GuestDials`.
- The runtime overlay includes `mvm-display-bridge`. It constructs the small
  fixed CDP method set itself, accepts only `Page.screencastFrame` events, and
  sends bounded JPEG frames hostward. Host bytes never become CDP commands.
- `DisplaySource` owns the single mode-`0600` Unix socket listener and feeds
  frames into the existing stream broker. Frame records use the same encrypted
  retention and hash chain as the other stream sources; the broker also keeps
  the first digest observed for each agent step.
- `mvmctl machine display <name>` opens a frame-only stream and serves the
  latest images from an ephemeral `127.0.0.1` listener. A random one-shot token
  authorizes exactly one viewer request.
- HVF cold boot, handoff, restore, standby, Firecracker, QEMU and libkrun all
  receive the same typed display-socket projection. No display device or guest
  network listener was added.

## Security boundary

This work creates no host-to-guest display route. The shared grant witness
proves that `display.view` does not grant operator input, and the loopback
witness exercises the real viewer bind. Frame bodies, CDP messages and step
identifiers are bounded before untrusted lengths can drive allocation. Raw CDP
passthrough is unrepresentable at the encoder: it accepts a private fixed-method
enum rather than a string. Compressed image bytes deliberately bypass the text
redactor, while their digests and metadata remain chain-bound.

`check-single-display-path` enforces one host listener, one spec channel, one
guest bridge dial, no guest listener, no source-side writes, no non-loopback
viewer bind, and no second frame transport.

## Validation

- `cargo test --workspace` (including integration tests and doctests)
- `cargo clippy --workspace -- -D warnings`
- `cargo check --workspace`
- `just check-gated`
- `cargo fmt --all -- --check`
- `cargo run -p xtask -- check-all`
- Focused display contract, bridge, stream broker/source/plane, CLI and audit
  posture tests

The browser or compositor remains responsible for launching the packaged
bridge against its local debugging pipe. OAuth brokering and any attended input
path are explicitly outside P0 and remain unchecked in the plan.

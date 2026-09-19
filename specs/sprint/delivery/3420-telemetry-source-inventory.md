# Telemetry source inventory beyond binaries, and the witness-ledger model

Issue #3420, W1b of `2026-09-17-host-mediated-telemetry`; epic #3419 remains open.

`specs/telemetry/sources.toml`, validated by the extended offline
`check-telemetry-inventory` gate, registers four source classes the binary
inventory could not see:

- 12 Rust subscriber/global-diagnostic initialization sites, with a
  fail-closed scan over non-test workspace sources: a new install of a
  subscriber, logger, or panic hook fails the gate until classified. Regions
  after `#[cfg(test)]` and test/fuzz/bench/example directories are exempt; the
  gate exempts its own file, which names the patterns literally.
- 12 script sources: all four `nix/wrappers/` dispatch scripts, the SDK
  host-driver modules that write to stderr/warnings, and the two `_hostsvc`
  broker-call chokepoints (registered although they emit nothing today —
  silent transport failure is the recorded gap). New wrapper files and newly
  emitting SDK modules fail the gate until classified.
- 20 launcher-to-producer edges covering all 18 guest/builder runtime gaps in
  `binaries.toml`, each with an activation policy (`always`, `conditional` +
  named condition, `on-demand`, `mediated`, `legacy`, `seed`, `unwired`).
  Producer references are checked against the binary inventory both ways.
- 8 backend telemetry-endpoint anchors: the shared vsock-port map and
  host-dial allow-list, the four VMM drivers, apple-container's inherited hvf
  seam, and a wasm row recording that no vsock endpoint exists there.

The startup-witness model is `WitnessLedger` in `mvm-core`'s telemetry
protocol module: activation-aware expectations, bounded unexpected-producer
tracking, and deterministic findings (missing, degraded, unavailable,
unexpected). An unlaunched conditional producer is not a missing producer; a
clean stop is state, not a finding. Nothing constructs the ledger at runtime —
collector integration is W4 — and neither the inventory nor the model
certifies capture, delivery, or nonblocking behavior.

## Findings recorded, not fixed here

- The Nix runtime-overlay flake stages `display-bridge` but not `ping`
  (`nix/images/runtime-overlay/flake.nix`), while the Rust overlay builder
  stages `ping` but not `display-bridge`
  (`crates/mvm-build/src/runtime_overlay.rs`), so `/bin/ping` mediated-tool
  substitution silently no-ops on a Nix-built overlay
  (`mount_mediated_tools` skips absent sources).
- `mvm-addon-vsock-bridge` is built by no current image or launcher; its edge
  is classified `unwired` and anchors its Cargo declaration.
- The `mvm::audit` mirror events (`mvm-hostd` supervisor audit mirror) have no
  matching layer in any subscriber stack; they are visible only under an
  explicit `RUST_LOG=mvm::audit=info`.
- `mvm-extension-provider` and `mvm-libkrun-supervisor` install the panic hook
  but no subscriber; `mvm-hostlib` and `mvm-mcp` link tracing-emitting crates
  with no subscriber path at all. These stay classified as runtime gaps in the
  inventories rather than being wired here.

## Validation

- 17 focused `check-telemetry-sources` tests pass (fixture drift matrix plus
  the live workspace run), alongside the 17 existing inventory tests.
- 7 focused `WitnessLedger` tests pass, including serde roundtrip,
  activation-awareness, boundedness at the producer cap, and refusal paths.
- The live gate classifies 29 runtime-gap and 19 non-runtime binaries, 12
  subscriber init sites, 12 script sources, 20 launch edges and 8 backend
  endpoints, and states that runtime coverage is not certified.
- `cargo fmt --all -- --check` passes. Workspace clippy (`just clippy`,
  pinned 1.97.1, warnings denied) passes.
- Affected-crate run: 2,902 tests pass (`cargo nextest run -p xtask -p
  mvm-core`, 3 skipped).
- Full host workspace after rebasing onto current main: 14,443 tests pass,
  zero failures, 27 skipped (`just test`, nextest 0.9.143). The pre-rebase
  tree also passed in full (14,436). Two intermediate full runs failed only
  in `mvm-hostd::host_agent_restart` under heavy machine load; the same
  tests pass five-of-five in isolation and in the quiet-machine full run,
  and no `mvm-hostd` file differed between the failing and passing trees.
  Recorded as a load flake, not a regression.
- Pinned-toolchain doctests pass (`just test-doc`).
- All 72 `check-all` repository gates pass before and after the rebase,
  including the extended telemetry gate. `just check-gated` (Linux
  all-target cross-check via cargo-zigbuild plus the BDD feature target)
  passes on the rebased tree.

This slice changes no runtime, transport, subscriber, VM launch or export
behavior. It does not prove nonblocking emission, loss accounting, early-boot
coverage or detached collection, and no startup witness is checked at runtime.
Remaining W1: the executable outside-span/detached/capture conformance harness
and hardware-qualified baseline measurements. W2–W7 remain open. Do not close
#3420 or #3419 on this delivery alone.

# ADR 070 - Browser-reachable surface: verify, don't virtualize

**Status**: Accepted
**Date**: 2026-06-03
**Cross-refs**: ADR-002 (security posture — the signed/audited artifacts this verifies), ADR-041 (signed, audited execution plans — claim 8), ADR-014 (VmBackend single trait — the seam a wasm backend would *not* fit), Plan 33 (hosted MCP transport — mvm owns protocol, mvmd owns transport). Input: a comparison against a sibling browser-VM project that boots Linux in the browser via a RISC-V→wasm emulator.

## Context

A sibling browser-VM project runs full environments **in the browser**: a RISC-V RV64GC interpreter compiled to `wasm32`, booting an unmodified kernel, with a WebSocket relay for egress. The natural question for mvm was "should we grow an analogous browser capability?"

The answer turns on one distinction that is easy to miss. That project **emulates** a CPU; mvm **virtualizes** on real hardware (Firecracker/libkrun/Vz over KVM/HVF). You can ship a CPU emulator as wasm and run it in a tab. You **cannot** run KVM in a tab. So the headline browser-emulator capability — "boot the workload in the browser, serverless" — has no path into mvm's runtime model, and a `wasm`/emulator `VmBackend` is the wrong shape for the `VmBackend` trait (kernel path, ext4 rootfs, TAP, pause/resume, vsock — nearly all N/A; ADR-014). That dead end should be recorded so it is not relitigated.

What *does* transfer is the part underneath the emulator: **content-addressed, self-verifying artifacts that any peer can check by re-derivation, with no server to trust** (its Law L5 — `verify_kappa()`). mvm already produces exactly such artifacts — signed `ExecutionPlan`s, content-addressed bundles, and a chain-signed audit log (claims 8/9/14). Those are verifiable from bytes alone. That is the idea that maps cleanly onto mvm's strengths.

## Decision

1. **mvm will not pursue "run microVMs in the browser."** It is incompatible with hardware virtualization. No wasm/emulator backend.

2. **mvm grows a serverless, in-browser *verification* surface for its signed artifacts.** The first instantiation ships now: an audit-log verifier. `crates/mvm-verify` is a dependency-light, wasm-clean leaf crate that re-implements `mvm_supervisor::verify_audit_chain` against an in-memory `&str` + an Ed25519 public key; `web/audit-verify/` is a `#[wasm_bindgen]` shim + a static page. An operator drops a downloaded `<tenant>.jsonl` and the host signer's public key into a tab and gets a verdict — no host, no backend, nothing leaves the page.

3. **Verification cores must be wasm-clean leaf crates.** The browser surface may depend only on crates that compile to `wasm32-unknown-unknown` — no tokio/libc/rustix, no `mvm-supervisor`/`mvm-core` in the graph. `mvm-verify` depends only on `ed25519-dalek`, `sha2`, `base64`, `serde`, `serde_json`. Byte-exact parity with the native verifier is **pinned by a cross-crate test** (`mvm-supervisor`'s `mvm_verify_matches_supervisor_chain`): if the audit entry's serde shape drifts, CI fails there, not silently in the browser.

4. **The wasm artifact stays out of the main workspace.** `web/audit-verify/` is excluded from the Cargo workspace so `wasm-bindgen` and the `wasm32` target never enter `cargo build --workspace` or CI. Its logic is tested via the in-workspace `mvm-verify` crate; the page is built with `wasm-pack` (see `web/audit-verify/README.md`).

5. **Remote console/control stays in mvmd, not mvm.** A browser-reachable *console* (driving a live microVM remotely) is realistic — mvm's PTY-over-vsock console is a raw byte stream and `mvm-mcp` is already transport-agnostic — but the HTTP/WebSocket transport + tenant auth is fleet-orchestration territory, reserved for mvmd by Plan 33. mvm's obligation is only to keep the console byte-stream and the `mvm-mcp` protocol cleanly bridgeable, which they already are. This ADR does not add any host-side remote surface to mvm.

## Consequences

- A new, small, fully-tested crate (`mvm-verify`) that is independently useful: any Rust caller (CLI, mvmd, a future `mvmctl audit verify --stdin`) can verify a chain from bytes without the supervisor's heavy dependency graph.
- A serverless transparency tool: third parties can audit mvm's claim-8 log without running mvm or trusting a server — the strongest form of the "verify by re-derivation" property, applied to mvm's actual artifacts.
- The browser tool's correctness is guarded by a test in the security-critical crate, so the duplication (a mirrored `AuditEntry`) is drift-proof rather than hope-based.

### Follow-ups

- [ ] `mvmctl audit pubkey` — print the host signer's Ed25519 public key as hex, so operators have a first-class way to feed the verifier (today they must derive it from the keypair).
- [ ] Extend the verifier to **plan/bundle inspection** (`mvm_plan::verify_plan`, `read_and_verify_bundle` are already byte-oriented) — but only once `mvm-plan`'s graph is confirmed wasm-clean (it currently pulls `mvm-core`, which is not). May require lifting the pure verify path into a leaf crate, mirroring this ADR's pattern.
- [ ] If a hosted browser **console** is ever wanted, it is an mvmd effort (Plan 33), not mvm.

## Alternatives considered

- **A wasm/emulator `VmBackend`.** Rejected: wrong shape for the trait, and it would mean shipping a CPU emulator — a different product, not a backend.
- **Depend on `mvm-supervisor`/`mvm-plan` from the wasm crate.** Rejected: their graphs pull tokio/libc/rustix and do not compile to `wasm32`. Hence the leaf-crate rule (decision 3).
- **Re-derive the signed bytes via `serde_json::Value`.** Rejected: `Value` re-serializes object keys sorted, but the audit entry is signed in struct-declaration order, so a round-trip through `Value` would reorder keys and break every signature. `mvm-verify` mirrors the struct's field order and `skip_serializing_if` attributes instead, reproducing the signed bytes exactly.

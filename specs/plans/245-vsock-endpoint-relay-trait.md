# Plan 245 — Vsock Endpoint Relay Trait

> **For agentic workers:** keep the checkboxes current. The last unchecked item is the current blocker.

**Status:** COMPLETE

**Goal:** Refactor the HVF vsock egress/broker bridge so backend-specific code depends on one small transport/relay trait rather than concrete UDS relay method names, without moving any egress policy, HTTP proxying, TLS, or host-client behavior out of `mvm-hostd`.

**Architecture:** The trait sits exactly at the byte-relay seam between the VMM device model and the per-VM endpoint UDS. `GuestEndpointRelay` only exposes four transport operations: relay guest bytes for a connection id, drain endpoint bytes by connection id, close a connection id, and report whether any connections remain active. `SubstitutionBridge` remains the concrete UDS-backed implementation and is reused unchanged for both the egress and broker paths. `EgressGate`, raw TCP handling, and the host HTTP forward proxy stay in `mvm-hostd`.

**Files:**
- `crates/mvm-backend/src/vsock_egress_bridge/substitution_bridge.rs`
- `crates/mvm-backend/src/vmm/vsock.rs`
- `specs/plans/245-vsock-endpoint-relay-trait.md`
- `specs/SPRINT.md`
- `specs/REFACTOR-STATUS.md`

## Tasks

- [x] Introduce a small relay trait at the backend transport boundary with no policy, HTTP, or TLS methods.
- [x] Implement the trait in the existing UDS-backed relay used by HVF egress and broker streams.
- [x] Refactor `vmm::vsock` to call the relay through the transport-trait semantics for guest bytes, endpoint drains, closes, and active-state checks.
- [x] Keep packet framing and host-side behavior unchanged: no guest-wire changes, no `EgressGate` duplication, no hostd logic moved into backend code.
- [x] Run targeted validation:
  - `cargo fmt --all --check`
  - `CARGO_TARGET_DIR=/tmp/mvm-host-http-forward-proxy-target cargo test -p mvm-backend vsock_egress_bridge::substitution_bridge --lib`
  - `CARGO_TARGET_DIR=/tmp/mvm-host-http-forward-proxy-target cargo test -p mvm-backend vmm::vsock --lib`
  - `CARGO_TARGET_DIR=/tmp/mvm-host-http-forward-proxy-target cargo test -p mvm-guest-helpers egress_client --lib`
  - `CARGO_TARGET_DIR=/tmp/mvm-host-http-forward-proxy-target cargo test -p mvm-hostd http_forward --lib`
  - `CARGO_TARGET_DIR=/tmp/mvm-host-http-forward-proxy-target cargo clippy -p mvm-backend --lib --tests -- -D warnings`
  - `RUSTC=/Users/auser/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc CARGO_TARGET_DIR=/tmp/mvm-host-http-forward-proxy-target-rustup /Users/auser/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo zigbuild --release --target aarch64-unknown-linux-musl -p mvm-guest --bin mvm-oci-init`
- [x] No HVF artifact rebuild / BusyBox HTTPS smoke needed for this trait-only slice because reserved-frame dispatch and host HTTP/raw egress behavior were not changed; only the backend relay interface changed.
- [x] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` in the same change.

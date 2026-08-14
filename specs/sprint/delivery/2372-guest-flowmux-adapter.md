# Guest FlowMux loopback adapter (Plan 316 Phase 3)

**Issue:** #2372  
**Branch:** `feat/316-guest-flowmux-adapter`

Wired the in-guest loopback egress proxy and addon DNS forwarder to the shared
`FlowMuxReconnectClient`, replacing the legacy raw-egress line-prelude protocol
on the guest side.

## What changed

- Added `crates/mvm-agentd/src/flowmux_egress.rs`: a SOCKS5/HTTP loopback proxy
  that multiplexes CONNECT, absolute-form HTTP forward, UDP ASSOCIATE, and a
  loopback DNS stub over one authenticated FlowMux session.
- Added `crates/mvm-agentd/src/flowmux_keys.rs`: loads the per-boot guest
  signing key and host-signer trust anchor used by the FlowMux adapters.
- Trimmed `crates/mvm-agentd/src/egress_client.rs` to shared SOCKS5/HTTP
  parsing and reply helpers; deleted the raw-egress dispatch, line-prelude
  constants, and legacy tests.
- Updated `mvm-egress-client.rs` to create a `FlowMuxReconnectClient` and call
  `flowmux_egress::run`.
- Updated `addon_dns.rs` and `mvm-addon-dns.rs` to forward non-authoritative
  queries through `FlowMuxClient::resolve` when
  `MVM_ADDON_DNS_FLOWMUX_RESOLVER` is set.
- Cleaned `guest_vsock_session.rs`: removed the raw-egress `read_connect_ack`
  helper and exported a generic `splice_streams` for the FlowMux proxy.
- Exposed `read_frame_from`, `AsyncStreamSyncAdapter`, and a test-only
  `FlowMuxReconnectClient::from_receiver` in `flowmux.rs` for in-crate tests.

## Verification

- `cargo test -p mvm-agentd --features addons` passes, including new tests for
  the FlowMux DNS resolver path and the DNS stub rewrite-ID behavior.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- `cargo fmt --all --check` is clean.

## Remaining

Host-side raw-egress deletion and endpoint crash/restart integration tests are
outstanding and tracked under Plan 316 Phase 3.


## PR

- <https://github.com/tinylabscom/mvm/pull/2468>
- The previous PR #2459 on `feat/316-complete-migration` entered the merge
  queue before this branch split; this branch carries the same guest-adapter
  change on a new name so it can be reviewed/merged independently.

# Plan 316 — Guest FlowMux adapter design

Owner: feat/316-complete-migration
Status: draft

## Goal

Replace the guest-side raw-egress loopback proxy (`mvm-egress-client`) with a
single FlowMux client that owns one authenticated session to the host
`GuestService::NetworkFlow` port. SOCKS5 CONNECT, SOCKS5 UDP ASSOCIATE, HTTP
CONNECT, HTTP forward, and DNS requests all ride on that session. A session
loss fails every live local flow promptly and reconnects under bounded
exponential backoff without replaying an `Open`, request body, or datagram.

The secret-substitution HTTP forward proxy (`forward_proxy.rs` / WireRequest)
is **out of scope** for this change; it stays on its own authenticated channel
until Plan 316 Phase 4 adds `OpenHttp`.

## Background

- Host side: `mvm-hostd::supervisor::flowmux` already accepts one authenticated
  FlowMux session and serves `OpenTcp`, `OpenUdp`, `Resolve`, `Data`,
  `HalfClose`, `Reset`, and `CloseUdp`.
- Guest side today: `crates/mvm-agentd/src/egress_client.rs` runs an async
  tokio loopback proxy that speaks the legacy raw-egress line protocols
  (`host:port\n`, `MVM_HTTP_FORWARD/1\n`, `MVM_DNS/1\n`, `MVM_SOCKS5_UDP/1\n`).
- Authentication: the guest agent already generates an ephemeral Ed25519
  signing key per boot and loads the host signer public key. FlowMux reuses
  the same trust anchor and keypair.

## Design

### One session owner

`FlowMuxSession` in `crates/mvm-agentd/src/flowmux.rs` is the only code that
holds the authenticated session. It runs in its own tokio task and exposes an
async request/response API to the local proxy adapters:

```rust
pub struct FlowMuxSession;

impl FlowMuxSession {
    /// Connect to the host NetworkFlow channel, perform the authenticated
    /// handshake as guest, send FlowMux `Hello`, and read `HelloAck`.
    pub async fn connect(
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
    ) -> Result<Self>;

    /// Open a TCP flow. Returns `Opened` -> a `FlowMuxStream` handle, or
    /// `Refused` -> an error carrying the host's reason.
    pub async fn open_tcp(&self, target: &str) -> Result<FlowMuxStream>;

    /// Open a UDP association. Returns `UdpOpened` -> a `FlowMuxUdpSocket`
    /// handle, or `Refused`.
    pub async fn open_udp(&self) -> Result<FlowMuxUdpSocket>;

    /// Resolve a DNS name. Returns the raw DNS response bytes.
    pub async fn resolve(&self, name: &str, qtype: DnsRecordType) -> Result<Vec<u8>>;
}
```

The handshake (`mvm_core::net::session::Session::guest`) is synchronous over a
`Read + Write` stream. The async `connect` wrapper bridges this by doing the
crypto handshake in `tokio::task::spawn_blocking` on an owned std stream, then
wrapping the resulting `Session` in an async read/write loop.

### Stream handles

`FlowMuxStream` is an async `AsyncRead + AsyncWrite` type. Writes emit `Data`
frames, reads return payload bytes from incoming `Data` frames. EOF on the
host side surfaces as graceful end of stream; a host `Reset` surfaces as an
error. Dropping the handle sends `HalfClose` if only the write direction was
active, or `Reset` if the caller wants to abort.

`FlowMuxUdpSocket` exposes:

```rust
pub async fn send_to(&self, dest: SocketAddr, payload: &[u8]) -> Result<()>;
pub async fn recv_from(&self) -> Result<(SocketAddr, Vec<u8>)>;
```

`send_to` emits `UdpSend` frames with the FlowMux UDP address prefix.
`recv_from` reads `UdpRecv` frames and returns the source address + body.

### Reconnect owner

`FlowMuxClient` wraps `FlowMuxSession` plus reconnect state:

- One `tokio::sync::watch` channel advertises session readiness.
- On connect failure or session drop, mark all outstanding `FlowMuxStream` /
  `FlowMuxUdpSocket` handles as broken so local clients fail immediately.
- Reconnect with bounded exponential backoff (250 ms -> 16 s cap), jitter, and
  a small number of absolute attempts before giving up.
- During reconnect, new `open_tcp` / `open_udp` / `resolve` calls wait on the
  readiness watch with a deadline; if the session never comes back they fail.
- **No replay**: a new session starts with fresh odd stream IDs. Any request
  body or datagram that was in flight is lost; the local client sees a broken
  pipe and must retry at the application layer.

### Local proxy adapters

Each existing guest listener becomes a thin adapter that uses the shared
`FlowMuxClient`:

| Listener | File | Maps to |
|----------|------|---------|
| SOCKS5/HTTP proxy | `egress_client.rs` | `open_tcp` for CONNECT, `open_udp` for UDP ASSOCIATE, `resolve` for DNS, `open_tcp` for HTTP forward |
| Guest DNS stub | `bin/mvm-addon-dns.rs` | `resolve` |

The adapters keep their socket accept loops and protocol framing (SOCKS5
handshake, HTTP request parsing). The relay logic is simplified: instead of
splicing a raw host stream, they copy bytes between the local socket and a
`FlowMuxStream` / `FlowMuxUdpSocket`.

### Frame I/O

The async frame layer uses the same wire format as the host:

- Length-prefixed `MVFM` frames from `mvm_contract::protocol::network_flow`.
- Each payload is sealed with `Session::seal` and opened with `Session::open`
  before encoding / after decoding.
- The session task reads frames from the transport, dispatches `Data` /
  `UdpRecv` / `WindowUpdate` / `HalfClose` / `Reset` / `CloseUdp` to the
  appropriate stream handle, and forwards outbound frames from stream handles
  onto the transport.

### Keys and identity

The guest agent already creates an ephemeral `SigningKey` at boot and loads
`host_signer_key` from `/etc/mvm/host-signer.pub` (see
`mvm-guest-agent.rs`). The FlowMux client uses:

- `guest_signing_key` — the same ephemeral key used for control RPC.
- `host_anchor` — the same host signer public key used for control RPC.
- `session_id` — assigned by the host during `Session::guest`.

No new guest-side key material or config file is required.

## Files to change

### New

- `crates/mvm-agentd/src/flowmux.rs` — session, stream handles, frame pump,
  reconnect owner.
- `crates/mvm-agentd/src/flowmux/frame_io.rs` — async encode/decode + seal/open.
- `crates/mvm-agentd/src/flowmux/stream.rs` — `FlowMuxStream` async read/write.
- `crates/mvm-agentd/src/flowmux/udp.rs` — `FlowMuxUdpSocket`.
- `crates/mvm-agentd/src/flowmux/tests.rs` — UnixStream-pair roundtrip tests.

### Modified

- `crates/mvm-agentd/src/egress_client.rs` — replace raw-egress prelude with
  `FlowMuxClient` calls; delete line-sniffing dispatch.
- `crates/mvm-agentd/src/bin/mvm-addon-dns.rs` — use `FlowMuxClient::resolve`.
- `crates/mvm-agentd/src/lib.rs` — expose `flowmux` module.
- `crates/mvm-agentd/src/bin/mvm-guest-agent.rs` — pass `guest_signing_key` /
  `host_signer_key` to the FlowMux client startup path.
- `crates/mvm-agentd/src/guest_vsock_session.rs` — remove raw-egress-specific
  helpers (`read_connect_ack`, `write_initial_bytes`) once no longer used.

### Deleted (after migration)

- Legacy raw-egress line marker constants in `egress_client.rs`.
- `mvm-core/src/guest_netd.rs` and `mvm-core/src/socks5_udp.rs` if no longer
  referenced after the guest adapter lands.

## Failure modes

- Host refuses a flow -> `Refused`/`ResolveRefused` surfaced to the local proxy
  as a SOCKS/HTTP/DNS error.
- Host credit exhaustion -> host sends `Reset`; local stream returns an error.
- Session lost -> all live handles error; reconnect owner starts backoff. New
  requests block until reconnect or timeout.
- Reconnect exhausted -> `FlowMuxClient` enters a permanent failed state; the
  local proxy listeners keep accepting connections but every request fails.

## Testing

1. Unit tests in `flowmux/tests.rs` using `UnixStream::pair()`:
   - handshake + Hello/Ack roundtrip,
   - `OpenTcp` allowed/refused,
   - data echo,
   - guest `Reset` retires stream,
   - `OpenUdp` send/recv,
   - `Resolve` roundtrip,
   - reconnect after dropped stream.
2. Update `egress_client.rs` tests to speak FlowMux frames instead of raw
   preludes.
3. Integration: start the host FlowMux acceptor + guest adapter in a test and
   exercise SOCKS5 CONNECT/UDP ASSOCIATE and DNS.

## Open questions

1. Should the reconnect owner block new requests indefinitely, or fail fast
   after a bounded wait? Proposal: block up to the forward-leg timeout
   (`cfg.forward_timeout_secs`) then fail.
2. Do we keep the existing sync `forward_proxy.rs` secret-substitution path
   running on a separate loopback port, or fold it into the same binary?
   Proposal: keep it separate until Phase 4 `OpenHttp`.
3. How does the guest adapter learn the vsock/UDS path for NetworkFlow?
   Proposal: reuse the existing `MVM_EGRESS_VSOCK_PORT` / `/run/egress.sock`
   plumbing; no new env var.

## Acceptance criteria

- [x] `mvm-egress-client` no longer emits `host:port\n`, `MVM_HTTP_FORWARD/1`,
      or `MVM_DNS/1` line frames.
- [x] One `FlowMuxClient` task owns the authenticated session; adapters share
      it via clones of an `Arc<FlowMuxClient>`.
- [x] Session loss fails live flows and reconnects with bounded backoff.
- [x] All new code has unit/integration tests; `cargo clippy --workspace
      --all-targets -- -D warnings` is clean.
- [x] `specs/plans/316-single-flow-vsock-networking.md` Phase 3 guest-adapter
      checkbox is ticked.

# Plan 234 — Transparent networking over vsock

**Status:** In progress — `mvm-net` protocol contract, guest bridge planning, Linux guest executor, packet translation foundation, dependency-light guest pump seam, TCP response synthesis, bounded pump loop substrate, concrete TUN/wire adapters, Linux guest runner, and packaged guest bridge binary landed.

**Owner directive:** workload networking remains a vsock-mediated capability. The guest gets normal application-visible networking behavior, but the host remains the only authority that opens real network sockets, performs DNS, terminates TLS for secret-bearing flows, applies egress policy, records audit, and emits attestable evidence.

## Decisions

- Use one crate, `crates/mvm-net`, for the transparent networking subsystem. Keep protocol, guest bridge, host authority, TLS transform, plugin pipeline, DNS, ICMP echo, limits, and audit modules together until their interfaces are stable enough to extract.
- Keep compile-time cost explicit: the default crate build exposes protocol types without serialization derives or runtime dependencies; heavier support such as serde, guest TUN execution, host async I/O, TLS, and plugins must remain opt-in features.
- The existing `mvm-network` crate remains the low-level provisioning/provider trait surface. It is not renamed or overloaded.
- TLS termination is mandatory for any flow that can carry host-held secrets, replacement material, or response bytes that must be checked before the guest sees them.
- Replacement is plugin-like, but plugins operate on semantic stream events and bounded chunks. Byte-by-byte callbacks are not the hot-path API.
- ICMP echo is supported as a controlled protocol adapter. Arbitrary raw sockets are out of scope for the production default.
- The first production target is transparent DNS plus TCP over vsock for ordinary guest tools such as `wget`, package managers, SDK clients, and browser automation.

## Workstreams

- [x] **A1 — Create the single `mvm-net` crate and protocol foundation.**
      Add the workspace member, keep the first implementation to tested shared protocol primitives, keep serde opt-in, document the crate in the architecture reference, and verify the default normal dependency tree stays empty beyond `mvm-net`.
- [x] **A2 — Define the complete protocol contract.**
      Extend `mvm-net::proto` with version negotiation, flow correlation, DNS, TCP, UDP, ICMP echo, TLS-transform routing, denial reasons, and audit correlation fields. Add serde roundtrip and malformed-message tests for every message family.
- [x] **B1 — Build the guest network bridge.**
      Add the guest-side module and binary that creates `tun0`, installs the synthetic default route, points resolver configuration at the synthetic gateway, and translates guest traffic into `mvm-net` protocol frames over vsock.
- [x] **B1a — Add dependency-light guest bridge planning.**
      Add `mvm-net::guest` behind an opt-in `guest` feature with validated synthetic IPv4 defaults, interface-name validation, resolver paths, transparent-network vsock port, and an ordered operation plan for TUN, default route, resolver, and vsock-authority connection. Keep normal dependencies empty for default, no-default-features, and `guest` builds.
- [x] **B1b — Implement the Linux guest TUN executor.**
      Add the Linux-only executor that opens `/dev/net/tun`, applies the B1a operation plan, installs route/resolver state, connects to the vsock authority, and fails closed on missing capabilities or kernel support.
- [x] **B1c — Implement the TUN packet/protocol pump.**
      Translate IP packets read from the guest TUN fd into DNS, TCP, UDP, and ICMP `mvm-net` protocol frames over the vsock authority stream, apply host responses back to the TUN device, and enforce bounded buffers/backpressure before any guest packet can escape.
- [x] **B1c1 — Add dependency-light packet translation foundation.**
      Add `mvm-net::guest_packet` behind the existing `guest` feature. Parse outbound IPv4 from the TUN boundary into DNS query, TCP open/data/close, UDP datagram, and ICMP echo protocol events; track DNS/ICMP/flow correlation state; remember synthetic DNS IP mappings; synthesize DNS and ICMP echo replies back into IPv4 packets; and refuse malformed, fragmented, unsupported, over-limit, and unknown-flow packets without adding runtime dependencies.
- [x] **B1c2a — Add the dependency-light guest pump seam.**
      Add `mvm-net::guest_pump` behind the existing `guest` feature. Wire the packet translator to generic authority and packet-sink traits; send outbound translated `mvm-net` protocol messages to the authority; write synthesized DNS and ICMP echo responses back to the guest sink; ignore handshake control messages; and keep unsupported transport authority responses fail-closed until protocol-specific synthesis lands.
- [x] **B1c2b — Add stateful TCP response synthesis.**
      Extend `mvm-net::guest_packet` with TCP flow state keyed by both guest 4-tuple and `FlowId`; synthesize authority `TcpOpenResult` messages into SYN-ACK or RST-ACK packets; synthesize ordered host-to-guest `TcpData` chunks into PSH/ACK or FIN/ACK packets; synthesize host closes into FIN/RST packets; reject wrong-direction, out-of-order, unknown-flow, and over-limit chunks; and wire `mvm-net::guest_pump` to write those TCP packets back to the guest sink.
- [x] **B1c2c — Add bounded guest pump loop substrate.**
      Extend `mvm-net::guest_pump` with a reusable `GuestPumpLoop` and `GuestPumpLoopConfig`; own one bounded TUN packet buffer; add testable source/authority-receive traits; process at most one guest packet and a bounded number of authority messages per tick; report idle/closed edges; reject source errors, invalid read sizes, zero limits, and over-IPv4 packet buffers without adding dependencies.
- [x] **B1c2d — Add the concrete Linux TUN/vsock fd adapters.**
      Add `TunPacketIo` for the Linux TUN packet source/sink boundary and an opt-in `wire-json` feature with bounded length-prefixed `NetMessage` framing, partial-read preservation, guest authority trait impls, closed-stream handling, and oversized-frame refusal.
- [x] **B1c2e — Add the concrete Linux TUN/vsock runner.**
      Add the real runner that reads from the Linux TUN fd, writes protocol frames to the vsock authority stream, consumes host responses, synthesizes TCP replies to the guest, and enforces bounded readiness/backpressure across both directions.
- [x] **B1d — Package the guest bridge binary.**
      Add the lean guest entrypoint that loads its bridge config, runs the Linux executor plus guest runner, reports startup/runtime failures clearly, and can be embedded into guest images without pulling host-side networking code.
- [ ] **B2 — Build the host network authority.**
      Add the host-side module and binary that accepts the per-VM vsock stream, owns synthetic DNS/IP mapping, reuses the canonical network policy projection, opens real host sockets only after admission, and records flow-open/flow-close audit events.
- [ ] **C1 — Add DNS plus TCP MVP.**
      Support A/AAAA DNS answers, synthetic IP mapping, TCP connect/data/close, allow-host default port handling, denied-host failure behavior, and bounded backpressure.
- [ ] **C2 — Add mandatory TLS transform for secret-bearing flows.**
      Use a per-VM name-constrained trust root in the guest and a host-only private key in the transform authority; terminate guest TLS, originate upstream TLS, and fail closed on certificate-pinned clients or unsupported ALPN.
- [ ] **C3 — Add plugin-like transform pipeline.**
      Define plugin manifests, capability declarations, timeout budgets, max buffered bytes, stream-event APIs, and crash isolation. Start with built-in audit, secret replacement, response leak guard, and metadata-endpoint denial plugins.
- [ ] **D1 — Add UDP and controlled ICMP echo.**
      Support DNS-adjacent UDP first, then general admitted UDP datagrams. Implement ICMP echo as explicit reachability/audit behavior without allowing arbitrary raw sockets.
- [ ] **E1 — Wire `machine run --net` / `--allow-host` to `mvm-net` on HVF.**
      Spawn the guest bridge and host authority from the workload runner, remove the raw `host:port` egress path from the default HVF flow, and keep all real egress behind the host authority.
- [ ] **E2 — Prove the user-visible behavior.**
      Add an acceptance path where `machine run --image busybox --allow-host google.com:443 -it -- /bin/sh` can resolve and fetch `https://google.com` through the HVF vsock networking path. Add denied-host, no-network, TLS-transform, and ICMP echo coverage.
- [ ] **F1 — Harden for production.**
      Add fuzz tests, malformed-packet tests, flow limits, per-VM rate limits, memory caps, plugin crash tests, chain-signed audit verification, and benchmarks for latency, throughput, and CPU.

## Acceptance

- A guest with no network grant cannot resolve names, open TCP, send UDP, or obtain synthetic ICMP echo responses.
- A guest with `--allow-host host:port` can reach only admitted destinations and only through the host authority.
- Secret-bearing HTTPS flows terminate at the transform authority; the guest never receives the real secret value through env, disk, logs, or transformed response bytes.
- Audit records identify DNS decisions, flow opens, flow closes, transform actions, denials, byte counts, and the exact policy digest.
- Receipts identify the `mvm-net` protocol version, host authority binary digest, guest bridge binary digest, transform plugin digests, and effective network policy.

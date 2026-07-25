# Plan 259 — User-space MicroVM outbound networking

**Status: COMPLETE**

This plan implements the actionable networking work from PR #1831 while
preserving the repository's uniform-vsock production boundary. Production
workloads remain NIC-less and use the authenticated host egress endpoint;
transparent ordinary TCP/UDP sockets are available in the explicit QEMU
dev/test backend through QEMU's rootless user-mode virtio network.

## Completed work

- [x] Evaluate slirp4netns/libslirp, gVisor netstack, gost, redsocks, QEMU
  user-mode networking, and the custom vsock SOCKS5 relay. Record the choice
  and its security boundary in
  [`specs/research/259-userspace-egress-evaluation.md`](../research/259-userspace-egress-evaluation.md).
- [x] Keep the production path on the existing NIC-less vsock seam rather than
  adding a second packet-forwarding model.
- [x] Add a shared, bounded SOCKS5 UDP datagram codec. IPv4, IPv6, and hostname
  destinations are supported; fragmented datagrams, malformed headers, invalid
  domains, and oversized datagrams fail closed.
- [x] Extend the host egress gate with UDP decisions while preserving the
  existing TCP decision path and mandatory-deny ranges.
- [x] Add guest-side UDP Associate negotiation, loopback UDP relay, and framed
  vsock transport handling.
- [x] Add host-side async UDS and Linux blocking-vsock UDP relays. Hostname
  resolution remains host-side and every destination is checked against the
  shared UDP policy before a host socket is used.
- [x] Bound frame and datagram allocations, reject malformed frames, drop
  unanswered datagrams after the response budget, and keep the association
  alive for later datagrams.
- [x] Confirm and test transparent TCP/UDP for the rootless QEMU dev/test
  backend. Its `-netdev user` + `virtio-net-pci` path gives workloads a normal
  guest NIC without a host TAP or elevated setup; it is explicitly outside
  production claims.
- [x] Add an opt-in local latency/throughput comparison for direct kernel
  sockets versus SOCKS5-framed/relayed TCP and UDP in
  [`tests/egress_path_bench.rs`](../../tests/egress_path_bench.rs).
- [x] Document rootless launch modes, backend boundaries, and proxy behavior in
  [`public/src/content/docs/guides/networking.md`](../../public/src/content/docs/guides/networking.md).
- [x] Cover codec round trips and rejection paths, UDP policy separation from
  TCP, guest association framing, host default-deny/malformed handling, QEMU
  networking selection, and the benchmark's opt-in path.

## Validation

Focused validation:

```text
cargo fmt --all -- --check
cargo check -p mvm-core -p mvm-runtime -p mvm-agentd -p mvm-hostd
cargo test -p mvm-core socks5_udp
cargo test -p mvm-runtime egress_gate::tests::udp_decision_uses_udp_rules_without_widening_tcp
cargo test -p mvm-agentd --features addons egress_client::tests::udp_associate_frames_datagrams_over_the_upstream
cargo test -p mvm-hostd supervisor::socks5_udp::tests
MVM_EGRESS_BENCH=1 cargo test --test egress_path_bench -- --nocapture
```

The benchmark compares transport overhead on the local host; it is not a
claim about a particular hypervisor, network, VPN, or Internet route. A live
QEMU run is the transparent rootless integration path; the production
NIC-less backends intentionally require proxy-aware workloads.

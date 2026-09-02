# Plan 316 — Single flow-aware vsock networking path

## Status

**The active remainder moved to
`specs/plans/2026-08-19-flowmux-single-path-closeout.md` and issue #2751. Do not
use the closed phase issues below as the current tracker.**

Phase 0 froze L3 expansion and Phase 1 pinned the protocol. The transport
cutover in `specs/plans/2026-08-15-flowmux-single-transport-cutover.md` completed
the production outbound path: TCP, UDP, DNS, mediated ICMP, and typed HTTP use
FlowMux, the raw/Wire dispatcher is gone, and launch waits for authenticated
session readiness. PR #2741 then fixed the host-first handshake on the
relayed-vsock backends.

The shared per-VM endpoint budgets, bounded typed transformations, endpoint-
owned connectors, declared FlowMux ingress runtime, performance harness,
public compatibility-surface removal, complete frozen-L3 deletion, and
permanent single-path/socket-owner gates are implemented through W7 of the
successor plan's dependency-ordered PR stack. The final performance decision
and live backend matrix remain under that successor plan.

## Tracking issues

Umbrella: [#2368](https://github.com/tinylabscom/mvm/issues/2368).

| Phase                                                                 | Issue                                                   | Blocked by     |
| --------------------------------------------------------------------- | ------------------------------------------------------- | -------------- |
| 0 — Ratify the invariant and freeze expansion                         | [#2369](https://github.com/tinylabscom/mvm/issues/2369) | — (actionable) |
| 1 — Pin protocol, resource, and performance baselines                 | [#2370](https://github.com/tinylabscom/mvm/issues/2370) | #2369          |
| 2 — Introduce the one authenticated endpoint without changing callers | [#2371](https://github.com/tinylabscom/mvm/issues/2371) | #2370          |
| 3 — Converge egress TCP, UDP, and DNS                                 | [#2372](https://github.com/tinylabscom/mvm/issues/2372) | #2371          |
| 4 — Stream typed transformations over the same path                   | [#2373](https://github.com/tinylabscom/mvm/issues/2373) | #2372          |
| 5 — Implement declared ingress on FlowMux                             | [#2374](https://github.com/tinylabscom/mvm/issues/2374) | #2373          |
| 6 — Set the compatibility boundary without weakening isolation        | [#2375](https://github.com/tinylabscom/mvm/issues/2375) | #2374          |
| 7 — Delete L3 completely                                              | [#2376](https://github.com/tinylabscom/mvm/issues/2376) | #2375          |
| 8 — Make “one path” mechanically enforceable                          | [#2377](https://github.com/tinylabscom/mvm/issues/2377) | #2376          |

Phases run strictly in order; only Phase 0 is actionable until it merges.

This plan supersedes the production-path decisions in Plan 285
(`l3-vsock`) and Plan 287 (the userspace socket datapath). It preserves the
completed evidence from those plans as historical test and performance data,
but removes their runtime path. It also corrects the stale statement in
`specs/refactor/03-networking.md`: the L3 path was reintroduced after that
document said it had been deleted.

## Decision

Every untrusted workload has exactly one possible path to or from an external
network:

```text
guest loopback adapter
  -> authenticated FlowMux session on GuestService::NetworkFlow (vsock port 5253)
  -> one per-VM mvm-network-endpoint
  -> canonical policy, DNS, substitution/redaction, rate and audit pipeline
  -> host-originated TCP/UDP socket or host-owned ingress listener
```

`NetworkMode`, `L3Vsock`, `HostVsockProxy`, `raw_ip_stack`, the guest `mvm0`
TUN, `mvm-net-agent`, `mvm-netd`, `NetworkControl`, `NetworkData`, host TUN,
nftables forwarding, and the smoltcp datapath are deleted. `Off` is absence of
a network grant and absence of `NetworkFlow`; it is not a second networking
mode.

The endpoint is **flow-aware at L4**, not universally L7. TCP and UDP payloads
whose plan requests no content transformation are relayed without HTTP parsing.
L7 parsing, TLS termination, credential substitution, reversible replacement,
and redaction run only for an explicitly typed HTTP/connector flow whose signed
plan requires them. An opaque encrypted flow is never described as transformed.
If a plan requires transformation, admission refuses an opaque flow shape.

This is expected to be faster than the L3 path for ordinary TCP/UDP: the host
does not parse every IP packet, reconstruct guest TCP in smoltcp, maintain two
TCP state machines, or copy packet framing. Performance is nevertheless an
acceptance gate, not an assumption; Phase 1 records the legacy baseline and
Phase 8 compares the final path against it.

## Non-negotiable invariants

1. **One external socket owner.** Only `mvm-network-endpoint` may call outbound
   `connect` or bind workload ingress listeners. Broker services and typed
   connectors delegate network execution to it; they may not open a parallel
   route.
2. **No guest network device.** A production workload VMM exposes vsock and no
   virtio-net, TAP, bridge, TUN-backed hypervisor device, slirp, passt, vpnkit,
   or QEMU user network.
3. **No raw-packet protocol.** No production guest/host protocol carries IPv4
   or IPv6 packets. The endpoint accepts typed flow intent and bounded stream or
   datagram data only.
4. **Default deny.** No admitted destination or listener means no network
   endpoint capability. Endpoint loss, authentication failure, policy failure,
   audit failure where audit is mandatory, and transform failure all fail
   closed.
5. **Host-owned destination.** The host resolves DNS, pins the selected address,
   revalidates redirects, applies private/link-local/loopback/metadata denies,
   and originates the socket. Guest-provided IPs, hostnames, ports, CIDs, UDS
   paths, stream IDs, and listener IDs are never authorization inputs.
6. **Secrets remain host-side.** Raw secret values never enter guest memory,
   disks, logs, protocol frames, errors, metrics, or audit entries. Secret
   buffers remain redacted under `Debug` and zeroized on drop.
7. **Transform honesty.** Replacement/redaction is guaranteed only for a typed
   transform flow. A plan that requires it cannot use opaque TCP, UDP, or TLS
   passthrough.
8. **Ingress is declared.** The host binds exactly the signed address, port, and
   protocol. Undeclared listeners do not exist. Host TLS termination uses only
   a plan-bound certificate reference, and sanitized bytes alone cross to the
   guest.
9. **Bounded operation.** Streams, UDP associations, listeners, DNS entries,
   buffered bytes, frame sizes, connection rates, and transform work all have
   per-VM ceilings. Hitting a ceiling refuses the newcomer; it never evicts an
   authorized live flow to make room silently.
10. **All workload backends converge.** Firecracker, HVF, and libkrun use the
    same `WorkloadRunner` endpoint. Docker/Wasm remain outside a numbered claim
    until they use this endpoint contract or explicitly refuse networking.

## Security-claim effect

- **Claim 10 is strengthened:** the sole network decision and socket creation
  site is the per-VM endpoint; no L3 compatibility path can diverge from it.
- **Claim 12 is preserved:** every typed connector and listener is bound to the
  signed `ExecutionPlan` before dispatch and emits the same chain-signed audit
  taxonomy.
- **Claim 13 is preserved:** broker calls can request destination-bound use of a
  credential, but cannot receive or transmit its raw value.
- **Preview claim 16 is strengthened:** substitution and its leak gate sit on
  the only endpoint that can create an external connection. The claim remains
  scoped to typed transform flows and never extends to opaque ciphertext.
- **Claims 5 and 8 are preserved:** the new decoder is fuzzed, and the endpoint
  derives every capability from the admitted signed plan.

## Protocol and ownership

The wire contract lives in a new `mvm-contract::protocol::network_flow` module
so guest and host share one `#![no_std] + alloc`, `forbid(unsafe_code)` codec.
It uses a bounded binary header and binary payload rather than JSON/base64 on
the data plane. Protocol version 1 has these frame classes:

- session: `Hello`, `HelloAck`, `GoAway`;
- TCP: `OpenTcp`, `Opened`, `Refused`, `Data`, `WindowUpdate`, `HalfClose`,
  `Reset`;
- UDP: `OpenUdp`, `UdpOpened`, `UdpSend`, `UdpRecv`, `CloseUdp`;
- DNS: `Resolve`, `Resolved`, `ResolveRefused`;
- ingress: `InboundOpen`, `InboundReady`, `InboundRefused`, followed by the
  same TCP `Data`/credit/close frames; and
- typed transforms: `OpenHttp`, streaming request/response head and body
  frames, and a terminal `HttpComplete` or `Refused`.

The fixed header carries version, opcode, flags, stream ID, and payload length.
Decoding checks the payload cap before allocation, rejects stream ID zero for
flow frames, rejects unknown opcodes and flags, and rejects frames illegal for
the stream's current state. Stream IDs are odd for guest-initiated flows and
even for host-initiated ingress, preventing simultaneous-open collisions. Data
credit is per stream, so one stalled response cannot block unrelated flows.

Version 1 limits a frame payload to 64 KiB, a DNS name to 253 bytes, a single
HTTP head to 64 KiB, and a UDP datagram to 65,507 bytes. The signed plan's
existing `max_flows` default of 4,096 remains the aggregate TCP/HTTP ceiling;
UDP associations are capped at 256; declared ingress listeners retain the
existing userspace ceiling of 16. Phase 1 adds compile-time and runtime tests
that these constants are included in the endpoint memory ceiling.

Authentication binds the session to the host-owned
`VmInstanceIdentity { node_id, vm_id, boot_id, plan_digest }`. Reuse the existing
signed challenge, ephemeral X25519 key agreement, AES-GCM frame protection,
monotonic sequence, and replay rejection from the authenticated control
session; extract the transport-independent session machinery rather than copy
it. The endpoint receives the expected identity and verification material from
the admitted launch state, never from guest bytes.

## Workstreams

### Phase 0 — Ratify the invariant and freeze expansion

- [x] Add `machine run --port HOST:GUEST`; the initial foreground proxy was
      transitional. Phase 5 replaced it with signed FlowMux ingress, and the
      dynamic post-admission command is now an explicit migration refusal.
- [x] Add an accepted ADR that records the L4-with-selective-L7 decision, the
      impossibility of arbitrary guest TLS plus host replacement without TLS
      interception, and the rejection of a host MITM CA as the universal path.
- [x] Mark ADR-036 and ADR-037 superseded for production workload networking;
      retain their measurements and historical rationale without describing
      either implementation as live.
- [x] Reconcile `specs/refactor/03-networking.md`, ADR-001's backend matrix and
      claim-10 section, `specs/SPRINT.md`, and `specs/REFACTOR-STATUS.md` with
      the actual two-path starting state and this target invariant.
- [x] Add a temporary CI ratchet that forbids new non-test references to
      `L3Vsock`, `raw_ip_stack`, `NetworkControl`, `NetworkData`, `spawn_netd`,
      and `host_datapath` outside the files scheduled for deletion by this
      plan. The allowlist is an explicit file list and can only shrink.
- [x] Freeze Plan 285 and Plan 287: no feature work lands on their runtime path;
      only security fixes needed to keep the tree safe during migration may
      modify it.
- [x] In the first implementation change, make synthesis and admission reject
      `raw_ip_stack=true`/`L3Vsock` with an error naming the supported loopback
      proxy and typed-connector alternatives. Existing running VMs may drain,
      but no new production L3 workload may boot while FlowMux is built. This
      ensures the migration never operates three live production paths.

**Landed as.** ADR-042 (`specs/adrs/042-single-flow-vsock-networking.md`);
superseded-for-production markers on ADR-036 and ADR-037; a rewritten
`specs/refactor/03-networking.md`; a qualified tier matrix and claim-10 section
in ADR-001; `xtask check-l3-expansion-freeze`
(`xtask/src/check_l3_expansion_freeze.rs`, wired into the CI Lint job) with a
29-entry allowlist that fails closed on a stale entry so it can only shrink;
and one shared refusal, `mvm_core::plan::l3_retirement`, called from
`synthesize_plan`, `admit_for_run`, and
`mvm_cli::commands::machine::preflight_network`.

### Phase 1 — Pin protocol, resource, and performance baselines

- [x] Add `mvm-contract::protocol::network_flow` with the version-1 frame header,
      opcodes, strict state-independent decoding, and the exact limits above.
- [x] Add roundtrip tests for every frame, default/value tests, unknown
      opcode/flag/version rejection, truncated header/body rejection, cap-before-
      allocation, invalid stream IDs, oversized DNS/head/datagram rejection,
      and cross-endian golden byte fixtures.
- [x] Add a state-machine validator that rejects data-before-open, duplicate
      open/close, credit overflow, stream-ID parity violations, reuse after
      reset, and host-initiated opens not backed by a declared listener.
- [x] Move `max_flows` and the other endpoint resource ceilings out of
      `L3NetworkSpec` into a transport-neutral, signed `NetworkLimits` plan type
      before any FlowMux runtime consumes them. Defaults preserve the current
      4,096-flow ceiling; serde omits default values so existing signed-plan
      bytes remain stable until the intentional plan-version migration.
      Landed as an additive, default-omitted `ExecutionPlan.network_limits`
      contract with a validated builder and `effective_network_limits()`
      compatibility projection. The frozen L3 gateway now consumes that one
      accessor; pre-migration L3 fields remain deserialize-only compatibility
      data so existing signatures and plan bytes continue to verify.
- [x] Add `fuzz_network_flow_decode` and `fuzz_network_flow_state`; seed them
      with every valid frame class plus malformed length and transition cases.
- [x] Extract the existing authenticated-session handshake and encrypted frame
      machinery into a transport-independent unit shared by control RPC and
      FlowMux. Prove wrong boot ID, wrong plan digest, wrong key, replayed
      sequence, tampered ciphertext, expired session, and counter exhaustion
      fail before dispatch.
- [x] Add a hermetic `xtask network-perf` harness that runs legacy raw TCP,
      legacy typed HTTP, legacy UDP, and the new FlowMux equivalents against
      loopback fixtures. It records JSON containing host/arch, build profile,
      payload size, concurrency, p50/p95 connect latency, p50/p95 request
      latency, throughput, CPU time, peak RSS, and bytes copied.
- [x] Record 30-sample release-build legacy baselines on Linux x86_64 and macOS
      arm64 before changing the endpoint. Store the result under
      `specs/benchmarks/network/` with the source commit and command embedded in
      the JSON. The harness refuses to compare different hosts, architectures,
      profiles, or payload/concurrency matrices.

**Landed so far (Phase 1).** `mvm-core::net::session` — a transport-independent
authenticated session (`Session::host`, `Session::guest`, `seal`, `open`) shared
by the control-RPC path and the future FlowMux data path. It reuses the existing
Ed25519/X25519/AES-256-GCM handshake and per-direction sequence numbers, and
adds dedicated tests for replay, out-of-order frames, tampered ciphertext,
tampered signatures, wrong session ID, wrong signer, and sequence-counter
exhaustion. The control-RPC `AuthenticatedSession` in `mvm-agentd` is now a thin
JSON-envelope wrapper around this shared module.

`mvm-contract::protocol::network_flow` —
`limits` (the ceilings, including `MAX_FLOW_CREDIT_BYTES` derived from them so
the endpoint memory bound cannot drift), `opcode` (all 27 v1 opcodes, their
classes, their permitted sender, and the confirmation relation), `frame` (the
20-byte fixed header, state-independent decode, cap-before-allocate, golden
byte fixtures), and `state` (the session and per-stream machine). 87 unit tests.
`crates/mvm-contract/fuzz` carries `fuzz_network_flow_decode` and
`fuzz_network_flow_state` with 95 committed seeds; both are wired into
`security.yml`'s fuzz lane. The header's length field is a `u32`, not the
tunnel's `u16`: 64 KiB is one past what a `u16` expresses, and a cap the field
cannot represent is not really enforced at the parse boundary.

### Phase 2 — Introduce the one authenticated endpoint without changing callers

**Status: SUBSTANTIALLY LANDED, NOT COMPLETE.** The production endpoint role
is renamed, the authenticated FlowMux session acceptor and bounded stream
registry are wired into `mvm-network-endpoint`, and backend witnesses prove
exactly one `NetworkFlow` service per granted workload with no L3 services.
Unchecked boxes below are unchecked because they are not done, not because the
bookkeeping lagged — see the Status section.

- [x] Rename the production role from `mvm-substitution-endpoint` to
      `mvm-network-endpoint`, including Cargo bin declarations, release
      packaging, updater manifests, helper resolution, confinement profiles,
      scripts, process reaping, metrics labels, and operator diagnostics.
- [x] Rename `GuestService::Substitution` to `GuestService::NetworkFlow`, retain
      port 5253, and delete the hand-maintained duplicate
      `EGRESS_VSOCK_PORT` constant in favor of the typed service mapping.
      The port now has exactly one definition in the workspace:
      `mvm_contract::protocol::network_flow::NETWORK_FLOW_PORT`. It lives in
      `mvm-contract` rather than `mvm-net` because the guest cannot depend on
      `mvm-net` — the same arrangement `l3::L3_CONTROL_PORT` already uses.
      `mvm_net::GuestService::NetworkFlow` and `mvm_agentd::vsock::EGRESS_PORT`
      both derive from it, so the ~80 existing `EGRESS_PORT` call sites
      transitively name one value. A `const` assertion in `mvm-agentd` makes
      drift a compile error; `mvm-net`'s `port()` test asserts the mapping and
      the contract constant agree.
- [x] Rename `EndpointSpawner`/`RealEndpointSpawner` to
      `NetworkEndpointSpawner`/`RealNetworkEndpointSpawner`; keep exactly one
      production `spawn` implementation in `WorkloadRunner`.
      `EndpointSpawnRequest` moved with them, and `xtask
      check-uniform-vsock-egress` — which pins the converged runner shape by
      type name — was updated in the same change.
- [x] Make the endpoint authenticate one long-lived FlowMux session before it
      accepts any flow frame. A failed or missing session prevents workload
      readiness when the signed plan grants networking.
- [x] Add bounded per-stream registries, odd/even ID allocation, independent
      credit windows, cancellation-safe teardown, and endpoint-wide graceful
      shutdown. No lock guard may cross an await.
- [x] Keep the legacy raw/WireRequest dispatch behind an internal transition
      adapter for this phase only. It must call the new endpoint's canonical
      admission and socket-owner functions; it may not retain an independent
      connect, bind, DNS, rate, or audit implementation.
- [x] Add tests proving Firecracker, HVF, and libkrun specs expose exactly one
      `NetworkFlow` service when networking is granted, none when it is absent,
      and never expose L3 control/data services.

**Landed so far (Phase 2).** The production endpoint process is renamed from
`mvm-substitution-endpoint` to `mvm-network-endpoint` (`network_endpoint.rs`,
`network_endpoint_proxy.rs`, `network_endpoint_spawn.rs`,
`mvm-network-endpoint.rs`, and the corresponding test file). All backend
spawners (Firecracker, HVF, libkrun, QEMU) route to the single
`spawn_network_endpoint` site. `GuestService::NetworkFlow` (port 5253) is the
one declared vsock channel for workload networking.

`mvm-hostd::supervisor::flowmux` introduces `FlowMuxSession`, the host-side
authenticated FlowMux acceptor. It reuses the shared `mvm-core::net::session`
handshake, pins the guest identity against the plan's verifying key, and talks
the v1 FlowMux wire contract. Unit tests prove wrong anchors are rejected, the
handshake completes, `Hello`/`HelloAck` open the session, and an unimplemented
flow frame receives `GoAway` before the session closes cleanly.

`mvm-contract::protocol::network_flow::SessionValidator` gained
`mark_hello_ack_sent` so a host-side driver can advance its own state machine
after sending the ack; the validator still only observes inbound frames.

`mvm-hostd::supervisor::flowmux::registry` provides the per-session stream
registry: odd IDs for guest-initiated flows, even IDs for host-initiated
ingress, independent TCP/UDP ceilings, `Opening`/`Open`/`HalfClosed`/`Closed`
state transitions, and per-direction credit windows. It performs no I/O so it
is trivially unit-testable.

The `mvm-network-endpoint` binary now understands `EgressMode::FlowMux` and
`EndpointConfig::flowmux_identity`. The spawner
(`mvm-vmm::host::network_endpoint_spawn`) emits the identity JSON on stdin and
selects `flow_mux` mode when identity is present. The bin's `serve_flowmux`
accepts one UDS or vsock connection and runs the authenticated FlowMux session
in `spawn_blocking`.

### Phase 3 — Converge egress TCP, UDP, and DNS

- [x] Replace the raw `"host:port\n"` prelude with `OpenTcp`; return `Opened`
      only after a host connection succeeds, and return a typed refusal for
      policy, DNS, timeout, resource, and connection failures.
- [x] Move canonical host/port parsing, DNS resolution and pinning, mandatory
      range denial, redirect revalidation, `EgressGate`, byte accounting,
      connection rate limiting, and payload-free audit emission into one
      endpoint pipeline used by every outbound flow type.
- [x] Replace `MVM_DNS/1` and its line-sniffed dispatch with `Resolve` frames.
      Preserve QNAME/QTYPE/answer audit metadata, TTL bounds, rebinding checks,
      and direct-IP/domain-policy distinctions.
- [x] Replace `MVM_SOCKS5_UDP/1` and its private framing with `OpenUdp`,
      `UdpSend`, and `UdpRecv`. Preserve destination checks on every datagram,
      peer bounds, idle expiry, byte/rate limits, and silence-on-refusal toward
      the SOCKS client.
- [x] Adapt the guest loopback HTTP/SOCKS/DNS services to one FlowMux client and
      one reconnect owner. A session loss fails all live local flows promptly
      and reconnects under bounded exponential backoff without replaying an
      `Open`, request body, or datagram.
- [x] Delete `EgressMode`, `raw_egress`, protocol sniffing, duplicate line
      markers, and the raw-vs-wire admission choice. A workload with and without
      secret bindings uses the same protocol and endpoint.
- [x] Add integration tests for deny-all, allowed/denied TCP, truthful connect
      failure, DNS pinning/rebinding, UDP association/expiry, concurrent flows,
      half-close, cancellation, endpoint crash, and restart with a fresh boot
      identity.

### Phase 4 — Stream typed transformations over the same path

- [x] Replace `WireRequest`/`WireResponse` whole-body JSON/base64 exchange with
      `OpenHttp` plus bounded streaming head/body frames on FlowMux. Fold Plan
      313 Phase 1 into this work so long responses no longer buffer wholly or
      fail at a total-request 30-second deadline.
- [x] Route typed connector network execution through the endpoint. Broker
      dispatch retains binding authorization but cannot call `TcpStream::connect`,
      an HTTP client, or a resolver directly.
- [x] Apply destination-bound substitution only after final DNS/redirect
      admission and immediately before host TLS/request emission. Apply response
      redaction before each chunk crosses to the guest.
- [x] Carry transformation policy as an explicit admitted flow class. Refuse an
      opaque TCP/UDP request when the plan requires substitution, reversible
      replacement, or redaction; never silently downgrade it.
- [x] Preserve streaming boundaries through the inspector using a bounded
      overlap window large enough for the longest configured fingerprint, so a
      secret or PII token split across frames is still detected.
- [x] Add positive, negative, and boundary tests: valid substitution, wrong
      destination, unknown placeholder, redirect to an unbound host, split-frame
      secret, transformed streaming response, oversized head, body ceiling,
      idle timeout, audit redaction, and zeroized cleanup after cancellation.

### Phase 5 — Implement declared ingress on FlowMux

- [x] Move `L3IngressMapping` into a transport-neutral signed-plan and workload-
      IR type with protocol, exact host bind address, host port, guest loopback
      address/port, and transform class. Update Rust, Python, and TypeScript SDK
      serde fixtures and schemas together.
- [x] Make `mvm-network-endpoint` bind listeners only after plan admission and
      before reporting ready. Duplicate binds, wildcard binds not explicitly
      signed, unsupported protocols, and unavailable transform material refuse
      the launch.
- [x] Implement TCP ingress with even stream IDs: `InboundOpen` names only the
      admitted mapping ID and redacted peer metadata; the guest adapter connects
      to the declared loopback target and returns `InboundReady` before bytes
      flow.
- [x] Implement UDP ingress with one bounded peer table per declared mapping.
      Replies may target only a peer that previously sent a datagram to that
      mapping, preserving the existing no-UDP-egress-around-policy invariant.
- [x] Implement host-owned HTTP/TLS ingress transformation. Certificate keys
      are resolved by plan-bound secret reference inside the endpoint, never
      serialized to the guest; request redaction/replacement happens before
      guest delivery and response redaction happens before host transmission.
- [x] Support opaque TCP ingress through the same frames and endpoint, but mark
      it explicitly non-transforming. Admission refuses it whenever the mapping
      requires content transformation.
- [x] Remove the unused `mvm_core::ingress_broker` and `ingress_handler` model;
      no second listener process or policy type survives.
- [x] Add tests for exact/wildcard bind decisions, undeclared ports, TCP and UDP
      delivery, guest-local refusal, listener exhaustion, peer exhaustion,
      TLS-key non-disclosure, transformed request/response streaming, opaque-
      transform mismatch, audit metadata, and teardown releasing every socket.

### Phase 6 — Set the compatibility boundary without weakening isolation

- [x] Keep the loopback HTTP proxy, SOCKS5h, SOCKS5 UDP, controlled DNS stub,
      mediated ping helper, and typed SDK connectors as the supported guest
      compatibility surfaces; all terminate in the same FlowMux client.
- [x] Keep the Phase-0 `network.raw_ip_stack=true` rejection through the
      migration release. Do not silently reinterpret the declaration as
      FlowMux networking.
- [x] Remove `raw_ip_stack` from the Rust IR, Python/TypeScript SDKs, generated
      schemas, examples, documentation, and fixtures after the rejection release.
- [x] Close Plan 278 as rejected: do not set `DUMPABLE=1`, add `CAP_SYS_PTRACE`,
      read workload memory, or install seccomp user-notification for networking
      compatibility.
- [x] Document that a program which ignores the supported adapters has no
      network route and fails closed. Raw sockets, arbitrary IP protocols,
      custom in-guest resolvers, and general ICMP are unsupported rather than
      routed through a second stack.
- [x] Add BDD scenarios proving a proxy-aware application works, a typed
      connector transforms, and a non-cooperative direct socket cannot bypass
      FlowMux or reach the host network.

### Phase 7 — Delete L3 completely

- [x] Delete `mvm-contract::l3`, `NetworkMode`, `L3NetworkSpec`,
      `L3IngressMapping`, and every synthesis/admission branch that selects or
      validates an L3 mode.
- [x] Delete `mvm-net/src/l3/`, the L3 channel identities and leases that have
      no non-network consumer, and the L3-only fuzz targets.
- [x] Delete `mvm-agentd/src/l3/`, `mvm-net-agent`, guest `mvm0` setup, L3
      cmdline parsing, `CONFIG_TUN` workload-kernel requirement, and runtime
      overlay staging for the agent.
- [x] Delete `mvm-hostd/src/netd/`, the `mvm-netd` bin, Linux host-TUN/netns/
      nftables setup, the userspace smoltcp datapath, and L3 privileged tests.
- [x] Delete `mvm-vmm::host::netd_spawn`, network control/data VMM sockets,
      reaping/observability hooks, and backend teardown calls.
- [x] Remove smoltcp and every dependency that becomes unused; update
      `Cargo.lock`, `deny.toml`, closure-budget baselines, release packaging,
      Nix derivations, kernel configs, scripts, and CI path filters.
- [x] Remove `s25_l3_vsock` as a live product suite. Preserve only protocol-
      independent security scenarios by rewriting them against FlowMux; delete
      tests whose asserted capability is intentionally unsupported.
- [x] Run `cargo machete`, `cargo deny check`, `cargo audit`, and the duplicate-
      major/closure-budget gates; no L3-only dependency or binary may remain.

### Phase 8 — Make “one path” mechanically enforceable

- [x] Replace `check-uniform-vsock-egress` and `check-vsock-only-egress` with
      `check-single-network-path`. It must parse the workspace and assert:
      exactly one production network endpoint bin, exactly one production spawn
      implementation, every workload backend binds `NetworkFlow`, and no
      forbidden raw-packet/NIC/gateway symbols occur outside historical specs.
- [x] Add a socket-owner gate that permits outbound `connect` and workload
      listener `bind` only in the network endpoint and explicitly enumerated
      host infrastructure clients unrelated to workload networking. Test both a
      forbidden synthetic call and every narrow exemption.
- [x] Add a signed-plan projection test proving TCP, UDP, DNS, ingress, and typed
      connectors all reach the same canonical policy object and audit sink.
- [ ] Run the final `xtask network-perf` matrix against the Phase-1 legacy
      baselines. For opaque TCP/UDP, p50 and p95 latency may regress by at most
      5%, throughput must remain at least 95%, and peak RSS may not grow by more
      than 10%. Typed transformed HTTP may regress by at most 10% while gaining
      bounded streaming. Any exception requires measured root cause and owner
      approval in this plan before merge.
- [ ] Live-witness Firecracker on Linux/KVM and HVF on macOS; witness libkrun on
      every supported host OS. Each witness covers deny-all, admitted TCP, DNS,
      UDP, typed substitution, declared ingress, endpoint crash, no guest NIC,
      and absence of L3 services.
- [ ] Run `cargo test --workspace`, `cargo check --workspace`, host Clippy, and
      formatting on macOS. Run `cargo clippy --workspace --all-targets
    --all-features -- -D warnings`, Linux-gated tests, and the live KVM lane in
      the project builder VM.
- [ ] Update ADR-001's claim witnesses, `specs/SPRINT.md`,
      `specs/REFACTOR-STATUS.md`, public networking documentation, CLI help,
      schemas, release notes, and the plan checkboxes in the same final change.

## Definition of done

- [x] The source tree contains no production L3/raw-packet workload networking
      code and no second ingress or egress socket owner.
- [x] An admitted workload has either no `NetworkFlow` capability or exactly
      one authenticated FlowMux endpoint; there is no transport selector.
- [x] TCP, UDP, DNS, ingress, opaque relay, and typed transformations share one
      policy projection, resource budget, session identity, audit sink, and
      endpoint lifecycle.
- [x] Claims 5, 8, 10, 12, and 13 remain `Shipped`; preview claim 16 retains
      positive, negative, split-frame, wrong-destination, and audit-leak
      witnesses on the sole path.
- [ ] The performance gates and all repository tests are green on the required
      host and builder-VM lanes.

## Explicit non-goals

- No universal TLS interception CA and no attempt to defeat certificate
  pinning, QUIC, or ECH.
- No raw sockets, arbitrary IP protocols, custom in-guest resolver path, or
  general ICMP compatibility for production workloads.
- No guest NIC, host bridge, TAP, slirp, passt, vpnkit, or backend-specific
  networking fallback.
- No weakening of `PR_SET_DUMPABLE`, ptrace isolation, capability bounding,
  seccomp, Landlock, or the read-only workload rootfs to improve application
  compatibility.
- No second endpoint retained as a dev/test escape hatch. Hermetic protocol
  doubles are allowed; a real alternate network implementation is not.

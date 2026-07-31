# ADR-035 — L3 TUN-over-vsock, an opt-in compatibility network mode

**Status: Accepted**
**Date: 2026-07-31**
**Supersedes: nothing. Complements ADR-003 (cross-platform backends),
ADR-014 (signed/audited execution plans), ADR-020 (host-services broker),
ADR-023 (secrets subsystem / egress substitution), plan 278 (transparent
connect interception).**

## Context

A workload microVM has no NIC. Every byte a guest sends leaves over
AF_VSOCK to a host-side endpoint that originates the real connection.
That is what makes claim 10 (default-deny egress), claim 13 (no raw
secret reaches the guest), and the chain-signed audit log enforceable:
the host, not the guest, is the party that opens sockets.

The consequence is an application-compatibility wall. `mvm-core`'s
`guest_netd` points a workload at a SOCKS5h proxy on `127.0.0.1:1080`
and a DNS stub on `127.0.0.1:53` via the standard proxy environment
variables. Applications that honour `ALL_PROXY`/`HTTP_PROXY` work.
Applications that do not — statically linked binaries, Go programs with
their own dialer, anything issuing raw syscalls, anything that wants
ICMP, anything that runs its own resolver — get nothing, because there
is no route to anywhere.

Plan 278 closes part of that gap cooperatively, by intercepting
`connect(2)` with a seccomp user-notification listener and redirecting
the fd. That works for socket-API workloads and keeps the socket-aware
security properties intact. It does not help a workload that wants a
real IP stack: raw sockets, non-TCP/UDP protocols, in-guest routing
decisions, traceroute, or a userspace TCP implementation.

This ADR adds the other half: an **opt-in L3 tunnel** that gives such a
workload a normal Linux IP interface while keeping every packet inside
the vsock trust boundary.

## Decision

Add a third, explicitly-admitted network mode — `l3-vsock` — in which
the guest gets a point-to-point **TUN** interface named `mvm0`, and the
guest agent forwards raw IP packets, one per framed vsock message, to a
host-side machine-scoped gateway that applies policy before anything
touches host networking.

```
guest application
      │
guest TCP/IP stack
      │
   mvm0  (IFF_TUN | IFF_NO_PI, point-to-point, no L2)
      │
mvm-net-agent  (in-guest, unprivileged after setup)
      │
raw IPv4/IPv6 packets, framed over AF_VSOCK
      │
mvm-netd  (host, machine-scoped, one per VM session)
      │
policy · anti-spoof · flow state · DNS · ingress · NAT · audit
      │
host networking
```

The managed socket-aware vsock mode (`host-vsock-proxy`) remains the
**default and the preferred mode**. `l3-vsock` is a compatibility mode
that trades application-layer visibility for IP-stack fidelity, and the
plan records which one was admitted.

## Why TUN over vsock, and not the alternatives

**Why not a virtio-net device.** A NIC gives the guest a direct path to
a host bridge or TAP. That deletes the property the whole posture rests
on — that the host originates every flow — and re-introduces an L2
broadcast domain the host must then police. The in-house HVF backend
deliberately exposes no NIC at all (ADR-014, `project_vsock_only_auditable_data_plane`);
adding one for this mode would fork the backend contract.

**Why not extend the existing control RPC.** The guest agent's vsock
protocol on port 5252 carries machine control: exec, fs, health,
lifecycle. Multiplexing bulk packet traffic onto it would couple packet
backpressure to control-plane liveness — a guest that saturates its
uplink would starve its own health checks and the host's shutdown path.
Constraint 2 of this design is a hard separation: packets get their own
vsock ports and their own connections.

**Why L3 and not L2 (TAP).** An Ethernet device would require the host
to answer ARP, run a DHCP server or equivalent, and police broadcast and
multicast for a link with exactly two endpoints. All of that is pure
attack surface for a point-to-point link. `IFF_TUN | IFF_NO_PI` gives
the guest kernel a normal routed interface with none of it: no MAC, no
ARP, no DHCP, no bridge, no broadcast domain. The guest's own stack does
TCP; we carry IP.

**Why not an existing proxy runtime.** `gvproxy`, `passt`/`pasta`,
`slirp`, `vpnkit`, and QEMU user networking all terminate guest flows in
a process that knows nothing about mvm's signed plans, policy epochs, or
chain-signed audit log. Bolting one in would mean a second, unaudited
policy engine. The gateway here is an mvm component that consumes the
same `CanonicalEgress` projection nftables and the socket-aware gate
already consume, and emits into the same audit chain.

**Why not TLS interception.** L3 mode sees packets. Once a guest
encrypts, the payload is opaque. We do not add a transparent MITM to
recover visibility: it would require distributing a host CA into the
guest trust store, which is a larger and worse security change than the
one this ADR makes. The honest consequence is a documented capability
difference (below), not a hidden one.

## Protocol

A small binary protocol, deliberately not a general object
deserializer. It lives in `mvm-protocol` (`#![no_std]` + alloc,
`forbid(unsafe_code)`) so guest and host share exactly one
implementation and so it is trivially fuzzable.

### Outer framing

Stream-safe, length-prefixed:

```text
u32  frame_length            big-endian; bytes that follow, header + payload
     ├── fixed header (24 bytes)
     └── payload (frame_length - header_len bytes)
```

### Fixed header (24 bytes, big-endian)

| Offset | Size | Field         | Notes                                      |
|-------:|-----:|---------------|--------------------------------------------|
| 0      | 4    | `magic`       | `b"MVL3"`                                  |
| 4      | 1    | `version`     | major; v1 = 1. Unknown major → reject      |
| 5      | 1    | `msg_type`    | see below                                  |
| 6      | 2    | `flags`       | reserved, must be 0 in v1                  |
| 8      | 2    | `header_len`  | 24 in v1; a larger value is a v2 extension |
| 10     | 2    | `reserved`    | must be 0                                  |
| 12     | 8    | `session_id`  | host-assigned; 0 only on `HELLO`           |
| 20     | 2    | `queue_id`    | v1: 0                                      |
| 22     | 2    | `payload_len` | must equal `frame_length - header_len`     |

`payload_len` is `u16`, so the protocol can never be asked to allocate
more than 64 KiB even before the tighter `MAX_PAYLOAD_LEN` check. The
`queue_id` field exists in v1 so multi-queue negotiation later is a
feature bit, not an incompatible rewrite.

### Message types

| Value | Name        | Direction   | Payload                                          |
|------:|-------------|-------------|--------------------------------------------------|
| 0x01  | `HELLO`     | guest→host  | version, requested features, max queues          |
| 0x02  | `CONFIG`    | host→guest  | session, addresses, MTU, routes, DNS, epoch      |
| 0x03  | `READY`     | guest→host  | echoes session + epoch; interface is up          |
| 0x04  | `PACKET`    | both        | exactly one complete IP packet                   |
| 0x05  | `HEARTBEAT` | both        | monotonic counter                                |
| 0x06  | `SHUTDOWN`  | both        | reason code                                      |
| 0x07  | `ERROR`     | both        | code + bounded (≤128 B) ASCII detail             |

Every payload has a fixed binary layout with explicit endianness. There
is no JSON, no CBOR, and no self-describing container on the data path.

### v1 constants

- MTU: **1500**. Chosen because it is what the overwhelming majority of
  host paths carry without fragmentation, and because a guest that sees
  1500 needs no unusual configuration. TCP MSS is clamped by the gateway
  so ordinary flows never fragment.
- One data queue.
- No segmentation/offload metadata, and no virtio-net header. A
  `PACKET` payload is the IP packet and nothing else.
- `MAX_PAYLOAD_LEN` = 2048, so `MAX_FRAME_LEN` = 2072. Control messages
  fit comfortably; packets are additionally capped at the negotiated
  MTU.

### Framing invariants (all fail closed, all fuzzed)

- unknown major version → reject the connection, do not negotiate down;
- `frame_length` > `MAX_FRAME_LEN` → reject **before** allocating;
- `header_len` < 24, or `header_len` > `frame_length` → reject;
- `payload_len` ≠ `frame_length - header_len` → reject;
- `magic` mismatch → reject;
- non-zero `flags`/`reserved` in v1 → reject;
- `PACKET` shorter than the minimum IPv4 (20 B) or IPv6 (40 B) header,
  or longer than the negotiated MTU → drop and count;
- a `session_id` that is not the current session → drop and audit.

We build nothing above the vsock stream. Vsock is reliable and ordered;
adding retransmission or sequencing would duplicate the guest's TCP.

## Identity and session binding

Machine identity is **structural, never guest-asserted**.

Each VM's supervisor owns its own per-VM vsock listener sockets
(`mvm_core::config::vm_vsock_port_socket` on libkrun/Firecracker,
`vm_hvf_vsock_port_socket` on HVF). A connection arriving on that socket
is by construction from that VM; there is no shared listener where a
guest could claim to be another machine. Where the backend exposes the
peer CID, it is recorded in audit as corroboration — not as the
authorization input.

`HELLO` carries no machine ID. The host mints a random 64-bit
`session_id` per boot, returns it in `CONFIG`, and thereafter:

- the data connection must present the current `session_id`;
- a frame with any other session is dropped and audited;
- machine stop, restart, restore, and snapshot-resume all invalidate the
  session, its address lease, its flow table, its DNS bindings, and its
  ingress mappings.

There is no reconnect onto a stale session. A guest that loses the
transport gets networking marked unavailable and may only re-enter
through a fresh host-approved session.

## Guest configuration

The host assigns everything. The guest chooses nothing:

- IPv4 address and point-to-point peer (the synthetic gateway);
- MTU;
- default route;
- synthetic DNS resolver address;
- session ID and policy epoch;
- negotiated queue count and feature bits.

The agent configures `mvm0` with `TUNSETIFF` plus direct `SIOCSIFADDR` /
`SIOCSIFDSTADDR` / `SIOCSIFMTU` / `SIOCSIFFLAGS` / `SIOCADDRT` ioctls and
raw `AF_NETLINK` for the deny routes — the same synchronous, tokio-free
approach `mvm-agentd/src/netinit.rs` already uses. It depends on no
in-guest utility: not `ip`, not `ifconfig`, not `ethtool`, not
NetworkManager, not systemd-networkd. Minimal, distroless, and scratch
images all work.

After the TUN fd is open and routes are installed, the agent drops
`CAP_NET_ADMIN` and every other capability from all five sets, clears
the bounding set, and sets `PR_SET_NO_NEW_PRIVS`. The workload therefore
cannot reconfigure `mvm0`, create interfaces, or alter routes.

**IPv6.** The workload kernel ships `CONFIG_IPV6=n`
(`nix/images/kernel/base.nix`). v1 therefore assigns IPv4 only. The
protocol reserves the v6 fields and the host validator parses and
policices IPv6 fully — including extension-header chain bounds — so a
guest that manufactures IPv6 packets is rejected rather than
mis-handled, and enabling the kernel option later needs no wire change.

## Host gateway

`mvm-netd` — `crates/mvm-hostd/src/netd/`, with a thin `[[bin]]` — is
machine-scoped, not a general packet forwarder. It reuses the
supervisor's existing lifecycle, audit recorder, and plan admission
rather than growing a parallel set.

Per VM it: binds the session, validates every frame and every IP packet,
enforces anti-spoofing, applies the plan's egress and ingress policy,
serves DNS, forwards admitted packets through a platform datapath,
returns admitted reply packets to the right session, maintains bounded
flow state, emits audit and metrics, and deletes everything when the
machine exits.

Policy is not re-implemented. Admission consults the same
`mvm_core::policy::projection::CanonicalEgress` that nftables and the
socket-aware `EgressGate` consume, so `--allow-host api.example.com:443`
means exactly one thing across every enforcement point.

### Platform seam

```rust
trait L3Datapath {
    fn open(&self, req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError>;
}
trait DatapathHandle {
    fn send_to_network(&self, packet: &[u8]) -> Result<(), DatapathError>;
    fn recv_from_network(&self, buf: &mut [u8]) -> Result<usize, DatapathError>;
    fn close(self: Box<Self>) -> Result<(), DatapathError>;
}
```

Userspace admission always runs before `send_to_network` and after
`recv_from_network`. No platform routing rule may bypass it; the
kernel-level rules are defence in depth, never the only check.

### Linux

- an mvm-owned host TUN device per machine;
- a per-machine network namespace holding it, so routes and rules cannot
  leak into the host's main table;
- narrowly scoped routes for exactly the machine's /30;
- nftables for NAT plus a default-drop filter, applied through the
  existing `NftApplier` seam with slug-validated identifiers;
- **no** host bridge, **no** Firecracker TAP, **no** Firecracker network
  device. Firecracker continues to expose only vsock for this mode. The
  guest's `mvm0` is unrelated to Firecracker's TAP-backed virtio-net
  support, which this mode does not use.

Teardown is deterministic and idempotent: namespace, TUN, routes,
nftables table, and listeners are removed on stop and on failed startup
alike.

### macOS

The platform-neutral core — protocol, session, policy, DNS, flow state,
ingress, audit — is shared. The macOS datapath is **not** shipped in
this change. The `darwin` backend is present and fails closed with a
named error; `l3-vsock` is refused at admission on macOS rather than
silently degraded, and it is never selected by auto-detection.

The exact missing privileged operations are:

1. `utun` interface creation — `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` +
   `connect()` with `ctl_info` for `com.apple.net.utun_control`. Requires
   root; there is no entitlement that grants it to an unprivileged process.
2. Interface address/MTU configuration — `SIOCAIFADDR` / `SIOCSIFMTU` on
   the utun. Requires root.
3. Route installation/removal scoped to the utun — `PF_ROUTE` socket
   writes. Requires root.
4. PF anchor management — loading and flushing rules in an mvm-owned
   anchor (`pfctl -a mvm/<machine>`), plus enabling PF if disabled.
   Requires root.

mvm has no privileged host helper today. Adding one is a separate,
narrowly-scoped change: a helper whose API is exactly the four
operations above plus status and deterministic cleanup, with **no**
arbitrary command execution, **no** arbitrary PF rule insertion, and
**no** file access. It must be authenticated to the calling supervisor
and must refuse operations for machines that supervisor does not own.
That helper is out of scope here and is tracked in plan 279 §macOS.

We do not route macOS through `gvproxy` or any other proxy runtime as an
interim measure.

## Policy

Every packet is treated as hostile. On the guest→host direction the
gateway validates IP version, header length, total length, source,
destination, transport protocol, ports, extension headers,
address class, fragmentation, and session ownership — in that order,
before any of it reaches a datapath.

**Anti-spoofing.** The source address must equal the address the host
assigned to this session. A guest cannot impersonate another machine,
the host, loopback, multicast, or broadcast.

**Default-deny destinations**, beyond the plan's allowlist:
`MANDATORY_DENY_RANGES` (cloud metadata `169.254.169.254/32`,
link-local, CGNAT, loopback, IPv6 loopback and link-local), multicast,
broadcast, this-network `0.0.0.0/8`, benchmarking, documentation,
reserved, and **RFC1918 private ranges**. `MANDATORY_DENY_RANGES` does
not include RFC1918 — for the socket-aware path the host's own resolver
and connect logic bound the exposure — so L3 mode adds a private-range
default-deny of its own, opened only by an explicit CIDR rule in the
plan. "Private" is not "safe".

**Fragmentation.** v1 rejects IP fragments rather than implementing
reassembly, which is the classic unbounded-state sink. TCP MSS is
clamped so the configured MTU does not provoke routine fragmentation.
The ICMP and ICMPv6 types needed for path-MTU discovery and ordinary
error signalling are permitted; echo request/reply are permitted only to
admitted destinations. IPv6 extension-header traversal is bounded in
both chain length and total header bytes, and a malformed or excessive
chain is rejected.

**Stateful return traffic.** A reply is admitted only against an
existing outbound flow, or a declared ingress mapping. Unsolicited
inbound is dropped. Flow entries are bounded per VM, expire on idle, and
table exhaustion is audited and counted rather than silently growing.

## DNS

Domain allowlists cannot be enforced by permitting arbitrary DNS and
then arbitrary IP connections — the guest simply resolves elsewhere.
So in L3 mode:

- the guest is configured with a synthetic mvm resolver address (the
  gateway's own address);
- UDP/53 and TCP/53 to that address are terminated by the gateway;
- DNS to any other destination is denied unless the plan explicitly
  admits it;
- names are resolved by the host-controlled resolver, and domain policy
  is applied before any answer is returned;
- returned addresses are pinned to (domain, ports, VM session, policy
  epoch) with a bounded TTL, reusing `DnsPin`/`DnsPinRegistry`;
- a subsequent packet is admitted only if its destination matches a
  live binding for an admitted name, or an explicit IP/CIDR rule;
- answers that would rebind into loopback, link-local, metadata,
  management, or private ranges are rejected unless the plan admits
  those ranges, reusing `dns_guard::dns_answer_forbidden`;
- outstanding queries, response size, alias-chain length, and cached
  record count are all bounded.

TLS SNI is **not** used as an authorization input. It may be absent or
encrypted, and relying on it would push us toward interception.

## Ingress

Ingress mappings are declared in the signed plan and opened by the same
gateway:

```text
host listen address:port  →  machine address:guest port
```

No undeclared listener is ever opened. Wildcard binds require explicit
admission. Bind conflicts are reported by name and port rather than
being retried. Inbound connections are routed only to the session that
declared them, are byte- and connection-accounted, and every listener is
closed on machine stop, so a restart cannot inherit a stale mapping.
TCP is implemented in this change. **UDP ingress is not** — it is an
explicit follow-up in plan 279, not a claimed feature.

## Resource bounds

A malicious guest controls every byte arriving from the TUN device.
Therefore: fixed maximum frame size; fixed v1 MTU; bounded queues in
both directions with a documented tail-drop policy; bounded flow tables
with per-VM caps and idle expiry; bounded DNS state; connection and idle
timeouts; token-bucket rate limits; preallocated per-connection packet
buffers; no unbounded deserialization; and no per-packet heap allocation
after initialization on the steady-state path.

Drops are counted, not logged per packet. Audit records the *decision
classes* and their counters, never a line per packet.

## Audit and observability

Events go into the existing chain-signed log via the supervisor's
recorder. New `LocalAuditKind` variants cover: tunnel requested,
connected, configured, ready, disconnected; DNS admitted/denied; flow
admitted/denied/closed; ingress opened/closed; malformed frame; spoofed
packet; queue overflow; rate-limit action; and resource cleanup.

Entries carry machine ID, session ID, plan digest, policy rule ID,
policy epoch, protocol version, the address/port tuple, direction,
reason code, and byte/packet counts.

Entries never carry packet payloads, DNS payloads beyond normalized
metadata, authorization headers, secrets, or application content.

## Security guarantees

L3 mode **does** guarantee:

- the guest has no direct host NIC, and none is created for this mode;
- every guest IP packet crosses the vsock boundary and is admitted by
  the host before touching host networking;
- source anti-spoofing against the host-assigned address;
- signed-plan destination and port enforcement, via the same canonical
  projection as every other enforcement point;
- host-controlled DNS, so domain rules mean something;
- stateful return-flow enforcement; unsolicited inbound is dropped;
- declared-only ingress;
- bounded resource usage under a hostile guest;
- machine attribution and auditability of every policy decision;
- no silent fallback to another networking mode, ever.

L3 mode **does not** claim:

- visibility into encrypted application payloads;
- hostname identification independent of the controlled resolver;
- transparent secret substitution inside arbitrary TLS — this is the
  central capability difference against ADR-023's owned-cleartext path;
- application-level HTTP policy without an explicit owned proxy;
- Ethernet or raw Layer-2 compatibility;
- parity with virtio-net offload performance.

## Capability difference between the modes

| Capability | `host-vsock-proxy` (managed) | `l3-vsock` |
|---|---|---|
| Connection intent (host:port as the app asked) | yes | only via controlled DNS |
| Owned-cleartext secret substitution (ADR-023) | yes | **no** |
| Cleartext PII redaction on owned paths | yes | **no** |
| L7 (HTTP/SNI) policy | yes, where owned | **no** |
| Packet/flow/port/destination policy | yes | yes |
| Controlled DNS + domain allowlists | yes | yes |
| Declared ingress | yes | yes |
| Raw sockets, ICMP, non-TCP/UDP protocols | **no** | yes |
| Works without proxy-env cooperation | partly (plan 278) | yes |
| Guest sees a normal IP interface | no | yes |

The managed mode remains preferred whenever the workload is compatible
with it. Selecting `l3-vsock` is an explicit, audited decision to give
up the first four rows.

## Failure behaviour

If the tunnel cannot be established, configured, bound to the machine
session, or admitted by the signed plan, networking is unavailable and
the machine is told so. If an established tunnel disconnects, the guest
agent marks `mvm0` down; there is no fallback to a NIC, to host
networking, or to the managed mode. Startup failure tears down partial
state on the same path as normal stop.

## Consequences

- One more admitted network mode to reason about, and one more
  enforcement path to keep in sync with `CanonicalEgress`. Mitigated by
  sharing the projection rather than re-deriving rules.
- A new in-guest binary in the closure for images that opt in. It is
  cfg-gated to Linux and is not baked into images that do not select the
  mode.
- `CONFIG_TUN` joins the workload kernel. It is a small, well-audited
  driver and is required for the mode; it stays out of the builder
  kernel.
- macOS gains no L3 support in this change, and says so explicitly
  rather than degrading.

## Future work

- Multi-queue: negotiate `queue_count` in `HELLO`/`CONFIG`, open one
  vsock connection per queue at `L3_DATA_PORT_BASE + q`, and hash each
  packet's flow tuple to a stable queue so ordering within a flow is
  preserved. The header field and negotiation slots exist in v1.
- UDP ingress.
- macOS `utun` + PF datapath, behind a narrowly-scoped privileged helper.
- IPv6 datapath, once the workload kernel enables it.
- Zero-copy or batched packet transfer, if measurement justifies it.

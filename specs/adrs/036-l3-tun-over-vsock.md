# ADR-036 — L3 TUN-over-vsock, an opt-in compatibility network mode

**Status: Superseded for production workload networking by ADR-042
(2026-08-11).**
**Date: 2026-07-31**
**Superseded by: ADR-042 (one flow-aware vsock networking path). The
`l3-vsock` mode this ADR introduced is leaving the production workload path;
new `raw_ip_stack=true` / `NetworkMode::L3Vsock` launches are refused. The
measurements, threat analysis, and compatibility-wall reasoning below remain
accurate history, and are why ADR-042 states an explicit compatibility
ceiling rather than pretending the wall does not exist. Nothing below
describes a live production transport. The staged removal is
`specs/plans/316-single-flow-vsock-networking.md`.**
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

There is no operator-facing mode selector. The transport follows from one
property of the workload — whether it needs a real in-guest IP stack —
declared as `network.raw_ip_stack` in its manifest. Workloads that do not
declare it get the socket-aware path, which is the default and the stronger
posture; those that do get the tunnel.

Two properties fall out of deriving it this way, and both were mistakes we
made first:

- **Host capability is not an input.** An earlier cut folded "can this host
  serve the tunnel" into the derivation. It is a safe direction — it can
  only add host visibility — but it makes one plan mean different things in
  different places, and gives the same workload a different plan digest on
  macOS than on Linux. Host capability is now an admission *check*: a
  workload that needs the tunnel is refused on a host without one, and
  everything else runs.
- **The tunnel is not the default.** Making it the default inverted the
  design: L3 is a compatibility mode that gives up substitution, so it
  should be reached for by workloads that need it, never landed on by
  accident.

The mode remains in the *signed plan* — it is the admitted contract, and a
control plane sets it — but it is not something an operator picks.

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

**Why not an existing proxy runtime.** The userspace gateway runtimes —
`slirp`, `vpnkit`, QEMU user networking and their kin — all terminate guest flows in
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
deserializer. It lives in `mvm-contract` (`#![no_std]` + alloc,
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

### macOS (Apple Silicon)

The platform-neutral core — protocol, session, identity, lease, policy,
DNS, flow state, ingress, audit — is shared unchanged. The Linux
TUN/netns/nftables mechanics are **not** portable to macOS and are not
pretended to be.

The macOS backend is a **userspace socket gateway**: admitted guest flows
are translated into host sockets. That needs no privileges at all — no
`utun`, no routes, no PF anchor, no helper — and covers ordinary
application TCP, UDP, and host-terminated DNS. It does not cover raw
sockets, arbitrary IP protocols, arbitrary ICMP, or multicast, and it does
not claim to.

**Status: superseded in part by [ADR-052](052-userspace-socket-datapath.md),
which designs the translator and widens it from a macOS-only backend to a
platform-neutral unprivileged one.** What shipped with *this* ADR was a
placeholder, `MacosUserspaceGateway` — a capability declaration plus a
refusal at `is_available()`, so that `l3-vsock` on macOS was refused at
admission with a stated reason rather than degraded or routed through
a userspace gateway.

That placeholder is **deleted**. `host_datapath()` now returns
`UserspaceSocketDatapath`, which serves the flows the declaration always
described: it reports `tcp`, `udp`, `controlled_dns`, `declared_ingress`
and `userspace_socket_translation`, and **not** `full_packet_forwarding`,
`icmp`, `arbitrary_ipv4`, `arbitrary_ipv6` or `raw_ip_protocols`. A plan
needing one of those is still refused at admission, and now permanently: it
would take the privileged helper enumerated below, and
[ADR-039](039-macos-network-helper.md), which proposed that helper, is
**Rejected** — mvm adds no root-capable component. Two things the
declaration claims are not yet true of the datapath behind it: declared
ingress is advertised with no listening socket serving it, and the
readiness descriptor it exposes has nothing registered on it, so
host-originated traffic moves on the drive loop's 50 ms tick rather than on
the event that made it ready. Both are recorded in ADR-052 §"Known defects
in what shipped".

The later full-packet backend would need privileged operations mvm has no
helper for, and — per ADR-039 — will not be getting one:

1. `utun` creation — `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` +
   `connect()` with `ctl_info` for `com.apple.net.utun_control`. Root; no
   entitlement grants it unprivileged.
2. Address/MTU configuration — `SIOCAIFADDR` / `SIOCSIFMTU`. Root.
3. Route installation/removal scoped to the utun — `PF_ROUTE` writes. Root.
4. PF anchor management — loading and flushing an mvm-owned anchor
   (`pfctl -a mvm/<machine>`), and enabling PF if disabled. Root.

A helper for those must expose exactly those four operations plus status
and deterministic cleanup: no arbitrary command execution, no arbitrary PF
rules, no arbitrary routes, no arbitrary files, no arbitrary interfaces. It
must authenticate to the calling supervisor and refuse machines that
supervisor does not own.

The HVF backend continues to expose no guest NIC either way, and its
virtio-vsock terminates into an mvm-owned host stream.

### WSL2

WSL2 is a **Linux execution node**, not a native Windows backend. When mvm
runs inside WSL2 with nested KVM, the guest's vsock terminates inside the
WSL Linux environment, `mvm-netd` runs there, and the Linux forwarding
backend is used. Windows sits entirely outside the guest/vsock boundary and
needs no protocol change.

**Status: architecturally supported, not validated.** Nothing in the
protocol or the backend abstraction is Windows-aware, which is what makes
this work; but no WSL2 runner has executed the suite, so it is not claimed
as tested.

### Native Windows

**Not supported.** mvm has no native Windows VMM backend, so there is
nothing for a Windows forwarding adapter to attach to. The portable types
are kept free of Linux assumptions so a future adapter is possible, and the
likely mapping is:

```text
Linux guest AF_VSOCK
  → Hyper-V socket transport
  → Windows host AF_HYPERV
  → Windows mvm-netd transport adapter
  → userspace socket gateway or WFP/packet backend
```

Native Windows would require a Windows-capable hypervisor backend, Hyper-V
socket service registration and machine identity, a Windows forwarding
implementation, Windows lifecycle and cleanup, and native live tests. None
exist. "Works on Windows" in this document always means WSL2.

## The guest channel, and why the endpoint is not the identity

A guest always speaks AF_VSOCK. What the host holds varies by VMM:

| VMM | Host-facing endpoint |
|---|---|
| Firecracker | per-port Unix socket (the VMM's termination of the guest's virtio-vsock connection) |
| libkrun | per-port Unix socket |
| in-house HVF | an mvm-owned stream |
| QEMU | a real AF_VSOCK socket |
| future Windows | AF_HYPERV service |

All five are the same fact — the host end of a guest vsock connection — and
`mvm_net::channel::GuestChannelProvider` normalizes them behind typed
`GuestService` values (`MachineControl`, `NetworkControl`,
`NetworkData { queue }`, `WorkloadExit`, `Broker`, `Substitution`). Nothing
above that abstraction sees a path, a CID, or a port.

**"Complete host control over vsock" does not mean reimplementing
virtio-vsock.** The VMM implements the transport; mvm owns the host-facing
service endpoint and every application-level byte — whether the VM gets a
vsock device at all, the service-to-endpoint mapping, listener creation,
connection acceptance, per-boot authentication, limits, policy, audit
attribution, shutdown, revocation, and cleanup. That is the whole
authorization surface, and it is entirely ours.

**Why a CID is not enough.** CIDs, UDS paths, and service ports are all
reusable across boots. Authorizing on one would let a restarted machine —
or a later machine that inherited the number — present as its predecessor.
So authorization binds to `VmInstanceIdentity { node_id, vm_id, boot_id,
plan_digest }`, minted by the host per boot, and every networking
connection is bound to that plus a per-boot session nonce, the admitted
plan digest, the policy epoch, and the active lease. A guest can select
none of them: `HELLO` carries a version, feature bits, and a queue count,
and nothing else.

## The network lease

`mvm_net::lease::NetworkLease` is one signed grant of network identity for
one VM boot. A standalone `mvmctl` mints one through
`LocalLeaseAuthority`; a control plane will later issue one centrally. The
node-local data plane verifies the same object either way, so there is one
networking model rather than a local one and a cluster one.

A lease is bound to one boot (`boot_id`), one node, one plan digest, and
one policy epoch, inside a validity window. Verification order is version,
signature, identity binding, then validity — nothing about the grant is
read before the signature is confirmed. Every failure denies the whole
lease.

**Control-plane loss** never opens anything up. `ControlPlaneLossPolicy`
chooses only how fast an already-admitted workload loses what it had:
hold-existing-deny-new (the default), hold-until-expiry, or
deny-immediately. After expiry, all three deny.

## Local versus central responsibility

A control plane authorizes and programs; it does not carry packets.

| Central (future `mvmd`) | Node-local (`mvm-hostd` / `mvm-netd`) |
|---|---|
| VM network identity, address allocation, DNS naming | the backend vsock/UDS/HVF listener |
| placement, allowed routes, ingress declarations | binding a channel to the local boot |
| egress policy, policy epochs | packet validation, anti-spoofing |
| lease issuance and expiry | local flow state, DNS termination |
| service discovery, inter-node routing metadata | local ingress listeners, host forwarding |
| audit aggregation | backpressure, fail-closed, immediate teardown |

## Cross-node traffic

AF_VSOCK is never stretched between machines. Each node terminates its own
guests' vsock locally, and node-to-node traffic rides a separate,
authenticated transport:

```text
VM A → local vsock → Node A mvm-netd
     → authenticated node-to-node transport
     → Node B mvm-netd → local vsock → VM B
```

The guest cannot tell whether a destination VM is local or remote. Source
and destination VM identity, tenant isolation, lease and route
authorization, hop identity, and flow audit correlation all survive the
hop. The node-to-node transport is a separate abstraction and is **not
implemented**; the local implementation does not depend on it.

[ADR-040](040-node-to-node-transport.md) designs that transport and
records why it stays unimplemented. Three of the paragraph above's
promises are not currently keepable, and none of the three is fixable
inside a transport: "the guest cannot tell whether a destination is local
or remote" is unachievable while `PoolAllocator` gives two nodes the same
addresses, since the two cases are then indistinguishable from the packet;
destination-side authorization needs a policy language that can name a
peer workload, which `CanonicalRule` cannot and `IngressTable` has no
source for; and "flow audit correlation" presumes a local audit record
that `netd` does not yet produce. ADR-040 carries the design, the
alternatives it rejects, and the four conditions that unblock it.

## Launch-path convergence

Audited paths and their status:

| Path | Guest NIC | Status |
|---|---|---|
| `machine run` transient | none | converged |
| `machine run`/`start` persistent | none | converged |
| Firecracker workload driver (`driver/fc.rs`) | none — no `/network-interfaces` PUT at all | converged |
| `mvm-hostd` supervisor launch | none | converged (same `VmStartConfig`) |
| warm restore / fork (`vm/instance_snapshot.rs`) | refused — a non-empty `network-interfaces` list on restore is a hard failure | converged |
| libkrun | attaches a drained virtio-net | **advertises `l3_vsock: false`**, so `l3-vsock` cannot select it |
| QEMU dev/test | n/a | does not advertise `l3_vsock` |
| builder VM (`mvm-build/src/firecracker.rs`) | TAP NIC | **not a workload path** — the Nix build engine, carries no untrusted workload |

The invariant is structural rather than conventional in two places: the
backend-neutral `VmStartConfig` has **no** guest network-device field at all
(regression-gated by
`machine::nic_guard::tests::the_launch_specification_has_no_guest_network_device_field`),
and `machine::nic_guard::enforce_no_guest_nic` refuses an `l3-vsock` launch
on any backend that does not advertise both `l3_vsock` and
`no_routable_guest_nic`.

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
explicit follow-up in plan 285, not a claimed feature.

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

Decisions go onto the existing chain-signed per-tenant log through the
supervisor's `Recorder`, under a new `EventCategory::L3` — the same
plan-less route `icmp` and `dns` take, and for the same reason: the
gateway is a per-machine process holding a plan *digest* rather than an
`ExecutionPlan`, and the `flow` category is mandatorily plan-bound.

The `LocalAuditKind::L3*` variants are **not** this path. They belong to
the unsigned local operations log at `<mvm_home>/log/audit.jsonl`; the
tamper-evident record is `<mvm_home>/audit/<tenant>.jsonl`, and that is
the one this gateway writes.

Served today, one event name each:

| Event | From |
|---|---|
| `l3.tunnel_ready` | the handshake completing |
| `l3.tunnel_disconnected` | teardown, carrying what never reached the chain |
| `l3.flow_admitted` | the first packet of a flow to a destination |
| `l3.flow_denied` | a refused guest packet, with its reason code |
| `l3.ingress_delivered` | the first return packet admitted from a remote |
| `l3.ingress_denied` | a refused inbound packet, with its reason code |
| `l3.dns_admitted` | an answered question, with the answer *count* |
| `l3.dns_denied` | a refused question, with its reason |
| `l3.malformed_frame` | a framing violation that ends the tunnel |
| `l3.stale_session` | a frame carrying a session that is not the live one |
| `l3.queue_overflow` | a packet dropped because a queue was full |
| `l3.rate_limited` | the DNS rate limiter refusing a query |

A spoofed-source packet is `l3.flow_denied` with `reason=spoofed_source`
rather than an event of its own — the deny code already names it.

**Not served, and why.** Tunnel *requested*, *connected*, and *configured*
have no call site: the handshake produces a single `GatewayEvent`, at
`ready`. Flow *closed* has none either — idle flows are reaped on a timer
that returns a count rather than events. Ingress *opened* and *closed*
likewise: the declared-ingress table is fixed at configuration time and
its lifetime produces no event. Each would need a gateway change to
surface, and inventing an entry with no decision behind it would put a
fact on the chain that nothing observed.

Every entry carries machine ID, session ID, plan digest, policy epoch,
and protocol version. Decision entries add the address/port tuple,
direction, verdict, and reason code. **No policy rule ID and no
byte/packet counts** — neither is on a `GatewayEvent`, and volume is a
counter rather than an audit fact.

### One entry per decision, never one per packet

`GatewayEvent` is per packet. An entry per packet would be a write
amplifier into the host's audit log that a guest drives at line rate, so
repeats fold into the first entry for their bucket and the fold is
counted. Two dedup tables: one keyed only on host-defined enumerations
(deny reason, direction), one on guest-chosen values (destination, DNS
name) and capped. A decision that cannot get a bucket in the capped table
degrades to its class key rather than going unrecorded — **granularity
gives way under pressure, the record does not**.

Those caps are the whole rate bound: a bucket emits at most once per
window, so a guest that never repeats a destination can cause at most
`2 × (256 + 128) = 768` entries per 30-second window. A separate emission
budget was considered and dropped — above the caps it can never fire, below
them it fires first and makes the degrade-to-class path unreachable, so it
is a knob that either does nothing or silently loses refusals. What the
tables fold is counted and written to the chain at teardown, so the log
states its own completeness.

### Failure policy

Emission is **fail-open and counted**. This process is the only way a
workload reaches the network; failing closed on a signer fault would turn
a full disk into a network outage for every machine on the host, and the
decision an entry describes has already been enforced whether or not it
was recorded. Failures increment a counter the teardown entry carries. An
absent host signer key leaves the gateway serving un-audited rather than
refusing to serve, matching the substitution endpoint at the same seam.

Entries never carry packet payloads, DNS payloads beyond normalized
metadata, authorization headers, secrets, or application content. A DNS
name is the one guest-chosen string kept, as the metadata the policy
decision was made against, and every guest-derived label is clamped.


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

## Substitution and L3: what actually changes

Secret substitution is central enough to the product that "L3 mode cannot do
it" needs to be precise rather than a bullet in a table.

**The primary control is unaffected.** mvm's guarantee is that raw secret
bytes never enter the guest: `host.secrets.v1` mints destination-bound,
time-bound credentials host-side, and the real values never leave the
supervisor's address space. That is enforced at the broker, on a channel
that has nothing to do with the packet path, so it holds identically in
`l3-vsock` mode. A workload on the tunnel is no more likely to hold a
secret than one on the brokered path.

**What L3 gives up is the backstop.** The egress-time scan that catches a
secret which reached the guest by some *other* route works because the
socket-aware endpoint **originates** the outbound connection — it holds the
cleartext, so it can see and rewrite it. Over the tunnel the guest
originates the connection, so what crosses the vsock boundary for a TLS
flow is ciphertext. No placement of a filter recovers that.

Three ways one could try, and why only one is taken:

1. **Terminate the guest's TLS with a host CA in its trust store.** This
   would restore full substitution. It is deliberately out of scope: it is
   a larger and worse security change than the one this ADR makes, and the
   design explicitly rules out transparent interception.
2. **Reassemble and rewrite cleartext TCP.** For flows the guest sends in
   the clear, the gateway could reassemble the byte stream, apply the
   scanner, and re-emit with adjusted sequence numbers and checksums. This
   is genuinely possible and is not implemented — it means terminating TCP
   in the gateway, and a subtly wrong implementation corrupts connections
   rather than failing visibly. It would also only ever cover cleartext,
   which is the minority of what matters.
3. **Refuse the combination.** Taken. A plan that binds secrets, enables
   reversible replacement, or enables per-destination redaction cannot
   select `l3-vsock`; `mvm_net::l3::check_mode_compatibility` refuses it at
   admission, before any build or boot, and the error names dropping
   `raw_ip_stack` from the workload's network declaration as the fix.
   In practice derivation already keeps such a plan on the socket-aware
   transport, so the gate is the backstop against a plan constructed
   directly rather than the ordinary path.

Option 3 is the important one. A workload whose substitution silently
stopped applying looks exactly like one that never needed it, which is how a
defence-in-depth layer becomes a defence in name only. Making the
combination inadmissible means the trade is always a decision someone made,
never one they inherited.

The two fields must also agree: an `l3-vsock` plan with no L3 spec, or an L3
spec on a plan that selected another mode, is refused for the same reason —
the plan would be ambiguous about what was admitted.

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

## Live boot witness

A real Firecracker microVM on the mvm workload kernel (`CONFIG_TUN=y`,
built in — `CONFIG_MODULES=n`, so `=m` was never an option), configured with
no `network-interfaces` entry. Observed from inside the guest:

```text
L3WITNESS tun_device_present=true
L3WITNESS interfaces_before=lo
L3WITNESS interfaces_after=lo,mvm0
L3WITNESS mvm0_mac=
L3WITNESS mvm0_arphrd=65534
L3WITNESS mvm0_created=true
```

`interfaces_before=lo` is the no-NIC invariant, observed rather than
asserted: the guest has loopback and nothing else. `arphrd=65534` is
`ARPHRD_NONE` — the device is layer 3, not Ethernet — and the empty MAC
follows from that, because a point-to-point IP interface has no hardware
address to report.

## Measured overhead

Per-packet cost of the host path, release build, MTU-sized (1500 B) TCP
segments. Measured by `crates/mvm-hostd/tests/l3_throughput.rs`, which is an
ordinary test so the numbers can be reproduced anywhere with
`cargo test --release -p mvm-hostd --test l3_throughput -- --nocapture`.

| Stage | Apple M4 Max | Intel i7-7700 @ 3.6 GHz |
|---|---:|---:|
| frame encode | 21 ns | 37 ns |
| frame decode | 3 ns | 5 ns |
| IP validation | 6 ns | 11 ns |
| DNS binding lookup | 18 ns | 15 ns |
| DNS reply construction | 49 ns | 138 ns |
| admission, established flow | 358 ns | 1283 ns |
| admission, refused | 369 ns | 1211 ns |
| **host path** (decode + admit + forward) | **508 ns** | **2785 ns** |

Reading these:

- **Framing and validation are free.** Together they are under 30 ns, a
  rounding error against the copy they wrap. The protocol's bounded,
  non-allocating design is doing its job.
- **Admission dominates**, at roughly 70% of the host path. The cost is the
  flow-table lookup plus the linear scan of canonical rules. That is the
  price of deciding every packet against the signed plan rather than
  installing a kernel rule and trusting it, and it is the intended
  trade.
- **The refusal path costs the same as the accept path** (369 vs 358 ns;
  1211 vs 1283 ns). This matters: a guest flooding denied packets gains no
  amplification over one sending admitted traffic, so the drop path is not
  itself an attack.
- **Headroom.** ~2 M packets/s on Apple Silicon and ~0.36 M packets/s on the
  older Xeon-class part, per machine, before the platform write. At MTU
  that is roughly 23 Gb/s and 4 Gb/s respectively — comfortably above a
  single workload's needs and well below virtio-net with offloads, which is
  the documented trade.

These exclude the vsock round trip and the host TUN write, which are
kernel costs this design does not control. The v1 copy path (guest kernel →
guest buffer → vsock → host buffer → host TUN) is deliberate; optimize it
only against measurements like these, not against intuition.

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
  rather than degrading. (Since closed: the userspace socket datapath of
  ADR-052 now serves macOS, within the limits §macOS states.)

## Future work

- Multi-queue: negotiate `queue_count` in `HELLO`/`CONFIG`, open one
  vsock connection per queue at `L3_DATA_PORT_BASE + q`, and hash each
  packet's flow tuple to a stable queue so ordering within a flow is
  preserved. The header field and negotiation slots exist in v1.
- UDP ingress.
- macOS `utun` + PF datapath, behind a narrowly-scoped privileged helper.
  **Closed, not pending:** [ADR-039](039-macos-network-helper.md) proposed
  that helper and is Rejected. ICMP, raw IP protocols and arbitrary
  IPv4/IPv6 stay refused at admission on macOS.
- IPv6 datapath, designed in [ADR-038](038-ipv6-support.md). **Landed**:
  the host assigns the gateway's `/126` on the TUN and the `inet` ruleset
  pins the guest's v6 source beside its v4 one, so the backend declares
  the whole `FULL_L3` set.
- Zero-copy or batched packet transfer, if measurement justifies it.
- **Known defect: one machine's forward chain drops another machine's
  traffic.** Each machine's table anchors a `filter`-priority forward base
  chain with `policy drop`, and a base chain's policy applies to every
  packet that reaches it, not only to the machine that installed it. Two
  chains at the same priority both run, so with two machines open each
  one's policy refuses the other's admitted traffic. Measured on Linux
  with nftables 1.0.9: a probe chain at `filter + 10` counts one machine's
  admitted packet with a single table loaded and stops counting it the
  moment a second machine's table is added. The shape is family-agnostic
  and predates IPv6 — it is not what the v6 rules introduced. The fix is
  for the chain to refuse only what it owns (`policy accept` with an
  explicit `iifname`/`oifname` drop pair) rather than to default-drop the
  host's whole forward path, which changes a security-sensitive ruleset
  and belongs in its own change with its own witness. Until then a host
  serves one L3 machine at a time, and the privileged lane's forward-hook
  witness measures only in a window where no other machine's table is
  loaded.

# ADR-052 — The userspace socket datapath

**Status: Superseded for production workload networking by ADR-042
(2026-08-11).**
**Date: 2026-08-02**
**Renumbered 037 → 052 on 2026-09-04.** Two ADRs held 037: this one and
ADR-037 (`mvmd` is the only production launch authority), so a citation of
"ADR-037" named two different decisions and a reader could not tell which.
This one moved because it is superseded and its inbound citations are
backward-looking, while the launch-authority ADR is Accepted and cited as
current authority. Every in-tree citation that meant this document was
retargeted in the same change. A reference to "ADR-037" predating that date
and discussing networking means this ADR. The number 052 was held by a
different ADR before the v1 restructure deleted it; nothing in the tree cited
that one.
**Superseded by: ADR-042 (one flow-aware vsock networking path). This ADR's
datapath forwarded raw IP packets for `l3-vsock`, which is leaving the
production workload path along with the mode itself. Its unprivileged-
forwarding analysis and its performance measurements remain accurate history;
its `UserspaceSocketDatapath` is not a live production transport. The staged
removal is `specs/plans/316-single-flow-vsock-networking.md`.**
**Supersedes: ADR-036 §"macOS (Apple Silicon)" in part — that section
staged `MacosUserspaceGateway` as a capability declaration plus a refusal
and left the translator undesigned. This ADR designs it, and widens it
from a macOS-only backend to a platform-neutral unprivileged one.
Complements ADR-036 (L3 TUN-over-vsock), which owns the protocol, the
policy seam, and the guest side unchanged.**

## Context

ADR-036 shipped `l3-vsock` with one working forwarding backend: the Linux
host TUN, driven through `netns` and `nftables`, requiring root or
`CAP_NET_ADMIN`. Every other platform got `UnsupportedDatapath` or, on
macOS, a `MacosUserspaceGateway` that declared
`ForwardingCapabilities::USERSPACE_SOCKETS` and then refused at
`is_available()`. That placeholder has since been deleted, along with the
two tests that asserted its refusal; `UserspaceSocketDatapath` is what
`host_datapath()` returns in its place.

That refusal is honest — it fails closed rather than degrading, and it
never routes macOS through a general-purpose proxy runtime — but it means
`l3-vsock` is unavailable on the platform where HVF is the default
backend. HVF is not the obstacle: it already advertises `l3_vsock: true`
unconditionally, because it presents no network device to the guest at
all, which is exactly the mode's precondition. The gap is entirely
host-side.

Two properties make the gap worth closing with sockets rather than
waiting for a privileged datapath:

- A userspace socket gateway needs **no privileges whatsoever** — no
  `utun`, no routes, no PF anchor, no helper. It is the only forwarding
  backend that can run as an ordinary user.
- Unprivileged Linux has the same gap. A contributor or CI runner without
  `CAP_NET_ADMIN` cannot use `l3-vsock` today either, despite the
  translator being platform-neutral by nature.

## Decision

Build **`UserspaceSocketDatapath`**: one platform-neutral `L3Datapath`
implementation that terminates guest TCP and UDP in userspace and
re-originates each admitted flow on a host socket.

1. It is **not** `cfg(target_os)`-gated. macOS always selects it. Linux
   selects it as a fallback when the TUN datapath is unavailable.
2. Guest TCP is terminated by **smoltcp**, scoped strictly below the
   `L3Datapath` seam.
3. The guest-side handshake is **deferred**: no SYN-ACK reaches the guest
   until the host-side `connect()` has succeeded.
4. It reports `ForwardingCapabilities::USERSPACE_SOCKETS`. ICMP, raw IP
   protocols, and arbitrary IPv4 forwarding remain unavailable and
   continue to be refused at admission, for the stated reason.

Nothing above the seam changes. The gateway, admitter, policy projection,
DNS, flow tracking, lease, and audit are untouched, because a datapath
only ever receives `AdmittedPacket` values that already cleared policy.

## Why smoltcp here is not a return of Model A

The smoltcp L3 egress stack was deleted as *the second egress model*. The
objection recorded in the F5 convergence work was that two egress models
existed concurrently — the vsock-proxy path (Model B) and the smoltcp-L3
path (Model A) — and that HVF's fail-open fallback was the last consumer
keeping the second one alive. The objection was never that a userspace TCP
implementation is inherently wrong.

Below the `L3Datapath` seam, smoltcp cannot become a second egress model.
It is not reachable from any launch path, it makes no policy decision, and
it cannot be handed bytes that have not been admitted, because
`send_to_network` takes `AdmittedPacket` — a type only `mvm_net::l3`'s
admitter can construct. It is an implementation detail of one backend,
selected by `host_datapath()`, in exactly the position `nftables` occupies
for the Linux backend.

The alternative was hand-rolling TCP termination. Rejected: retransmission,
window management, RTO, out-of-order reassembly, and the close-state
machine are a large amount of subtle work in a path a hostile guest drives
directly, and getting them subtly wrong is far more dangerous than the
dependency.

## Why the handshake is deferred

When the guest sends a SYN, the gateway can either answer immediately and
connect lazily, or hold the SYN until the host connect resolves.

Answering immediately is cheaper by one round trip and needs no half-open
state. It was rejected because it makes the guest's `connect()` lie: the
guest reaches ESTABLISHED for destinations that do not exist, and the
failure surfaces later as a mid-stream RST. Health probes, service
discovery, and retry logic all treat `connect()` success as a reachability
signal, and all of them would behave wrongly. The lie is also invisible in
the audit log, which records the admitted flow either way.

So the SYN never reaches the stack until the host side is real:

1. The SYN is parsed and **held**; a non-blocking host `connect()` opens.
2. Retransmitted SYNs for the same 4-tuple fold into the existing
   half-open entry rather than opening a second socket.
3. On connect success the held SYN is replayed into smoltcp, which then
   emits the SYN-ACK. The guest reaches ESTABLISHED only once the
   destination genuinely accepted.
4. On connect failure an RST is synthesized toward the guest and the entry
   is dropped. The guest's `connect()` fails, as it would on a real path.

Step 1 is load-bearing: given a listening socket, smoltcp answers a SYN
itself. Interception before the stack is what makes the deferral possible
at all.

## Destination integrity

This is the one security property socket translation does not inherit for
free, and the reason it needs its own invariant.

With a host TUN, the admitted packet's bytes are what goes on the wire.
The destination admission checked *is* the destination reached, and no
divergence is representable. With socket translation the datapath
**re-derives** a destination from the packet and passes it to `connect()`.
Any divergence between the checked value and the connected value is a
policy bypass that the audit log would not show, because the audit records
the admitted metadata rather than the socket's real peer.

Two rules, both mechanical:

- **`connect()` receives only the exact `IpAddr` carried by the admitted
  packet.** Never a hostname, never a string through `ToSocketAddrs`. A
  name resolved here would re-enter DNS resolution below the policy seam,
  which is the v4-mapped SSRF class this codebase has already been bitten
  by once.
- **The connected socket's `peer_addr()` is asserted equal to the admitted
  destination**, and the flow is torn down on mismatch. One cheap check
  converts "we derived it correctly" from an assumption into an invariant.

Destination *policy* — loopback, link-local, multicast, broadcast,
unspecified, reserved, and private-unless-admitted — is already enforced
above the seam by `mvm_net::l3::admit` and is not restated here.

## Resource bounds

Flow-table entries are cheap. Host sockets are not, and this is the first
datapath whose per-flow cost is a file descriptor.

`DEFAULT_MAX_FLOWS` is 4096. macOS ships a soft `RLIMIT_NOFILE` of 256.
A guest opening its full admitted allowance would exhaust the process's
descriptors — which does not merely break the tunnel, it breaks the
supervisor's ability to open its audit log, its vsock, or anything else.
The socket cap therefore cannot inherit the flow cap:

- `RLIMIT_NOFILE` is read at `open()`. The soft limit is raised toward the
  hard limit, which an unprivileged process may do. A fixed headroom is
  reserved for the process's own descriptors, and the table is capped at
  `min(DEFAULT_MAX_HOST_SOCKETS, budget - FD_RESERVE)`.
- `MAX_HALF_OPEN` is separate and much smaller, with its own timeout. A
  SYN flood parks a connecting descriptor per entry and must hit that
  bound long before the socket cap.

Consts rather than negotiated values, following the precedent in
`mvm_protocol::l3::limits` that a ceiling is something a hostile guest
cannot raise. The figures below are what
`crates/mvm-hostd/src/netd/userspace/limits.rs` holds as shipped; the
first draft of this table carried indicative numbers that the
implementation then moved away from, so it is restated from the code
rather than from intent:

| Const | Value | Rationale |
|---|---|---|
| `DEFAULT_MAX_HOST_SOCKETS` | 256 | An affordability bound, not a demand: what the host can carry at 44.51 MiB against the real per-flow cost below, held well under `DEFAULT_MAX_FLOWS` (4096) because a descriptor costs more than a table entry |
| `FD_RESERVE` | 64 | Uncounted slack for audit log, vsock, control channel, logging and the readiness pair; binds only when the raised `RLIMIT_NOFILE` is under 320 |
| `DEFAULT_MAX_HALF_OPEN` | 64 | A connecting descriptor each; sized for a real connect burst — page-load fan-out, parallel package install, sidecar startup — not for a flood |
| `HALF_OPEN_TIMEOUT_MILLIS` | 10_000 | Matches ordinary connect timeouts |
| `DEFAULT_MAX_UDP_ASSOCIATIONS` | 64 | Sized against what a workload opens once DNS is excluded — QUIC, NTP, syslog, metrics — and held to a quarter of the socket cap so datagrams cannot starve TCP of the shared descriptor budget |
| `DEFAULT_MAX_UDP_INGRESS_LISTENERS` | 16 | Declared inbound datagram mappings this datapath binds a listener for. A handful of named services, not a range — and far under the policy layer's own 64, because a mapping there is a table row while a listener here holds a descriptor for the machine's whole life and is never reclaimed |
| `PEERS_PER_INGRESS_LISTENER` | 32 | Peers one listener remembers so the guest's answer can go back to whoever asked. Sized for the concurrent conversations an exposed datagram service really has; a datagram from a peer past the cap is dropped rather than delivered, since the answer would have nowhere to go |
| `DATAGRAMS_PER_SOURCE_POLL` | 3 | `DEFAULT_QUEUE_DEPTH / (DEFAULT_MAX_UDP_ASSOCIATIONS + DEFAULT_MAX_UDP_INGRESS_LISTENERS)`: one divisor, because associations and listeners empty onto the one guest-bound queue. Sizing either against the whole depth would let whichever is polled first fill it and leave the other reading datagrams off host sockets only to discard them |
| Per-socket ring buffers | 16 KiB rx + 16 KiB tx | 32 KiB per flow |
| Per-flow device queues | 31 rx + 65 tx packets at the 1500-byte MTU | 144,000 bytes per flow |

### The memory ceiling, re-derived

**The `1024 × 32 KiB = 32 MiB` figure this ADR first carried is wrong**,
and was wrong in three independent ways: the socket cap is 256 rather than
1024; a flow costs far more than its two ring buffers, because each flow
got its own smoltcp device with its own packet queues; and UDP
associations, which landed after this ADR was written, add a term the
formula had no place for. The arithmetic below is what
`MEMORY_CEILING_BYTES` actually computes, spelled out so it can be checked
rather than trusted.

Per established flow:

```text
ring buffers      16,384 + 16,384                     =  32,768 bytes
device queues     (31 + 65) packets × 1500 bytes      = 144,000 bytes
                                                        -------------
FLOW_BUFFER_BYTES                                       176,768 bytes
```

The two queue depths are derived, not picked. `FLOW_RX_QUEUE_DEPTH` is
`ceil(16384 / 536) = 31` — a receive window's worth of segments at the 536
byte default MSS of RFC 879, which is what a guest whose SYN carries no MSS
option will use. `FLOW_TX_QUEUE_DEPTH` is `31 + 32 + 2 = 65`: an ACK burst
as deep as the receive queue (smoltcp answers each segment behind a
sequence hole with an immediate, un-rate-limited ACK), plus the 32 data
segments a two-round pump pass can emit, plus one control segment per poll.

Per machine at the cap:

```text
flows              256 × 176,768                      = 45,252,608 bytes
machine-wide device  2 × 256 packets × 1500 bytes      =    768,000 bytes
half-open SYNs      64 × 1500 bytes                    =     96,000 bytes
one UDP poll batch  64 × 3 × 1500 bytes                =    288,000 bytes
one ingress batch   16 × 3 × 1500 bytes                =     72,000 bytes
audit dedup tables (256 + 128) × 512 bytes              =    196,608 bytes
                                                         --------------
MEMORY_CEILING_BYTES                                     46,673,216 bytes
```

**46,673,216 bytes is 44.51 MiB**, not 32 MiB. It is an upper bound and not
an attainable state — flows, half-open entries, associations and ingress
listeners all draw on the same descriptor budget, so a machine cannot hold
256 of one and the full cap of each of the others at the same instant — but
it is summed anyway, because a
ceiling that has to be reasoned about to be believed is a ceiling nobody
re-checks. `the_per_machine_memory_ceiling_is_what_we_claim` in `limits.rs`
asserts every term and the total.

The discrepancy this section used to record is closed. The doc comment on
`DEFAULT_MAX_HOST_SOCKETS` said the worst case at a cap of 256 was "back
under 44 MiB", which counted only the per-flow term (45,252,608 bytes,
43.16 MiB) and omitted the three machine-level terms the constant itself
sums; it now states 44.51 MiB and names both figures so the smaller one
cannot be mistaken for the ceiling again.

The audit dedup tables are a gateway-level term in a datapath-level
ceiling. They are counted here because this constant is the one place the
process's guest-drivable footprint is stated, and a table a guest fills by
choosing destinations is guest-drivable memory wherever it sits.

Each of the six terms is asserted separately as well as in the total, and
the machine-wide device — the one with no named constant — is asserted as
the **residual** of the five that do. That is not redundancy: two terms of
equal size move the total identically, so a total on its own cannot say
which one went, and a residual form makes a dropped term fail under its own
name. Declared UDP ingress added the fifth term, and adding it is what
moved the association batch from 4 datagrams per poll to 3: the two share
one guest-bound queue and one divisor.

- **At capacity the new packet is dropped; a live flow is never evicted.**
  This matches the existing `FlowAdmission` posture rather than
  introducing a second one.

**Backpressure is what makes the memory ceiling real.** When a host socket
drains slower than the guest sends, the datapath stops accepting from
smoltcp and lets its receive window close. Without that the buffers grow
without bound and the stated ceiling is fiction.

## Connection lifecycle details

- A guest FIN becomes `shutdown(Write)` on the host socket, never
  `close()`. Closing outright breaks half-duplex protocols by discarding
  the peer's remaining response.
- A host-side error on an established flow (`ECONNRESET`, `EHOSTUNREACH`)
  synthesizes an RST toward the guest rather than dropping the flow
  silently, so the guest's stack learns instead of hanging to its own
  timeout.
- `close()` deterministically closes every host socket, on the normal path
  and the failed-startup path alike. The trait already requires
  idempotence; with descriptors it stops being bookkeeping and becomes a
  leak that accumulates across machine restarts.

## Placement and data flow

The datapath lives in `crates/mvm-hostd/src/netd/userspace/`, beside
`linux.rs` and below the seam.

`gateway.rs` is a large file, but it is not near the file-size gate.
`xtask check-file-size` counts **production lines only** — those before a
file's first top-level `#[cfg(test)]`, per this repo's trailing-tests
convention. `gateway.rs` is ~1466 lines total but its production body is
**889**, against a `MAX_PROD_LINES` of 1500. It has ample headroom, and a
change there needs no preparatory split.

| File | Responsibility |
|---|---|
| `mod.rs` | `UserspaceSocketDatapath` + `UserspaceHandle` |
| `device.rs` | The virtual smoltcp `phy::Device` over the guest packet queues |
| `tcp.rs` | Half-open table, connect lifecycle, established-flow pumping |
| `udp.rs` | Datagram association table |
| `limits.rs` | Bounds and their defaults |

`send_to_network` enqueues into the device's RX queue. `recv_from_network`
dequeues from its TX queue, returning `WouldBlock` when empty, as the trait
already specifies. A `service()` step polls smoltcp and the host sockets
between them.

**Readiness.** The handle owns a `mio::Poll`, which wraps a single pollable
descriptor on both platforms — kqueue on macOS, epoll on Linux. The new
readiness accessor on `DatapathHandle` returns that descriptor, and
`mvm-netd`'s loop registers it alongside the guest data channel. One
descriptor, no second concurrency model, identical on both platforms.

As shipped the poll set is empty, so the descriptor never fires and the
datapath advances only on the loop's timer tick. See §"Known defects in
what shipped".

`mio` is already a workspace dependency, so this adds a dependency *edge*
from `mvm-hostd` rather than a new third-party dependency to the project.

UDP is the simpler sibling: a host socket per association, replies
synthesized back as IP+UDP, non-DNS only, since DNS terminates above the
seam.

## Prerequisite: the mvm-netd drive loop

Two defects in the shipped gateway binary block this work. Both are
platform-neutral, so the Linux backend has them today.

**The clock is a frame counter.** `mvm-netd` declares `let mut now: u64 =
0` and increments it once per guest frame, then passes it to every API
declared `now_millis`. Those values drive real expiry: `expire_idle`
computes `now_millis - last_seen_millis` against
`DEFAULT_TCP_IDLE_MILLIS` (300_000) and `DEFAULT_DATAGRAM_IDLE_MILLIS`
(60_000). A TCP flow therefore expires after 300,000 guest frames rather
than five minutes, and the flow table is bounded by capacity alone. The
same counter drives the DNS rate-limit token bucket.

The fix is in the **caller only**. `mvm_net::l3::flow` deliberately takes
a caller-supplied millisecond counter rather than reading `Instant`, so
that expiry is a pure function of its inputs and tests assert behaviour
instead of sleeping. That design is correct and is preserved; `mvm-netd`
simply supplies real monotonic milliseconds.

**Host-to-guest traffic only moves when the guest transmits.** The
steady-state loop blocks on `data.read()` and polls the datapath only
after a guest frame arrives, as its own comment concedes. A server pushing
to a quiet guest stalls indefinitely. smoltcp additionally requires
independent pumping for its retransmit timers.

Both are fixed with a `mio` loop servicing the guest channel, the datapath
readiness descriptor, and a timer tick.

## Capability reporting

`host_datapath()` attempts `LinuxDatapath` and falls back to
`UserspaceSocketDatapath` when TUN is unavailable.

The risk is a silent downgrade. A Linux operator who has lost
`CAP_NET_ADMIN` would otherwise see a plan refused for `missing: ["icmp"]`
with nothing indicating the fallback caused it. The fallback reason
therefore rides in the diagnostic — "TUN unavailable (no `CAP_NET_ADMIN`);
using userspace socket translation" — rather than leaving it to be
inferred.

## Testing

All unprivileged, so every case runs on both CI platforms.

- **Unit.** Device queue round-trip; SYN retransmit folds into one
  half-open entry; connect failure synthesizes RST; capacity drops rather
  than evicts; idle expiry asserted as a pure function of `now_millis`
  with no sleeping.
- **Integration.** A real localhost listener, synthesized guest packets,
  bytes proven to flow both directions. Critically: **no SYN-ACK reaches
  the guest before the listener accepts**, which makes the deferred
  handshake executable rather than aspirational. And `peer_addr()` equals
  the admitted destination.
- **Hostile guest.** SYN flood bounded at `MAX_HALF_OPEN` with no
  descriptor exhaustion; malformed TCP; descriptor-budget exhaustion
  degrades to drop, never panic.
- **Drive-loop regression.** Flows expire on wall-clock time; and
  host-to-guest data flows while the guest is silent — the Linux defect,
  proven fixed.

## What this does not do

ICMP, raw IP protocols, and arbitrary IPv4 forwarding remain unavailable.
A plan needing them is refused at admission by the capability check, for
the right reason rather than for "macOS". That shortfall is now
**permanent on this backend**, not pending: closing it needs the `utun` +
PF datapath and the privileged helper ADR-036 §macOS enumerates, and
[ADR-039](039-macos-network-helper.md) — the ADR that proposed exactly that
helper — is **Rejected**. mvm adds no root-capable component, so a socket
gateway is the whole of what an unprivileged host can offer, and a workload
needing raw IP is refused rather than served badly.

IPv6 is not carried either. `mvm_net::l3::admit` refuses any packet whose
`version` is not 4, so a v6 destination never reaches this datapath.
[ADR-038](038-ipv6-support.md) designs the family; nothing of it has landed.

Multi-queue and zero-copy transfer are orthogonal and tracked in the
deferred set of `specs/plans/285-l3-tun-over-vsock.md` (referenced by
filename because `285` is used twice on main).

## Known defects in what shipped

None of these is a design property. Two of the four are now closed and
are kept here, struck through, with what closed them: an ADR that quietly
deleted its own defect list would leave nothing to check the fix against.
The other two are open, and they are the same shape: a capability this
backend advertises truthfully that nothing on the demand side can ask for
or fully use.

- ~~**A 50 ms latency floor on everything the host originates.**~~
  **Closed.** Every host socket this datapath opens — a half-open connect,
  an established flow, a datagram association — is now registered on the
  set behind `readiness_fd`, so a connect the kernel has decided and a byte
  a peer sent wake the drive loop rather than waiting out its tick. The tick
  remains the floor on time-driven work (expiries, half-open timeouts,
  transport timers), which is what it was always for.

  Registration is an ownership fact rather than a bookkeeping one:
  `readiness::Watched` owns the socket and its registration together and
  drops them in that order, so a socket that exists is registered and one
  that has gone is not. The alternative — deregistering at each of the
  dozen places a socket can be dropped out of a table — works until the
  thirteenth is added, and a descriptor that closes while the set still
  names it frees its *number* for the next `open` in the process.

  The set costs two descriptors per machine rather than one: the poll
  side, which `readiness_fd` hands the drive loop, and an owned reference
  to the same kernel object that goes to every socket. mio's registry is
  borrowed from its poll set, and a borrow cannot outlive it into a
  socket's `Drop`.

  Registration alone left one case on the tick, and that is closed too. The
  service pass spends the set's readiness before it reads a socket — an
  edge cleared afterwards would be one for bytes nothing goes back for — so
  a flow whose host-to-guest pump stopped at `max_bytes_per_pass` had a
  remainder no further edge would ever announce. That pass now reports
  `InboundDrain::Backlogged` out through `DatapathHandle::service`, and the
  drive loop treats it exactly as it treats a bounded drain's: it comes
  straight back instead of waiting. A stall is not a backlog and is not
  reported as one — what frees the stack's send buffer is the guest's ACK,
  and that arrives on the guest channel, which wakes the loop by itself.
- **`declared_ingress: true` is now true for datagrams and still not true
  for streams.** Half closed, and the open half is stated rather than
  rounded off.

  **Closed for UDP.** A declared datagram mapping binds a host listener on
  exactly the address it named, and the datagrams it receives are
  synthesized into packets addressed to the guest port the *declaration*
  named — never the datagram's own destination port, which names the host
  listener. Binding is not admitting: those packets leave through the
  handle's read path and go back through `admit_inbound`, which refuses any
  whose guest port has no declared mapping there, so withdrawing a
  declaration stops delivery while the socket is still bound.

  What a mapping accepts from is the address it declared and nothing else,
  and no second per-source allow-list was invented — the plan carries none,
  so one written in the datapath would be policy the datapath chose. What
  the datapath owes that decision is to bind exactly what was declared; the
  wildcard case is already gated behind explicit admission in
  `IngressTable`. In the other direction the listener is strict: its socket
  is unconnected, so a guest datagram leaves it only toward a peer that has
  already written to that mapping, inside that peer's lifetime. Anything
  else falls through to the outbound association path, whose socket is
  connected to an admitted destination — the fail-closed direction.

  **Open for TCP.** A declared stream mapping is admitted and binds
  nothing here. Serving one needs a listener whose accepted connections are
  originated *toward* the guest — the mirror of the deferred handshake,
  with the guest as the side that must be dialled — and this datapath does
  not build that. It is skipped at open rather than refused, so a plan
  carrying one still runs its outbound traffic, and it opens no socket, so
  nothing can be mistaken for serving it. The packet-forwarding backend
  serves both, since an inbound packet reaches its device with nothing
  bound. Until stream ingress lands here, `declared_ingress: true` remains
  an over-claim for TCP on this backend, and saying so is the point of this
  entry.
- ~~**`ipv6_flows: true` is honest about this backend and unreachable from
  either end.**~~ **Closed 2026-08-04.** The declaration is now
  load-bearing on both sides.

  **Demand.** `L3NetworkSpec.features` is the request. A plan setting the
  `IPV6` bit is what makes the host lease a v6 pair, and `GatewayConfig`
  derives `required_capabilities.ipv6_flows` from that lease — one place,
  from the lease rather than from a constant. A backend without the
  capability now produces a `CapabilityShortfall` naming `ipv6_flows`
  before the VM boots. Both backends have the capability today: the Linux
  TUN datapath's v6 half landed alongside this, so it declares the whole
  `FULL_L3` set rather than refusing such a plan.

  **Supply.** The allocator carves a unique-local `/126` at the same index
  as the `/30`, `assign_config` sends it, and the granted feature bits say
  so. The guest holds a v6 address, so `admit_outbound` has something to
  check a v6 source against and the family is no longer refused for want
  of one.

  A plan that does not ask for IPv6 is unchanged in every byte, which is
  the other half of the decision: the capability is honest *and* the
  default is still one address family.
- ~~**`Gateway::poll_inbound` drains without a per-pass budget.**~~
  **Closed.** The drain is bounded by `MAX_INBOUND_PACKETS_PER_PASS` and
  reports `InboundDrain::Backlogged` when the budget is what stopped it, so
  the drive loop comes straight back rather than waiting on a readiness edge
  it has already spent. It is the guest-facing drain's own mechanism pointed
  the other way, at the same number — never a second one. This was a
  fairness and latency defect rather than an unbounded-memory one: the
  datapath's queues are bounded, so a pass capped out in the thousands. A
  guest still has a hand on the rate, since it chooses which destinations
  reply.

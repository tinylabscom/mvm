# ADR-037 — The userspace socket datapath

**Status: Accepted**
**Date: 2026-08-02**
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
macOS, a `MacosUserspaceGateway` that declares
`ForwardingCapabilities::USERSPACE_SOCKETS` and then refuses at
`is_available()`.

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

Indicative defaults, consts rather than negotiated values, following the
precedent in `mvm_protocol::l3::limits` that a ceiling is something a
hostile guest cannot raise:

| Const | Value | Rationale |
|---|---|---|
| `DEFAULT_MAX_HOST_SOCKETS` | 1024 | Well above real workloads, far below `DEFAULT_MAX_FLOWS` |
| `FD_RESERVE` | 64 | Audit log, vsock, control channel, logging, slack |
| `DEFAULT_MAX_HALF_OPEN` | 128 | A connecting descriptor each; sized for burst, not flood |
| `HALF_OPEN_TIMEOUT_MILLIS` | 10_000 | Matches ordinary connect timeouts |
| Per-socket buffers | 16 KiB rx + 16 KiB tx | 32 KiB per socket |

The memory ceiling is therefore `1024 × 32 KiB = 32 MiB` per machine at
the cap. That number is asserted in a test, not left to be recomputed by
hand whenever a buffer size changes.
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

`gateway.rs` is 1486 lines against the repository's `MAX_PROD_LINES` of
1500 — **fourteen lines of headroom**. It cannot absorb any part of this
work. If the readiness plumbing turns out to need more than a trivial
change there, `gateway.rs` is split first, as its own commit, before any
of this lands on top of it.

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
the right reason rather than for "macOS". Closing that gap needs the
`utun` + PF datapath and the privileged helper ADR-036 §macOS enumerates,
which remains a separate decision and a separate ADR.

Multi-queue, IPv6, and zero-copy transfer are orthogonal and tracked in
the deferred set of `specs/plans/285-l3-tun-over-vsock.md` (referenced by
filename because `285` is used twice on main).

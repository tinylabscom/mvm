---
title: L3 networking over vsock
description: An opt-in compatibility mode that gives a workload a real IP stack without giving it a NIC.
---

Workload microVMs have no network device. Egress leaves over vsock, and the
host originates every connection — that is what makes default-deny egress,
secret substitution, and the signed audit log enforceable.

The cost is application compatibility. A program that honours `HTTP_PROXY`
works. A statically linked Go binary with its own dialer, a runtime that
ignores proxy environment variables, anything wanting ICMP, and anything
running its own resolver all get nothing, because there is no route
anywhere.

mvm closes that gap. The guest gets a normal Linux IP interface, `mvm0`, and
every packet it sends is framed over vsock to a host-side gateway that
applies policy before anything touches the network. **The guest still has no
NIC.**

```sh
mvmctl machine run \
  --allow-host api.example.com:443 \
  --image alpine \
  -- curl https://api.example.com/
```

## There is no transport to choose

**You do not select a networking mode, and there is no flag to do it with.**
The transport follows from one question about the *workload*:

> Does it need a real in-guest IP stack — raw sockets, ICMP, non-TCP/UDP
> protocols, or its own resolver?

- **No** (almost always) → the socket-aware transport. This is the default
  and the stronger posture: the host originates every connection, so secret
  substitution, cleartext redaction, and L7 policy all apply.
- **Yes** → the L3 tunnel described here.

The need is declared by the workload, not chosen at run time:

```python
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    network=mvm.network(mode="bridge", raw_ip_stack=True),
)
def probe(): ...
```

Leaving it out is the default and means the socket-aware transport. A
non-boolean value is a parse error rather than a silent default: the kwarg
changes what the workload is admitted for, and quietly reading
`raw_ip_stack="yes"` as false would strand it on a transport it cannot use.

Two consequences worth knowing:

- **The plan is host-independent.** The same workload derives the same
  transport everywhere, so a plan built on your laptop means what it means
  in production. Host capability is deliberately *not* an input to the
  derivation.
- **A host that cannot serve the tunnel refuses only the workloads that
  need it.** Where the host can carry a workload's TCP and UDP but not raw
  IP — every macOS host, and any Linux host without `CAP_NET_ADMIN` — the
  workload is admitted if that is all it needs, and refused with a stated
  reason if it needs more. Nothing is degraded to make it fit.

## What you give up

:::caution[L3 mode cannot inspect or substitute inside encrypted traffic]
In L3 mode mvm sees **packets**, not connections. Once your application
negotiates TLS, the payload is opaque to the host.

That means these do **not** apply in L3 mode:

- transparent secret substitution inside application traffic;
- cleartext PII redaction;
- HTTP-level or SNI-based policy;
- hostname attribution independent of the controlled resolver.

You do not have to remember any of this, and you cannot get it wrong: a
plan that binds secrets, enables reversible replacement, or enables
per-destination redaction is *derived* onto the socket-aware transport, and
the compatibility gate refuses the combination outright if anything ever
tried to construct it directly.

Worth being precise about what is and is not lost. Host-side substitution
works by having the broker release destination-bound, time-bound credentials
rather than raw secret values, and that mechanism is **unaffected** by the
networking mode. What L3 gives up is the egress-time *backstop* — the
outbound scan that would catch a secret which reached the guest by some
other route — because in L3 mode the guest originates its own TLS, so the
host sees ciphertext.
:::

## What still holds

Choosing L3 mode does not weaken the boundary. It still guarantees:

- the guest has no NIC, and none is created for this mode;
- every guest IP packet crosses the vsock boundary and is admitted by the
  host before reaching host networking;
- the source address must be the one the host assigned — spoofing is
  dropped;
- destination and port enforcement from the signed plan, through the same
  policy projection `--allow-host` compiles into everywhere else;
- host-controlled DNS, so domain rules mean something;
- return traffic only for flows you opened; unsolicited inbound is dropped;
- only ingress you declared;
- bounded queues, flow tables, and DNS state under a hostile guest;
- no silent fallback — if the tunnel fails, networking is unavailable, and
  where the host substitutes one forwarding backend for another it says so
  and says what the substitution costs.

## Mode comparison

| | `host-vsock-proxy` (default) | `l3-vsock` |
|---|---|---|
| Connection intent (host:port as asked) | yes | via controlled DNS |
| Secret substitution | **yes** | **no** |
| Cleartext PII redaction | **yes** | **no** |
| HTTP/SNI policy | yes, where owned | **no** |
| Destination / port / flow policy | yes | yes |
| Controlled DNS + domain allowlists | yes | yes |
| Declared ingress | yes | TCP on the packet backend; UDP on both; see the limits below |
| Raw sockets, ICMP, non-TCP/UDP | **no** | only on the packet backend |
| Works without proxy-env cooperation | partly | yes |

## Platform support

Two forwarding backends exist, and which one a host gets is not a choice
you make.

- The **packet backend** moves whole IP packets through a host tunnel
  device, with routes and a firewall anchor. It needs root or
  `CAP_NET_ADMIN`. Linux only.
- The **socket backend** needs no privileges at all. It terminates the
  guest's TCP and UDP in userspace and re-opens each admitted flow on an
  ordinary host socket. It carries application traffic and nothing else —
  see the limits below.

A host uses the packet backend when it can and the socket backend when it
cannot, and it tells you which, and why, rather than leaving a later
refusal to be interpreted.

| Platform | Status |
|---|---|
| **Linux** (Firecracker), privileged | The packet backend: a real host TUN and nftables, with a live boot witness (below). |
| **Linux** (Firecracker), unprivileged | The socket backend, with the substitution named in the diagnostic. A host without `/dev/net/tun`, root, or `CAP_NET_ADMIN` no longer loses the mode outright. |
| **Linux** (libkrun) | Not selectable. libkrun attaches a drained virtio-net device; L3 mode requires the guest to have no network device at all, so libkrun does not advertise the capability and selection fails closed. |
| **macOS** (Apple Silicon) | The socket backend. There is no packet backend on macOS and there will not be one: a tunnel device there needs root, and mvm runs no privileged host helper. |
| **Windows via WSL2** | Architecturally supported — WSL2 is a Linux node, the guest's vsock terminates inside it, and the Linux backend is used. Not yet validated on a WSL2 runner. |
| **Native Windows** | **Not supported.** mvm has no native Windows VMM backend. "Works on Windows" here always means WSL2. |

### What the socket backend cannot carry

A gateway that re-opens flows on host sockets cannot put an arbitrary
packet on the wire, so **ICMP, raw IP protocols, and arbitrary IPv4 or
IPv6 forwarding are unavailable on it**. A plan needing any of them is
refused at admission, naming what is missing and naming the backend
substitution that caused the refusal. It is never partially served.

Carrying a v6 *flow* and emitting an arbitrary v6 *packet* are separate
capabilities, and the socket backend declares them separately: it carries
TCP and UDP over IPv6, and it still cannot emit a raw v6 packet. That
declaration is now load-bearing rather than decorative — a plan that asks
for IPv6 requires `ipv6_flows` of whichever backend was selected, and a
backend without it refuses the session.

On macOS this is permanent rather than pending — the privileged helper it
would take was considered and turned down, because mvm adds no root-capable
component. On Linux it is a consequence of the privilege the process
happens to hold: restore `CAP_NET_ADMIN` and the packet backend comes back.

Everything the socket backend *does* carry keeps the guarantees above
unchanged: the guest still has no NIC, packets still cross the vsock
boundary and clear admission before anything is opened, and the host still
asserts that the socket it connected reached the exact address that was
admitted.

## How it fits together

```text
guest application
      │
guest TCP/IP stack
      │
   mvm0            point-to-point TUN, no MAC, no ARP, no bridge
      │
mvm-net-agent      in-guest; drops CAP_NET_ADMIN after setup
      │
framed IP packets over a dedicated vsock connection
      │
mvm-netd           host, one per machine boot
      │
policy · anti-spoof · flow state · DNS · ingress · NAT · audit
      │
host networking
```

Control messages and packet data use **separate** vsock connections, so a
saturated uplink cannot starve the machine's own control plane or its
shutdown path.

## Live boot witness

From a real Firecracker microVM on the mvm workload kernel, with no
network-interface entry in its configuration. Every line is observed from
inside the guest:

```text
L3WITNESS tun_device_present=true
L3WITNESS interfaces_before=lo
L3WITNESS interfaces_after=lo,mvm0
L3WITNESS mvm0_mac=
L3WITNESS mvm0_arphrd=65534
L3WITNESS mvm0_created=true
```

Reading it: before the agent runs the guest has **only loopback** — no
`eth0`, no virtio-net, nothing routable. After, it has `mvm0`, whose
`arphrd` is 65534 (`ARPHRD_NONE`, the layer-3 device type) and whose MAC
address is empty, because a point-to-point IP interface has none.

## Limits in this version

- **IPv6 is opt-in, and off unless the plan asks for it.** The workload
  kernel speaks IPv6; admission judges a v6 destination under rules that
  mirror v4; the host allocates a point-to-point `/126` beside the `/30`;
  and the guest agent configures the address, its peer, a default route
  through that peer, and the assigned resolver. The guest does that over
  rtnetlink, in the same setup phase as the v4 bring-up and before
  privileges are dropped, so a dual-stack assignment costs the guest no
  extra privilege and no extra process.

  A plan that does not set the `IPV6` feature bit in its `l3` network spec
  gets no v6 address at all, and its `CONFIG` is byte-for-byte the v4-only
  one. That is deliberate: an address family a workload does not need is
  reachable surface it did not ask for. A `CONFIG` carrying a v6 half and
  no v4 half is refused rather than half-applied.

  The v6 pool is unique-local (`fd00::/8`), never global and never
  documentation space. Holding an address in `fc00::/7` is an identity on
  the point-to-point link and **not** a permission to reach that range:
  another machine's leased address, its gateway, and unrelated ULA space
  are all refused by the address-class check unless a rule explicitly
  admits them, exactly as RFC1918 is in v4.

  A backend that cannot carry v6 flows refuses the session before the VM
  boots, naming `ipv6_flows` in the shortfall, rather than handing the
  guest an address whose packets go nowhere.
- Embedded-v4 addresses do not bypass the v4 rules. A v4-mapped,
  v4-compatible, NAT64, or 6to4 address is collapsed to the v4 address it
  carries and then judged by the whole v4 policy, so link-local metadata and
  private ranges stay refused however they are spelled.
- IP fragments are rejected rather than reassembled. TCP MSS is clamped so
  ordinary traffic does not fragment.
- One data queue. The protocol reserves the fields for more.
- Ingress mappings may declare `tcp` or `udp`. A protocol that is neither
  is refused at admission rather than accepted and ignored.

On the socket backend specifically:

- **Declared UDP ingress is served; declared TCP ingress is not.** A
  datagram mapping binds a host listener on exactly the address it names,
  and datagrams arriving on it are delivered to the guest port the mapping
  declares — subject to the same admission check every inbound packet
  passes, so withdrawing the mapping stops delivery. A *stream* mapping is
  admitted and binds nothing: serving one needs a listener whose accepted
  connections are originated toward the guest, which this backend does not
  build. Do not rely on inbound TCP reaching a workload here. Egress —
  connections the guest opens — is unaffected either way.
- A UDP mapping answers only peers that have written to it. The guest's
  reply leaves by the listener the conversation arrived on, so the peer
  sees it from the address it dialled; a datagram the guest aims anywhere
  else takes the ordinary outbound path and is subject to egress policy
  like any other. A peer entry lasts as long as a datagram association
  does, so a conversation quiet for longer than that is answered from a
  fresh source port, which a peer sees as a rebind.

Two limitations this backend used to carry are gone. The gateway is now
woken by the host sockets themselves, so a completed connection and an
arriving reply no longer wait out its 50 ms timer; that timer is back to
being what advances time-driven work such as idle expiry. And a large
inbound burst is taken a bounded number of packets at a time, so a flood of
return traffic can no longer delay the guest's own packets while the
gateway works through it.

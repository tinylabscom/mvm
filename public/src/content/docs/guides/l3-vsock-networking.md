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
mvm always uses the strongest configuration the workload can actually use.

A selector could only ever let someone pick a weaker posture than the one
they would otherwise have had, and the right answer is the same every time:

- a workload whose plan needs the host to see its outbound cleartext — one
  that binds secrets, or enables reversible replacement or redaction — gets
  the socket-aware transport, because the tunnel cannot provide that;
- on a host with no L3 datapath (macOS today), every workload gets the
  socket-aware transport, because that is what the host can serve;
- every other workload gets the tunnel, which is universally compatible.

Note the direction of the middle clause: it can only ever give the host
*more* visibility, never less. Moving the other way is what must never
happen quietly, and the compatibility gate refuses it outright.

All of that is derived, so it cannot be got wrong. The mode is still
recorded in the *signed plan* — it is the admitted contract, and a control
plane sets it — but it is not an operator knob.

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

Worth being precise about what is and is not lost. The guarantee that raw
secrets never enter the guest is enforced at the host-services broker and is
**unaffected** by the networking mode. What L3 gives up is the egress-time
*backstop* that would catch a secret which reached the guest some other way
— because in L3 mode the guest originates its own TLS, so the host sees
ciphertext.
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
- no silent fallback — if the tunnel fails, networking is unavailable.

## Mode comparison

| | `host-vsock-proxy` (default) | `l3-vsock` |
|---|---|---|
| Connection intent (host:port as asked) | yes | via controlled DNS |
| Secret substitution | **yes** | **no** |
| Cleartext PII redaction | **yes** | **no** |
| HTTP/SNI policy | yes, where owned | **no** |
| Destination / port / flow policy | yes | yes |
| Controlled DNS + domain allowlists | yes | yes |
| Declared ingress | yes | yes |
| Raw sockets, ICMP, non-TCP/UDP | **no** | yes |
| Works without proxy-env cooperation | partly | yes |

## Platform support

| Platform | Status |
|---|---|
| **Linux** (Firecracker) | Supported and tested, including a privileged lane with a real host TUN and nftables, and a live boot witness (below). |
| **Linux** (libkrun) | Not selectable. libkrun attaches a drained virtio-net device; L3 mode requires the guest to have no network device at all, so libkrun does not advertise the capability and selection fails closed. |
| **macOS** (Apple Silicon) | No L3 datapath, so workloads run on the socket-aware transport — which is the stronger posture, and everything still works. The intended backend is a userspace socket gateway (TCP, UDP, controlled DNS); it is not implemented, and is never faked or routed through a proxy runtime. |
| **Windows via WSL2** | Architecturally supported — WSL2 is a Linux node, the guest's vsock terminates inside it, and the Linux backend is used. Not yet validated on a WSL2 runner. |
| **Native Windows** | **Not supported.** mvm has no native Windows VMM backend. "Works on Windows" here always means WSL2. |

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

- IPv4 only. The workload kernel ships without IPv6; the protocol and the
  host validator handle v6 already, so enabling it later needs no wire
  change.
- IP fragments are rejected rather than reassembled. TCP MSS is clamped so
  ordinary traffic does not fragment.
- One data queue. The protocol reserves the fields for more.
- TCP ingress only. Declaring UDP ingress is refused at admission rather
  than accepted and ignored.

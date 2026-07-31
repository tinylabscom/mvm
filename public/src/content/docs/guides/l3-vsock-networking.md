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

`--network-mode l3-vsock` closes that gap. The guest gets a normal Linux IP
interface, `mvm0`, and every packet it sends is framed over vsock to a
host-side gateway that applies policy before anything touches the network.
**The guest still has no NIC.**

```sh
mvmctl machine run \
  --network-mode l3-vsock \
  --allow-host api.example.com:443 \
  --image alpine \
  -- curl https://api.example.com/
```

## What you give up

:::caution[L3 mode cannot inspect or substitute inside encrypted traffic]
In L3 mode mvm sees **packets**, not connections. Once your application
negotiates TLS, the payload is opaque to the host.

That means these do **not** apply in L3 mode:

- transparent secret substitution inside application traffic;
- cleartext PII redaction;
- HTTP-level or SNI-based policy;
- hostname attribution independent of the controlled resolver.

If your workload depends on any of them, stay on the default
`--network-mode host-vsock-proxy`. mvm prints this warning once when you
select `l3-vsock`, and admission refuses a plan that both selects L3 mode
and requires managed substitution.
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
| **Linux** (Firecracker) | Supported and tested, including a privileged lane with a real host TUN and nftables. |
| **Linux** (libkrun) | Not selectable. libkrun attaches a drained virtio-net device; L3 mode requires the guest to have no network device at all, so libkrun does not advertise the capability and selection fails closed. |
| **macOS** (Apple Silicon) | **Not available.** The intended backend is a userspace socket gateway (TCP, UDP, controlled DNS). It is not implemented, so `l3-vsock` is refused at admission with a stated reason. It is never degraded and never routed through a proxy runtime. |
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

## Limits in this version

- IPv4 only. The workload kernel ships without IPv6; the protocol and the
  host validator handle v6 already, so enabling it later needs no wire
  change.
- IP fragments are rejected rather than reassembled. TCP MSS is clamped so
  ordinary traffic does not fragment.
- One data queue. The protocol reserves the fields for more.
- TCP ingress only. Declaring UDP ingress is refused at admission rather
  than accepted and ignored.

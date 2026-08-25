---
title: FlowMux networking
description: Policy-enforced workload networking through one authenticated vsock path.
---

FlowMux is mvm's single workload-networking path. Workload microVMs have no
routable network device. Guest loopback adapters describe connection intent to
an authenticated per-VM endpoint over vsock, and the host opens only the
connections admitted by the signed plan.

There is no transport selector. Declaring network policy makes the FlowMux
service available; omitting it leaves networking closed. Retired raw-stack
fields and packet-tunnel plan values are rejected with migration guidance
instead of silently selecting another path.

```sh
mvmctl machine run \
  --allow-host api.example.com:443 \
  --image alpine \
  -- curl https://api.example.com/
```

## Supported application surfaces

Applications reach FlowMux through one of these loopback or SDK surfaces:

- **HTTP and HTTPS proxy:** standard proxy-aware clients use the injected
  loopback proxy settings. HTTPS uses `CONNECT`; a typed HTTP flow can opt into
  host-owned transforms such as secret substitution and redaction.
- **SOCKS5h and UDP associate:** TCP and UDP clients use the loopback SOCKS5h
  adapter. Hostname resolution stays host-controlled because the `h` form sends
  the hostname to FlowMux rather than resolving it inside the guest.
- **Controlled DNS:** guest DNS requests go through the loopback adapter and are
  checked against the same signed destination policy before a result is used.
- **Mediated ping:** the loopback service offers the admitted reachability probe;
  it does not give the workload a raw ICMP socket.
- **Typed connectors:** SDK connectors name the destination and protocol shape
  explicitly. The host can then apply connector-specific validation,
  transformation, substitution, and audit behavior without exposing credentials
  to the guest.

Opaque TCP and UDP remain byte streams or datagrams. FlowMux does not pretend it
can inspect encrypted payloads. Selective L7 behavior runs only when the signed
plan declares a typed flow that gives the endpoint ownership of that protocol.

## Reaching a key-value store

A workload that needs durable storage does not need a network for it:

```sh
mvmctl machine run --name worker --image myworker --host-service host.kv.v1
```

`host.kv.v1` is served on the host-services broker channel, so the bytes stay
on the host and nothing hands the guest a credential. The namespace comes from
the supervisor's call context rather than any request field, so one workload
cannot address another's by asking for it. A workload whose signed plan did not
bind the service gets `NotBound` before any handler runs.

Verbs are `get`, `put`, `delete`, and `list`. Keys are validated rather than
sanitized — a key that would need rewriting to be safe is refused, because a
caller that read back a different key than it wrote has no way to notice.
Values are bounded: the broker is a control channel, not a bulk transport.

A catalog runtime can declare the services it needs, so an operator does not
have to know that a given runtime wants a store and pass the flag every time.
Declared bindings and `--host-service` are unioned: the entry says what the
runtime needs, the flag says what the operator wants, and neither drops the
other.

## Reaching another workload

:::caution[Not yet authorable]
The enforcement model below is implemented and gated, but there is **no CLI
flag to author a peer binding yet**, so this is not something you can turn on
today. It is documented here because the decision path is live and the
namespace is reserved — not as a feature you can use.
:::

The design is that a workload dials a peer by name — `db.mvm.peer:5432` — and
the host resolves it and opens the connection. The name and the address it
resolves to are both bound in the signed plan, and that address is the peer's
own admitted ingress mapping, so the reachable set is fixed at admission rather
than discovered at runtime. The guest never learns an address and still has no
NIC.

Resolution happens in front of the same gate that decides ordinary egress, so
east-west traffic inherits default-deny instead of carrying its own rule:

- A gate with no peer bindings admits no peer.
- A binding authorizes one `name:port` route. The same peer on a port the
  binding does not name is refused; a binding is not a blanket grant to a host.
- Nothing listens at the address until the peer boots, so a dial to a stopped
  peer is refused by the connect. There is no liveness registry that could
  disagree with reality.

The reserved `.mvm.peer` suffix keeps the peer and host-name namespaces from
overlapping. A target either ends in it and resolves as a peer, or does not and
is decided as ordinary egress; a malformed peer name is refused at peer
resolution rather than looked up as a public host.
`xtask check-single-network-path` pins that branch to one place and both
connect sites to it.

Two limits hold regardless of how bindings are eventually authored: peer
dialing is **TCP-only**, and peers are **not reachable through the
credential-substituting HTTP proxy**.

## Applications that open direct sockets

A non-cooperative application that ignores the injected loopback adapters and
opens a socket directly fails closed: the guest has no routable NIC or default
route, and mvm does not fall back to a packet tunnel. Use the HTTP proxy,
SOCKS5h/UDP adapter, controlled DNS, mediated ping, or a typed connector. If an
application cannot use any of those surfaces, it is not network-compatible with
the workload boundary.

This is deliberate. A hidden fallback would bypass the single policy,
resource-accounting, substitution, redaction, and audit decision point that
FlowMux exists to provide.

## Security and resource properties

Every FlowMux session is authenticated to one admitted VM. The endpoint applies
destination and port policy before opening a host socket, keeps secrets and TLS
material host-side, bounds streams, datagrams, DNS state, connector work, and
ingress peers, and emits the canonical audit result. Declared ingress uses the
same endpoint and delivers only to a signed guest-loopback target.

The same contract applies across Firecracker, HVF, and libkrun: no production
backend attaches a routable workload NIC, and none may substitute a second
networking implementation.

## Data path

```text
guest application
  -> HTTP / SOCKS5h+UDP / DNS / ping / typed connector loopback adapter
  -> authenticated FlowMux session on GuestService::NetworkFlow
  -> one per-VM mvm-network-endpoint
  -> policy + limits + optional typed transforms + audit
  -> host-owned TCP/UDP socket or declared ingress listener
```

Control and data share the authenticated FlowMux protocol but retain bounded,
independent progress. Saturating one flow cannot create an unbounded queue or
silently widen another flow's authority.

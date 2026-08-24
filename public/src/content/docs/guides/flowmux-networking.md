---
title: FlowMux networking
description: Policy-enforced workload networking through one authenticated vsock path.
---

FlowMux is mvm's single workload-networking path. Workload microVMs have no
routable network device. Guest loopback adapters describe connection intent to
an authenticated per-VM endpoint over vsock, and the host opens only the
connections admitted by the signed plan.

FlowMux is a **virtual transport protocol** that runs over a single authenticated
vsock session. It multiplexes multiple traffic classes—TCP, UDP, DNS, HTTP,
ICMP (mediated ping), and host-initiated ingress—over one vsock stream rather
than using raw packet tunnels or guest NICs. The guest uses standard loopback
adapters (SOCKS5/HTTP proxy, DNS stub, mediated ping) to reach admitted destinations.
Raw packet tunnels, NICs, and L3 modes are retired and rejected at admission.

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

---
title: Networking
description: Network layout and connectivity in mvm microVMs.
---

## Dev Network Layout

```
Firecracker microVM (172.16.0.2/30, eth0)
    | TAP interface (tap0)
Lima VM (172.16.0.1/30, tap0)  --  iptables NAT  --  internet
    | Lima virtualization
Host (macOS / Linux)
```

The microVM has internet access via NAT through the Lima VM. The TAP device connects the microVM to Lima's network namespace.

## vsock Communication

MicroVMs don't use networking for host communication — they use Firecracker's **vsock** interface:

| Port | Protocol | Purpose |
|------|----------|---------|
| 52 | Length-prefixed JSON | Guest agent (health checks, status, exec, snapshot lifecycle) |

The host connects by writing `CONNECT 52\n` to the Firecracker vsock UDS socket and reading `OK 52\n`. All requests are request/response pairs.

## No SSH

MicroVMs have **no SSH access** by design. Communication is exclusively via vsock. This eliminates:

- SSH key management
- SSH daemon attack surface
- Network-based authentication bypasses

For debugging dev builds, use `mvmctl vm exec <name> -- <command>` which routes through the vsock agent.

## Port Forwarding

MicroVMs are accessible from the Lima VM at `172.16.0.2`. To expose a service to the host:

1. The microVM listens on its eth0 address (172.16.0.2)
2. Lima's networking makes the VM accessible from the host

## Cross-Tenant Isolation

In fleet mode ([mvmd](https://github.com/auser/mvmd)), tenants are isolated at L2 with separate bridges. Cross-tenant traffic is blocked by design. If you need cross-tenant communication, route through the host.

## DNS

The guest's `/etc/resolv.conf` is configured at build time to use Lima's DNS resolver. Internet access works out of the box through the NAT chain.
